import nmap
from core.aggression import AGGRESSION_PROFILES
from core.ad_enum import ADEnumerator
from core.vuln_engine import VulnEngine
import subprocess

class AdvancedScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.ad_enum = ADEnumerator()
        self.vuln_engine = VulnEngine()
    
    def scan(self, target, profile='normal'):
        config = AGGRESSION_PROFILES[profile]
        args = config['nmap_args']
        if '-p' not in args:
            args += f" -p {config['ports']}"
        if config['version_intensity'] > 0:
            args += f" --version-intensity {config['version_intensity']}"
        if config['scripts'] and '--script' not in args:
            args += f" --script={config['scripts']}"
        
        self.nm.scan(hosts=target, arguments=args)
        return self._parse_results(config)
    
    def _parse_results(self, config):
        results = []
        for host in self.nm.all_hosts():
            h = {
                'ip': host,
                'hostname': self.nm[host].hostname() or "N/A",
                'state': self.nm[host].state(),
                'os': self._get_os(host),
                'ports': []
            }
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    p = self.nm[host][proto][port]
                    h['ports'].append({
                        'port': port,
                        'proto': proto,
                        'state': p['state'],
                        'service': p.get('name', 'unknown'),
                        'version': p.get('version', 'N/A'),
                        'product': p.get('product', 'N/A'),
                        'script_output': p.get('script', {}),
                        'host': host
                    })
            if self._is_ad_host(h):
                try:
                    h['ad_info'] = self.ad_enum.enumerate(host)
                except:
                    h['ad_info'] = {}
            h['vulns'] = self.vuln_engine.analyze_host(h)
            results.append(h)
        return results

    def _get_os(self, host):
        if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
            return self.nm[host]['osmatch'][0]['name']
        return "Desconocido"

    def _is_ad_host(self, host_data):
        for port in host_data['ports']:
            if port['port'] in [389, 636, 3268, 3269]:
                return True
        return False