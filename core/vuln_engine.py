# core/vuln_engine.py
# Motor avanzado de detección de vulnerabilidades para pentscan
# Integración con Nmap NSE, análisis de banners, y detección proactiva

import subprocess
import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.js_api_scanner import JSAPIScanner
from core.risk_analyzer import RiskAnalyzer

class VulnEngine:
    """Motor de análisis de vulnerabilidades avanzado"""
    
    def __init__(self):
        self.js_scanner = JSAPIScanner()
    
    def analyze_host(self, host_data: dict) -> list:
        """
        Analiza un host completo y devuelve lista de vulnerabilidades.
        
        Args:
            host_data: dict con información del host (IP, puertos, scripts NSE, etc.)
            
        Returns:
            list: Lista de hallazgos en formato dict
        """
        findings = []
        ip = host_data['ip']
        
        # Analizar cada puerto abierto
        for port in host_data.get('ports', []):
            if port['state'] != 'open':
                continue
                
            # Detección basada en scripts NSE
            self._analyze_nse_scripts(port, findings, ip)
            
            # Detección de configuraciones inseguras
            self._analyze_insecure_configs(port, findings, ip)
            
            # Detección de servicios con vulnerabilidades conocidas
            self._analyze_service_vulns(port, findings, ip)
            
            # Análisis web específico (HTTP/HTTPS)
            if port['service'] in ['http', 'https']:
                self._analyze_web_vulns(port, findings, ip)
        
        # Detección de claves API en JavaScript (solo si hay HTTP)
        http_ports = [p for p in host_data.get('ports', []) if p['service'] in ['http', 'https']]
        if http_ports:
            self._analyze_js_api_keys(host_data, findings)
        
        # Asignar CVSS y severidad a todos los hallazgos
        for finding in findings:
            if 'cvss' not in finding or 'severity' not in finding:
                vuln_data = RiskAnalyzer.analyze_vulnerability(
                    finding['id'], 
                    finding.get('service', ''), 
                    finding.get('version', '')
                )
                finding['cvss'] = vuln_data['cvss']
                finding['severity'] = vuln_data['severity']
        
        return findings

    def _analyze_nse_scripts(self, port: dict, findings: list, ip: str):
        """Analiza la salida de scripts NSE de Nmap"""
        scripts = port.get('script_output', {})
        
        # Scripts de vulnerabilidad
        if 'vulners' in scripts:
            vulners_output = str(scripts['vulners'])
            cves = re.findall(r'(CVE-\d{4}-\d{4,7})', vulners_output)
            for cve in cves[:3]:  # Top 3 CVEs
                findings.append({
                    'id': cve,
                    'type': 'CVE',
                    'service': port['service'],
                    'port': port['port'],
                    'description': f'Vulnerabilidad {cve} detectada por Nmap Vulners',
                    'source': 'nmap-vulners'
                })
        
        # SMB signing
        if 'smb-security-mode' in scripts:
            smb_output = str(scripts['smb-security-mode']).lower()
            if 'signing disabled' in smb_output or 'message signing disabled' in smb_output:
                findings.append({
                    'id': 'SMB_SIGNING_DISABLED',
                    'type': 'CONFIG',
                    'service': 'smb',
                    'port': port['port'],
                    'description': 'SMB signing deshabilitado: susceptible a ataques NTLM relay',
                    'source': 'nmap-smb-security-mode'
                })
        
        # FTP anónimo
        if 'ftp-anon' in scripts:
            ftp_output = str(scripts['ftp-anon'])
            if 'Anonymous login allowed' in ftp_output or '230 Anonymous access granted' in ftp_output:
                findings.append({
                    'id': 'FTP_ANON_ENABLED',
                    'type': 'CONFIG',
                    'service': 'ftp',
                    'port': port['port'],
                    'description': 'FTP permite login anónimo: posible exposición de archivos',
                    'source': 'nmap-ftp-anon'
                })
        
        # HTTP con directorios expuestos
        if 'http-ls' in scripts:
            http_ls = str(scripts['http-ls'])
            if '/cgi-bin' in http_ls:
                findings.append({
                    'id': 'HTTP_CGI_EXPOSED',
                    'type': 'CONFIG',
                    'service': 'http',
                    'port': port['port'],
                    'description': 'Directorio /cgi-bin accesible: posible ejecución remota',
                    'source': 'nmap-http-ls'
                })
            if 'index of' in http_ls.lower():
                findings.append({
                    'id': 'HTTP_DIRECTORY_LISTING',
                    'type': 'CONFIG',
                    'service': 'http',
                    'port': port['port'],
                    'description': 'Listado de directorios habilitado: exposición de estructura',
                    'source': 'nmap-http-ls'
                })

    def _analyze_insecure_configs(self, port: dict, findings: list, ip: str):
        """Detecta configuraciones inseguras basadas en banners y servicios"""
        service = port['service'].lower()
        product = port['product'].lower()
        version = port['version']
        
        # Credenciales por defecto
        default_creds_services = ['http', 'https', 'ssh', 'telnet', 'ftp', 'snmp']
        if service in default_creds_services:
            # Verificar si el banner sugiere credenciales por defecto
            banner = f"{product} {version}".lower()
            if any(keyword in banner for keyword in ['default', 'factory', 'admin:admin']):
                findings.append({
                    'id': 'DEFAULT_CREDS',
                    'type': 'CONFIG',
                    'service': service,
                    'port': port['port'],
                    'description': 'Servicio sugiere uso de credenciales por defecto',
                    'source': 'banner-analysis'
                })
        
        # SNMP con comunidad por defecto
        if service == 'snmp':
            findings.append({
                'id': 'SNMP_DEFAULT_COMMUNITY',
                'type': 'CONFIG',
                'service': 'snmp',
                'port': port['port'],
                'description': 'SNMP detectado: probar comunidades por defecto (public/private)',
                'source': 'service-detection'
            })

    def _analyze_service_vulns(self, port: dict, findings: list, ip: str):
        """Detecta vulnerabilidades basadas en versión del servicio"""
        product = port['product'].lower()
        version = port['version']
        
        # Servicios con serialización insegura
        serialization_services = ['weblogic', 'jenkins', 'axis', 'jboss', 'websphere']
        if any(svc in product for svc in serialization_services):
            findings.append({
                'id': 'INSECURE_SERIALIZATION',
                'type': 'VULN',
                'service': port['service'],
                'port': port['port'],
                'description': 'Servicio vulnerable a deserialización remota (RCE potencial)',
                'version': version,
                'source': 'version-detection'
            })
        
        # Servicios obsoletos
        if version and version != 'N/A':
            # Apache antiguos
            if 'apache' in product and self._is_old_version(version, '2.4.49'):
                findings.append({
                    'id': 'OUTDATED_APACHE',
                    'type': 'VULN',
                    'service': 'http',
                    'port': port['port'],
                    'description': 'Apache antiguo: posible Path Traversal (CVE-2021-41773)',
                    'version': version,
                    'source': 'version-detection'
                })
            
            # OpenSSH antiguos
            if 'openssh' in product and self._is_old_version(version, '8.0'):
                findings.append({
                    'id': 'OUTDATED_OPENSSH',
                    'type': 'VULN',
                    'service': 'ssh',
                    'port': port['port'],
                    'description': 'OpenSSH antiguo: posible enumeración de usuarios',
                    'version': version,
                    'source': 'version-detection'
                })

    def _analyze_web_vulns(self, port: dict, findings: list, ip: str):
        """Análisis específico para servicios web"""
        scripts = port.get('script_output', {})
        
        # Cache poisoning
        if 'http-cache-poisoning' in scripts:
            findings.append({
                'id': 'CACHE_POISONING',
                'type': 'WEB',
                'service': 'http',
                'port': port['port'],
                'description': 'Vulnerable a Web Cache Poisoning: posible robo de sesiones',
                'source': 'nmap-http-cache-poisoning'
            })
        
        # Host header injection
        if 'http-host-header' in scripts:
            findings.append({
                'id': 'HOST_HEADER_INJECTION',
                'type': 'WEB',
                'service': 'http',
                'port': port['port'],
                'description': 'Vulnerable a Host Header Injection: posible redirección maliciosa',
                'source': 'nmap-http-host-header'
            })
        
        # SSL/TLS débil
        if 'ssl-enum-ciphers' in scripts:
            ssl_output = str(scripts['ssl-enum-ciphers']).lower()
            weak_indicators = ['rc4', 'des', 'md5', 'sslv3', 'tlsv1.0']
            if any(indicator in ssl_output for indicator in weak_indicators):
                findings.append({
                    'id': 'WEAK_SSL_CIPHER',
                    'type': 'CRYPTO',
                    'service': port['service'],
                    'port': port['port'],
                    'description': 'Configuración SSL/TLS débil detectada',
                    'source': 'nmap-ssl-enum-ciphers'
                })

    def _analyze_js_api_keys(self, host_data: dict, findings: list):
        """Detecta claves API expuestas en JavaScript"""
        try:
            # Tomar el primer puerto HTTP/HTTPS
            http_port = None
            for port in host_data.get('ports', []):
                if port['service'] in ['http', 'https']:
                    http_port = port
                    break
            
            if http_port:
                target_url = f"http://{host_data['ip']}:{http_port['port']}"
                api_keys = self.js_scanner.scan(target_url)
                for key in api_keys:
                    findings.append({
                        'id': 'API_KEY',
                        'type': 'SENSITIVE_DATA',
                        'service': 'http',
                        'port': http_port['port'],
                        'description': f'Clave {key["type"]} expuesta en JavaScript',
                        'key_type': key['type'],
                        'source': 'js-api-scanner'
                    })
        except Exception:
            # Silenciar errores de análisis JS (no crítico)
            pass

    def _is_old_version(self, version_str: str, threshold: str) -> bool:
        """Compara versiones de forma básica (mejorable con 'packaging' library)"""
        try:
            # Extraer números de versión
            v1_nums = [int(x) for x in re.findall(r'\d+', version_str.split()[0])[:3]]
            v2_nums = [int(x) for x in re.findall(r'\d+', threshold)[:3]]
            
            # Rellenar con ceros si es necesario
            while len(v1_nums) < 3:
                v1_nums.append(0)
            while len(v2_nums) < 3:
                v2_nums.append(0)
            
            # Comparar versión
            return v1_nums < v2_nums
        except:
            return False