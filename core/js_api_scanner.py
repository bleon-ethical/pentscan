# core/js_api_scanner.py
import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class JSAPIScanner:
    API_PATTERNS = {
        'aws': r'AKIA[0-9A-Z]{16}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'facebook': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'stripe': r'sk_live_[0-9a-zA-Z]{24}',
        'github': r'github_pat_[a-zA-Z0-9_]{82}',
        'slack': r'xox[baprs]-[0-9a-zA-Z]{10,50}',
        'twilio': r'AC[0-9a-f]{32}',
        'firebase': r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
        'sendgrid': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'
    }

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def scan_url(self, base_url):
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        try:
            # Obtener HTML principal
            resp = self.session.get(base_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Encontrar todos los scripts
            js_urls = set()
            for script in soup.find_all('script', src=True):
                js_urls.add(urljoin(base_url, script['src']))
            
            # Scripts inline
            inline_scripts = [script.string for script in soup.find_all('script') if script.string]
            
            all_js_content = inline_scripts[:]
            for js_url in js_urls:
                try:
                    js_resp = self.session.get(js_url, timeout=self.timeout)
                    all_js_content.append(js_resp.text)
                except:
                    pass
            
            # Buscar claves
            found_keys = []
            for content in all_js_content:
                if not content:
                    continue
                for key_type, pattern in self.API_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        # Validación básica (evitar falsos positivos)
                        if self._validate_key(key_type, match):
                            found_keys.append({
                                'type': key_type,
                                'key': match,
                                'source': 'JavaScript',
                                'risk': 'CRITICAL'
                            })
            return found_keys
        except Exception:
            return []

    def _validate_key(self, key_type, key):
        # Validación real para AWS
        if key_type == 'aws':
            import hashlib
            # Verificar longitud y caracteres válidos
            if len(key) == 20 and re.match(r'^AKIA[0-9A-Z]{16}$', key):
                return True
        # Para otros, asumir válido si coincide con patrón
        return True