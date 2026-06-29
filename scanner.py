import aiohttp
from bs4 import BeautifulSoup
import re
import asyncio
import urllib.parse
import ssl
import socket
from datetime import datetime, timezone

class AsyncWebScanner:
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
        }
        
    def detect_cms(self, html, headers, cookies_str=""):
        soup = BeautifulSoup(html, 'html.parser')
        generator = soup.find('meta', attrs={'name': 'generator'})
        gen_content = generator.get('content', '').lower() if generator else ''
        
        # 1. WordPress
        if 'wordpress' in gen_content or 'wp-content' in html or 'wp-includes' in html:
            return "WordPress"
            
        # 2. Drupal
        headers_str = str(headers).lower()
        html_lower = html.lower()
        if 'drupal' in gen_content or 'x-generator' in headers_str and 'drupal' in headers_str:
            return "Drupal"
        if '/sites/default/files' in html or 'data-drupal-selector' in html or 'drupal.settings' in html_lower or 'drupal.behaviors' in html_lower:
            return "Drupal"
        if 'x-drupal-cache' in headers_str or 'x-drupal-dynamic-cache' in headers_str:
            return "Drupal"
        if 'drupalsettings' in html_lower or '/core/misc/drupal.js' in html_lower or 'jquery.once.js' in html_lower:
            return "Drupal"
        if 'ssess' in cookies_str or 'sess' in cookies_str and ('drupal' in html_lower or 'sites/default' in html_lower):
            return "Drupal"
            
        # 3. Moodle
        if 'moodle' in gen_content or '/theme/image.php' in html or 'moodlesession' in headers_str or 'moodlesession' in cookies_str or 'var moodleconfig' in html_lower or 'm.yui' in html_lower:
            return "Moodle"
            
        # 4. Astro
        if 'astro' in gen_content or 'astro-island' in html or 'data-astro-cid' in html:
            return "Astro"
            
        # 5. React / Vite
        if 'id="root"' in html or 'data-reactroot' in html:
            if '/@vite/client' in html or 'vite' in html.lower():
                return "React (Vite)"
            return "React / SPA"
            
        return "Desconocido / A medida"

    def scan_headers(self, headers):
        issues = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        if 'server' in lower_headers:
            issues.append(f"Servidor: {lower_headers['server']}")
        if 'x-powered-by' in lower_headers:
            issues.append(f"Tecnología: {lower_headers['x-powered-by']}")
        if 'x-frame-options' not in lower_headers and 'content-security-policy' not in lower_headers:
            issues.append("Riesgo: Falta protección Clickjacking")
        if 'strict-transport-security' not in lower_headers and self.url.startswith('https'):
            issues.append("Riesgo: Falta HSTS")
        return issues

    def analyze_ecosystem(self, html, cms):
        ecosystem = []
        if cms == "WordPress":
            theme_match = re.search(r'/wp-content/themes/([^/]+)/', html)
            if theme_match: ecosystem.append(f"Tema WP: {theme_match.group(1)}")
            plugins = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
            for p in plugins: ecosystem.append(f"Plugin WP: {p}")
        elif cms == "Drupal":
            theme_match = re.search(r'/themes/custom/([^/]+)/', html)
            if theme_match: ecosystem.append(f"Tema Drupal: {theme_match.group(1)}")
            modules = set(re.findall(r'/modules/contrib/([^/]+)/', html))
            for m in modules: ecosystem.append(f"Módulo Drupal: {m}")
        elif cms == "Moodle":
            theme_match = re.search(r'/theme/([^/]+)/', html)
            if theme_match: ecosystem.append(f"Tema Moodle: {theme_match.group(1)}")
        return ecosystem

    def analyze_html_for_malware(self, html):
        findings = []
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script'):
            src = script.get('src')
            if src and any(pat in src for pat in ['pastebin.com', 'ngrok.io', 'bit.ly', 'eval(']):
                findings.append(f"Script sospechoso: {src}")
            else:
                content = script.string or ""
                if 'eval(function(p,a,c,k,e,d)' in content or 'String.fromCharCode' in content:
                    findings.append("JS ofuscado (Posible Malware)")
        for iframe in soup.find_all('iframe'):
            style = iframe.get('style', '')
            if 'display:none' in style.replace(' ', '') or iframe.get('width') == '0':
                findings.append(f"Iframe oculto: {iframe.get('src', 'No src')}")
        return findings

    def run_passive_audit(self, html):
        audit = []
        soup = BeautifulSoup(html, 'html.parser')
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen:
            audit.append(f"Meta Generator expuesto")
        if soup.find('link', attrs={'rel': 'EditURI'}):
            audit.append("RSD Link expuesto")
        return audit

    async def check_ssl_cert(self):
        parsed = urllib.parse.urlparse(self.url)
        hostname = parsed.hostname
        if not hostname or parsed.scheme != 'https':
            return False, None
            
        loop = asyncio.get_event_loop()
        
        def _get_cert():
            context = ssl.create_default_context()
            try:
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        return True, cert.get('notAfter')
            except Exception:
                return False, None
                
        valid, not_after = await loop.run_in_executor(None, _get_cert)
        
        exp_date = None
        if valid and not_after:
            try:
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except Exception:
                pass
                
        return valid, exp_date

    async def run_passive_scan(self, session):
        try:
            async with session.get(self.url, headers=self.headers, timeout=45, ssl=False) as response:
                html = await response.text()
                # Recopilamos headers de toda la cadena de redirecciones
                all_headers = dict(response.headers)
                for r in response.history:
                    all_headers.update(dict(r.headers))
                
                # Recopilamos las cookies del session jar
                cookies_str = ""
                if session.cookie_jar:
                    cookies_str = str(session.cookie_jar).lower()
                
                ssl_valid, ssl_exp = await self.check_ssl_cert()
                cms = self.detect_cms(html, all_headers, cookies_str)
                
                return {
                    "status": "success",
                    "target": self.url,
                    "cms_info": cms,
                    "header_issues": self.scan_headers(all_headers),
                    "ecosystem": self.analyze_ecosystem(html, cms),
                    "malware": self.analyze_html_for_malware(html),
                    "audit": self.run_passive_audit(html),
                    "ssl_valid": ssl_valid,
                    "ssl_expiration_date": ssl_exp.isoformat() if ssl_exp else None
                }
        except Exception as e:
            return {"status": "error", "target": self.url, "message": str(e)}
