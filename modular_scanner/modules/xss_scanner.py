from urllib.parse import urlparse
from utils.http_client import HttpClient
from utils.reporter import Reporter
from utils.form_parser import get_forms

class XssScanner:
    def __init__(self, http_client: HttpClient, reporter: Reporter):
        self.client = http_client
        self.reporter = reporter
        self.vulnerable_params = []
        self.xss_payloads = [
            "<script>alert('xss_test_payload')</script>",
            "'\"<svg onload=alert('xss_test_payload')>",
            "<img src=x onerror=alert('xss_test_payload')>",
            "javascript:alert('xss_test_payload')",
            "'-alert('xss_test_payload')-'",
            "<body onload=alert('xss_test_payload')>",
        ]

    def _test_parameter(self, url, method, param, value):
        """testing single parameter for reflected XSS"""

        for payload in self.xss_payloads:
            test_value = f"{value}{payload}"
            data_or_params = {param: test_value}

        try:
            if method.lower() == "post":
                response = self.client.session.post(url, data=data_or_params)
            else:
                response = self.client.session.get(url, params=data_or_params)

            #If the raw payload is reflected in the response, it's a potential vulnerability
            if payload in response.text:
                finding = {"url": url, "parameter": param, "method": method.upper(), "payload": payload}
                if finding not in self.vulnerable_params:
                    self.vulnerable_params.append(finding)
                    self.reporter.log_raw("xss_scanner", finding)
                return True
        except Exception:
            pass
        return False

    def scan(self, url):
        """Scanning a URL for reflected XSS vulnerabilities"""
        print(f"[*] Starting Reflected XSS scan for {url}...")

        #Testing forms
        forms = get_forms(self.client, url)
        print(f"Found {len(forms)} forms")
        for form in forms:
            for field in form["inputs"]:
                if field.get("name"):
                    print(f"[*] Testing form parameter '{field['name']}' at {form['action']}...")
                    self._test_parameter(form['action'], form['method'], field['name'], "test")

        parsed_url = urlparse(url)
        if parsed_url.query:
            for param_pair in parsed_url.query.split("&"):
                if '=' in param_pair:
                    name, value = param_pair.split("=", 1)
                    print(f"[*] Testing URL parameter '{name}'...")
                    self._test_parameter(url, 'GET', name, value)

        return self.vulnerable_params
