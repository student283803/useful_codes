from utils.http_client import HttpClient
from utils.reporter import Reporter


class HeaderScanner:
    def __init__(self, http_client: HttpClient, target_url:str, reporter:Reporter):
        self.client = http_client
        self.target_url = target_url
        self.reporter = reporter
        self.results = {
            'general_info': {},
            'security_headers': {}
        }

        self.SECURITY_HEADERS = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
    def analyze(self):
        """
        returns:
            dict: dictionary with analyzed information
        """

        print(f"[*] starting header scan for {self.target_url}...")
        response = self.client.get(self.target_url)

        if not response:
            print(f"[!] failed to retrieve server response {self.target_url}")
            return None
        headers = response.headers
        self.reporter.log_raw('header_scanner', dict(headers))
        if 'Server' in headers:
            self.results['general_info']['Server'] = headers['Server']
        if 'X-Powered-By' in headers:
            self.results['general_info']['X-Powered-By'] = headers['X-Powered-By']

        for header in self.SECURITY_HEADERS:
            if header in headers:
                self.results['security_headers'][header] = {
                    'present': True,
                    'value': headers[header]
                }
            else:
                self.results['security_headers'][header] = {
                    'present': False,
                    'value': None
                }
        return self.results