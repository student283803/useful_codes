# In file: modules/sqli_scanner.py

import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from utils.http_client import HttpClient  # Note: Corrected to HTTPClient for consistency
from utils.reporter import Reporter


class SqliScanner:
    """
    Module for detecting Error-Based SQL Injection vulnerabilities.
    """

    # Note: Corrected to HTTPClient for consistency
    def __init__(self, http_client: HttpClient, reporter: Reporter):
        self.client = http_client
        self.reporter = reporter
        self.SQL_ERROR_PATTERNS = [
            "you have an error in your sql syntax", "unclosed quotation mark",
            "unterminated quoted string", "warning: mysql_fetch", "sqlstate[",
            "microsoft ole db provider for odbc drivers", "invalid sql statement"
        ]
        self.vulnerable_params = []

    def _get_forms(self, url):
        """Finds and parses all HTML forms on a given URL."""
        try:
            response = self.client.get(url)
            if not response:
                return []

            soup = BeautifulSoup(response.content, "lxml")
            return soup.find_all("form")
        except Exception as e:
            # This will now only catch errors from BeautifulSoup, not from a None response.
            print(f"[DEBUG] Error during form parsing at {url}: {e}")
            return []

    def _test_parameter(self, url, method, param, value):
        """Tests a single parameter for SQLi by injecting a single quote."""
        payload = f"{value}'"
        data_or_params = {param: payload}

        try:
            # Using the session object directly for more control over the request type
            if method.lower() == 'post':
                response = self.client.session.post(url, data=data_or_params)
            else:
                response = self.client.session.get(url, params=data_or_params)

            # Check response for SQL error patterns
            for pattern in self.SQL_ERROR_PATTERNS:
                if pattern in response.content.decode('utf-8', errors='ignore').lower():
                    finding = {"url": url, "parameter": param, "method": method.upper()}
                    # Avoid adding duplicate findings
                    if finding not in self.vulnerable_params:
                        self.vulnerable_params.append(finding)
                        raw_log = {
                            "finding": finding,
                            "payload": payload,
                            "response_snippet": response.content.decode('utf-8', errors='ignore')[:500]
                        }
                        self.reporter.log_raw('sqli_scanner', raw_log)
                    return True
        except requests.exceptions.RequestException:
            pass
        return False

    def scan(self, url):
        """
        Scans a given URL for error-based SQLi vulnerabilities in forms and URL parameters.
        """
        print(f"[*] Starting Error-Based SQLi scan for {url}...")

        # 1. Test forms on the page
        forms = self._get_forms(url)
        print(f"[*] Found {len(forms)} form(s) on the page.")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get")
            form_url = urljoin(url, action)

            for input_tag in form.find_all(["input", "textarea"]):
                param_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                if param_name and input_type not in ["submit", "button", "reset", "checkbox", "radio"]:
                    print(f"[*] Testing parameter '{param_name}' in form with action '{action}'...")
                    self._test_parameter(form_url, method, param_name, "test_value")

        # 2. Test parameters in the URL query string
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parsed_url.query.split('&')
            print(f"[*] Found {len(query_params)} parameter(s) in the URL.")
            for param_pair in query_params:
                if '=' in param_pair:
                    param_name, param_value = param_pair.split('=', 1)
                    # Create a clean URL without query params for testing
                    base_url_for_test = parsed_url._replace(query="").geturl()
                    print(f"[*] Testing URL parameter '{param_name}'...")
                    self._test_parameter(base_url_for_test, 'GET', param_name, param_value)

        return self.vulnerable_params