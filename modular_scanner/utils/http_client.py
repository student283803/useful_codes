import requests
import json

class HttpClient:
    def __init__(self, config_path='config.json'):

        with open(config_path) as f:
            config = json.load(f)

        self.headers = {
            'User-Agent': config['http']['user_agent']
        }

        self.timeout = config['http']['timeout']
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        print("HTTP client initialized")

        def get(self, url):
            """sending GET request"""

            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response
            except requests.exceptions.RequestException as e:
                print(f"Error connecting to http client. Sending GET request to {url} failed: {e}")
                return None