import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.http_client import HttpClient
from utils.reporter import Reporter
from tqdm import tqdm


class DirBruteForcer:
    def __init__(self, http_client: HttpClient, target_url: str, reporter: Reporter, max_threads: int = 20):
        self.client = http_client
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.reporter = reporter
        self.max_threads = max_threads

    def _check_path(self, path:str):
        path = path.strip()
        test_url = self.target_url + path

        response = self.client.get(test_url)

        if response:

            raw_log_data = {
                'path': path,
                'url': test_url,
                'status_code': response.status_code,
                'content_length': len(response.text),
                'headers': dict(response.headers)
            }
            self.reporter.log_raw('dir_bruteforcer', raw_log_data)

            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                return (test_url, response.status_code)
        return None

    def scan(self, wordlist_path: str):
        """
        Args:
            wordlist_path (str): path to file with dict

        Returns:
            list: tuples (url, status_code) for found resources
        """

        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = f.readlines()
        except FileNotFoundError:
            print(f"{wordlist_path} not found")
            return []

        found_resources = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            print(f"[*]Starting scan for {wordlist_path} with {len(words)} words")

            futures = {executor.submit(self._check_path, word): word for word in words}
            for future in tqdm(as_completed(futures), total=len(words), desc="Scanning"):
                results = future.result()
                if results:
                    found_resources.append(results)
        return found_resources