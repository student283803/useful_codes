import argparse
from utils.http_client import HttpClient

def main():
    parser = argparse.ArgumentParser(description='Modular scan scanner')
    parser.add_argument('-u', '--url', required=True, help='URL to scan')
    args = parser.parse_args()
    target_url = args.url

    print(f"target url: {target_url}\n")

    http_client = HttpClient()
    print(f"conecting to {target_url}\n")
    response = http_client.get(target_url)

    if response:
        print(f"Success! Response from {target_url}: {response}")
        print(f"response code {response.status_code}\n")