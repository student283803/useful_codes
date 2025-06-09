import argparse
from utils.http_client import HttpClient
from utils.reporter import Reporter
from modules.dir_bruteforcer import DirBruteForcer
from modules.header_scanner import HeaderScanner

def main():
    parser = argparse.ArgumentParser(description='Modular scan scanner')
    parser.add_argument('-u', '--url', required=True, help='URL to scan')
    parser.add_argument('-m', '--module', required=True, choices=['dirscan', 'headerscan'], help='Module to scan (for example dirscan)')
    parser.add_argument('-w', '--wordlist', required=False, help='Path to wordlist dictionary')
    args = parser.parse_args()
    target_url = args.url

    print(f"target url: {target_url} | module: {args.module}\n")
    http_client = HttpClient()
    print(f"conecting to {target_url}\n")
    response = http_client.get(target_url)
    if response:
        print(f"Success! Response from {target_url}: {response}")

    if args.module == 'dirscan' and not args.wordlist:
        parser.error("--wordlist is required for dirscan")

    reporter = Reporter()
    reporter.setup_target(target_url)


    if args.module == 'dirscan':
        bruteforcer = DirBruteForcer(http_client, target_url, reporter=reporter)
        results = bruteforcer.scan(args.wordlist)
        if results:
            print(f"following resources was found: ")
            for url, status_code in results:
                print(f"  [+] {url} (Status: {status_code})")
        else:
            print(f"no hidden resources were found")
    elif args.module == 'headerscan':
        scanner = HeaderScanner(http_client, target_url, reporter=reporter)
        results = scanner.analyze()

        print(f"\n-----Analyze finished-----")
        if results:
            print(f"General info (fingerprinting): ")
            if results['general_info']:
                for key, value in results['general_info'].items():
                    print(f"  - {key}: {value}")
            else:
                print(f"no important results")

            print("\n[+] Starting analyze security headers")
            for header, data in results['security_headers'].items():
                if data['present']:
                    print(f"  [+] Found {header} = {data['value']}")
                else:
                    print(f"  [!] Missing: {header}")
        else:
            print(f"No results")







if __name__ == "__main__":
    main()