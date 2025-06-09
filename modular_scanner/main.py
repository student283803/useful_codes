import argparse
from utils.http_client import HttpClient
from utils.reporter import Reporter
from modules.dir_bruteforcer import DirBruteForcer

def main():
    parser = argparse.ArgumentParser(description='Modular scan scanner')
    parser.add_argument('-u', '--url', required=True, help='URL to scan')
    parser.add_argument('-m', '--module', required=True, choices=['dirscan'], help='Module to scan (for example dirscan)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist dictionary')
    args = parser.parse_args()
    target_url = args.url

    print(f"target url: {target_url} | module: {args.module}\n")
    http_client = HttpClient()

    if args.module == 'dirscan' and not args.wordlist:
        parser.error("--wordlist is needed for dirscan")

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


    print(f"conecting to {target_url}\n")
    response = http_client.get(target_url)
    if response:
        print(f"Success! Response from {target_url}: {response}")

if __name__ == "__main__":
    main()