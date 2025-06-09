import argparse
from utils.http_client import HttpClient
from utils.reporter import Reporter
from modules.dir_bruteforcer import DirBruteForcer
from modules.header_scanner import HeaderScanner
from modules.port_scanner import PortScanner

def main():
    parser = argparse.ArgumentParser(description='Modular scan scanner')
    parser.add_argument('-u', '--url', required=True, help='URL to scan')
    parser.add_argument('-m', '--module', required=True, choices=['dirscan', 'headerscan', 'portscan'], help='Module to scan (for example dirscan)')
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


    elif args.module == 'portscan':

        INTERESTING_PORTS = {

            '21', '22', '23', '25', '53', '80', '110', '139', '143', '443', '445',

            '1433', '1521', '3306', '3389', '5432', '5900', '8000', '8080', '8443'

        }

        scanner = PortScanner(target_url, reporter=reporter)

        results = scanner.scan()

        print("\n--- Portscan finished ---")

        if results:
            interesting_ports = []
            other_ports = []
            for port_info in results:

                if port_info.get('port') in INTERESTING_PORTS:
                    interesting_ports.append(port_info)
                else:
                    other_ports.append(port_info)


            if interesting_ports:
                print("\n🎯 Interested ports:")
                for port_info in interesting_ports:
                    port = port_info.get('port', 'N/A')
                    service = port_info.get('service', 'unknown')
                    version_info = port_info.get('version_info', 'Version data not found')
                    print(f"  [+] Port {port}/tcp: {service} ({version_info})")
            else:
                print("\nℹ️ Nie znaleziono żadnych portów z listy interesujących.")

            if other_ports:
                print("\n[+] Pozostałe otwarte porty:")
                for port_info in other_ports:
                    port = port_info.get('port', 'N/A')
                    service = port_info.get('service', 'unknown')
                    version_info = port_info.get('version_info', 'Version data not found')
                    print(f"  - Port {port}/tcp: {service} ({version_info})")
        elif results == []:
            print("Open ports not found")
        else:
            print("failed to retrieve scan results")





if __name__ == "__main__":
    main()