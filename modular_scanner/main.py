import argparse
from utils.http_client import HttpClient
from utils.reporter import Reporter
from modules.dir_bruteforcer import DirBruteForcer
from modules.header_scanner import HeaderScanner
from modules.port_scanner import PortScanner
from modules.sqli_scanner import SqliScanner
from modules.sqli_exploiter import SqliExploiter


def interactive_exploit_menu(finding, reporter):
    """Starts an interactive menu to exploit a single vulnerability."""
    exploiter = SqliExploiter(finding, reporter)

    while True:
        print("\n--- Interactive SQLi Exploitation Menu ---")
        print("What do you want to do?")
        print("[1] List databases")
        print("[2] List tables from a database")
        print("[3] Dump table content")
        print("[0] Exit exploitation menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            exploiter.list_dbs()
        elif choice == '2':
            db_name = input("Enter the database name to list tables from: ")
            exploiter.list_tables(db_name)
        elif choice == '3':
            db_name = input("Enter the database name: ")
            table_name = input("Enter the table name to dump: ")
            exploiter.dump_table(db_name, table_name)
        elif choice == '0':
            print("[*] Exiting exploitation menu.")
            break
        else:
            print("Invalid choice, please try again.")

def main():
    parser = argparse.ArgumentParser(description='Modular scan scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-m', '--module', required=True, choices=['dirscan', 'headerscan', 'portscan', 'sqli', 'fullscan'], help='Module to run')
    parser.add_argument('-w', '--wordlist', required=False, help='Path to wordlist dictionary')
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit found SQLi vulnerabilities")

    args = parser.parse_args()
    target_url = args.url

    print(f"target url: {target_url} | module: {args.module}\n")
    http_client = HttpClient()
    print(f"conecting to {target_url}\n")
    response = http_client.get(target_url)
    if response:
        print(f"Success! Response from {target_url}: {response}")

    if args.module in ['dirscan', 'fullscan'] and not args.wordlist:
        parser.error(f"--wordlist is required for {args.module}")

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
    elif args.module == 'sqli':
        scanner = SqliScanner(http_client, reporter=reporter)
        results = scanner.scan(target_url)

        print("\n--- SQLi Scan Finished ---")
        if results:
            print("\n[+] VULNERABILITY FOUND: Potential Error-Based SQL Injection.")
            print("  Vulnerable parameters found:")
            for finding in results:
                print(f"  - URL: {finding['url']}, Method: {finding['method']}, Parameter: {finding['parameter']}")

            if args.exploit:
                interactive_exploit_menu(results[0], reporter)
        else:
            print("\n[-] No obvious error-based SQLi vulnerabilities were found.")
    elif args.module == 'fullscan':
        print("--- Starting Full Scan Workflow (Discovery + SQLi Attack) ---")

        # --- PHASE 1: DISCOVERY ---
        print("\n[PHASE 1] Discovering directories and files...")
        dir_scanner = DirBruteForcer(http_client, target_url, reporter=reporter)
        dir_results = dir_scanner.scan(args.wordlist)

        # Extract just the URLs from the results
        discovered_urls = {item[0] for item in dir_results} if dir_results else set()
        # Add the initial target URL to the set of pages to test
        discovered_urls.add(target_url)

        print(
            f"\n[PHASE 1 FINISHED] Discovered {len(dir_results)} potential paths. Total unique URLs to test for SQLi: {len(discovered_urls)}")

        # --- PHASE 2: SQLi ATTACK ---
        print("\n[PHASE 2] Scanning all discovered URLs for Error-Based SQL Injection...")
        sqli_scanner = SqliScanner(http_client, reporter=reporter)
        total_sqli_findings = []

        for url in discovered_urls:
            # We call the scan method of the sqli_scanner for each found URL
            findings = sqli_scanner.scan(url)
            if findings:
                total_sqli_findings.extend(findings)

        # --- PHASE 3: FINAL REPORT ---
        print("\n--- Full Scan Finished ---")
        if total_sqli_findings:
            print("\n[+] VULNERABILITY FOUND: Potential Error-Based SQL Injection discovered on the following pages:")
            unique_findings = [dict(t) for t in {tuple(d.items()) for d in total_sqli_findings}]
            for finding in total_sqli_findings:
                print(f"  - URL: {finding['url']}, Method: {finding['method']}, Parameter: {finding['parameter']}")

            if args.exploit and unique_findings:
                print("\n--- Exploitation Phase Initiated (on first finding) ---")
                interactive_exploit_menu(unique_findings[0], reporter)
        else:
            print("\n[-] No obvious error-based SQLi vulnerabilities were found on any discovered pages.")




if __name__ == "__main__":
    main()