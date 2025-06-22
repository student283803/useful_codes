import argparse
from utils.http_client import HttpClient
from utils.reporter import Reporter
from modules.dir_bruteforcer import DirBruteForcer
from modules.header_scanner import HeaderScanner
from modules.port_scanner import PortScanner
from modules.sqli_scanner import SqliScanner
from modules.sqli_exploiter import SqliExploiter
from modules.xss_scanner import XssScanner
from modules.traversal_scanner import TraversalScanner
from modules.login_bruteforcer import LoginBruteforcer


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
    parser.add_argument('-m', '--module', required=True, choices=['dirscan', 'headerscan', 'portscan', 'sqli', 'fullscan', 'xss', 'traversal', 'login_brute'], help='Module to run')
    parser.add_argument('-w', '--wordlist', required=False, help='Path to wordlist dictionary')
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit found SQLi vulnerabilities")
    parser.add_argument("--attacks", default="sqli,xss", help="Comma-separated list of attacks for fullscan mode (e.g., sqli,xss,traversal).")

#only for login_brute
########################################################################################################
    login_args = parser.add_argument_group('Login Bruteforcer Arguments')
    login_args.add_argument("--user-list", help="Path to username wordlist")
    login_args.add_argument("--pass-list", help="Path to password wordlist")
    login_args.add_argument("--user-param", help="Username parameter name from the form (e.g., 'username', 'uname')")
    login_args.add_argument("--pass-param", help="Password parameter name from the form (e.g., 'password', 'pass')")
    login_args.add_argument("--failure-string", help="(Optional but recommended) Text that appears after a failed login")
########################################################################################################

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

############################################################## dirscan

    if args.module == 'dirscan':
        bruteforcer = DirBruteForcer(http_client, target_url, reporter=reporter)
        results = bruteforcer.scan(args.wordlist)
        if results:
            print(f"following resources was found: ")
            for url, status_code in results:
                print(f"  [+] {url} (Status: {status_code})")
        else:
            print(f"no hidden resources were found")

############################################################## headerscan

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

############################################################## NMAP

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
                print("\n[*] Interested ports:")
                for port_info in interesting_ports:
                    port = port_info.get('port', 'N/A')
                    service = port_info.get('service', 'unknown')
                    version_info = port_info.get('version_info', 'Version data not found')
                    print(f"  [+] Port {port}/tcp: {service} ({version_info})")
            else:
                print("\n No interested ports found")

            if other_ports:
                print("\n[+] Rest of open ports:")
                for port_info in other_ports:
                    port = port_info.get('port', 'N/A')
                    service = port_info.get('service', 'unknown')
                    version_info = port_info.get('version_info', 'Version data not found')
                    print(f"  - Port {port}/tcp: {service} ({version_info})")
        elif results == []:
            print("[-] Open ports not found")
        else:
            print("failed to retrieve scan results")

############################################################## SQLI

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

############################################################## FULLSCAN


    elif args.module == 'fullscan':

        print(f"--- Starting Full Scan Workflow with attacks: {args.attacks} ---")
        # PHASE 1: DISCOVERY
        print("\n[PHASE 1] Discovering directories and files...")
        dir_scanner = DirBruteForcer(http_client, target_url, reporter=reporter)
        dir_results = dir_scanner.scan(args.wordlist)
        discovered_urls = {item[0] for item in dir_results} if dir_results else set()
        discovered_urls.add(target_url)
        print(
            f"\n[PHASE 1 FINISHED] Discovered {len(dir_results)} potential paths. Total unique URLs to test: {len(discovered_urls)}")
        # PHASE 2: ATTACK
        attack_types = [attack.strip() for attack in args.attacks.split(',')]

        if 'sqli' in attack_types:
            print("\n[ATTACK - SQLi] Scanning all discovered URLs for Error-Based SQL Injection...")
            sqli_scanner = SqliScanner(http_client, reporter=reporter)
            total_sqli_findings = []
            for url in discovered_urls:
                findings = sqli_scanner.scan(url)
                if findings:
                    total_sqli_findings.extend(findings)
            if total_sqli_findings:
                unique_findings = [dict(t) for t in {tuple(d.items()) for d in total_sqli_findings}]
                print("\n[+] SQLi VULNERABILITY FOUND:")
                for finding in unique_findings:
                    print(f"  - URL: {finding['url']}, Method: {finding['method']}, Parameter: {finding['parameter']}")
                if args.exploit and unique_findings:
                    interactive_exploit_menu(unique_findings[0], reporter)
            else:
                print("\n[-] No SQLi vulnerabilities found in this phase.")

        if 'xss' in attack_types:
            print("\n[ATTACK - XSS] Scanning all discovered URLs for Reflected XSS...")
            xss_scanner = XssScanner(http_client, reporter=reporter)
            total_xss_findings = []
            for url in discovered_urls:
                findings = xss_scanner.scan(url)
                if findings:
                    total_xss_findings.extend(findings)
            if total_xss_findings:
                unique_findings = [dict(t) for t in {tuple(d.items()) for d in total_xss_findings}]
                print("\n[+] XSS VULNERABILITY FOUND:")
                for finding in unique_findings:
                    print(f"  - URL: {finding['url']}, Method: {finding['method']}, Parameter: {finding['parameter']}")
            else:
                print("\n[-] No XSS vulnerabilities found in this phase.")

        if 'traversal' in attack_types:
            print("\n[ATTACK - TRAVERSAL] Scanning all discovered URLs for Directory Traversal...")
            traversal_scanner = TraversalScanner(http_client, reporter=reporter)
            total_traversal_findings = []
            for url in discovered_urls:
                findings = traversal_scanner.scan(url)
                if findings:
                    total_traversal_findings.extend(findings)
            if total_traversal_findings:
                unique_findings = [dict(t) for t in {tuple(d.items()) for d in total_traversal_findings}]
                print("\n[+] TRAVERSAL VULNERABILITY FOUND:")
                for finding in unique_findings:
                    print(f"  - URL: {finding['url']}, Parameter: {finding['parameter']}")
            else:
                print("\n[-] No Directory Traversal vulnerabilities found in this phase.")
        print("\n--- Full Scan Finished ---")

############################################################## XSS

    elif args.module == 'xss':
        scanner = XssScanner(http_client, reporter=reporter)
        results = scanner.scan(target_url)

        print("\n--- XSS Scan Finished ---")
        if results:
            print("\n[+] VULNERABILITY FOUND: Potential Reflected XSS.")
            print("  Vulnerable parameters found:")
            for finding in results:
                print(f"  - URL: {finding['url']}, Method: {finding['method']}, Parameter: {finding['parameter']}")
        else:
            print("\n[-] No obvious reflected XSS vulnerabilities were found.")

############################################################## TRAVERSAL

    elif args.module == 'traversal':
        scanner = TraversalScanner(http_client, reporter=reporter)
        results = scanner.scan(target_url)
        print("\n--- Directory Traversal Scan Finished ---")
        if results:
            print("\n[+] VULNERABILITY FOUND: Potential Directory Traversal.")
            for finding in results:
                print(f"  - Type: {finding.get('type')}, URL: {finding.get('url')}, Parameter: {finding.get('parameter')}, Payload: {finding.get('payload')}")
        else:
            print("\n[-] No obvious Directory Traversal vulnerabilities were found.")

########################################################## LOGIN BRUTE-FORCE

    elif args.module == 'login_brute':
        if not (args.user_list and args.pass_list):
            parser.error("--user-list, --pass-list are required for the login_brute module.")

        brute_config = {
            "url": target_url,
            "user_param": args.user_param,
            "pass_param": args.pass_param,
        }
        scanner = LoginBruteforcer(http_client, reporter, config=brute_config)
        scanner.run_attack(args.user_list, args.pass_list)




if __name__ == "__main__":
    main()