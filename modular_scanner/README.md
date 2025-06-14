# Modular Web Vulnerability Scanner

A custom, extensible vulnerability scanner written in Python, designed for learning and automating penetration testing tasks.

This tool is built with a modular architecture that allows for easy addition of new scanning and exploitation capabilities.

## Features

The scanner currently supports the following modules and functions:

-   **Directory & File Discovery (`dirscan`)**: Brute-forces common paths to find hidden, accessible resources on the server.
-   **HTTP Header Analysis (`headerscan`)**: Scans and analyzes response headers for technology fingerprinting and misconfigured or missing security headers.
-   **Port Scanning (`portscan`)**: A wrapper for the **Nmap** tool to perform service and version detection on open ports.
-   **SQL Injection Detection (`sqli`)**: Scans URL parameters and HTML forms for Error-Based SQL Injection vulnerabilities.
-   **SQL Injection Exploitation (`sqli --exploit`)**: An optional wrapper for the **sqlmap** tool that provides an interactive menu to exploit found SQLi vulnerabilities.
-   **Reflected XSS Scanning (`xss`)**: Tests input parameters and forms for potential Reflected Cross-Site Scripting vulnerabilities.
-   **Directory Traversal Scanning (`traversal`)**: Tests suspicious URL parameters for Directory Traversal vulnerabilities.
-   **Login Form Bruteforcer (`login_brute`)**: Performs an autonomous, anomaly-based brute-force attack on login forms.
-   **Full Scan Workflows (`fullscan`)**: A meta-module that chains directory discovery with a user-specified list of attacks (e.g., `sqli,xss,traversal`) using the `--attacks` flag.
-   **Reporting**: Automatically archives raw results from all scans into unique, timestamped directories for later analysis.

## Usage

All commands must be run from the root of the project directory (`modular_scanner/`) with the virtual environment activated.

### Module Examples

-   **Port Scanning:**
    ```bash
    python main.py -m portscan -u "http://testphp.vulnweb.com"
    ```

-   **HTTP Header Analysis:**
    ```bash
    python main.py -m headerscan -u "https://google.com"
    ```

-   **Directory Discovery:**
    ```bash
    python main.py -m dirscan -u "http://testphp.vulnweb.com" -w wordlists/test_wordlist.txt
    ```

-   **Scan a specific page for SQLi and Exploit:**
    ```bash
    python main.py -m sqli -u "http://testphp.vulnweb.com/artists.php?artist=1" --exploit
    ```
    
-   **Scan a page for Reflected XSS:**
    ```bash
    python main.py -m xss -u "http://testphp.vulnweb.com/search.php?test=query"
    ```

-   **Test for Directory Traversal:**
    ```bash
    python main.py -m traversal -u "http://testphp.vulnweb.com/showimage.php?file=cat.gif"
    ```
    
-   **Brute-force a login form (with auto-discovery):**
    ```bash
    python main.py -m login_brute -u "http://testphp.vulnweb.com/login.php" --user-list wordlists/users.txt --pass-list wordlists/passwords.txt
    ```

-   **Run a full scan with multiple attack types:**
    ```bash
    python main.py -m fullscan -u "http://testphp.vulnweb.com" -w wordlists/test_wordlist.txt --attacks sqli,xss,traversal
    ```
    
## Setup & Installation

Follow these steps to set up and run the scanner.

### 1. System Prerequisites

This tool uses external programs for some of its modules. You must install them using your system's package manager.

-   **Nmap**: Required for the `portscan` module. Installation instructions can be found at [nmap.org](https://nmap.org).
    -   *macOS (Homebrew):* `brew install nmap`
    -   *Debian/Ubuntu:* `sudo apt-get install nmap`
-   **sqlmap**: Required for the `--exploit` functionality. Installation instructions can be found at [sqlmap.org](http://sqlmap.org/).
    -   *macOS (Homebrew):* `brew install sqlmap`
    -   *Debian/Ubuntu:* `sudo apt-get install sqlmap`



### 2. Python Environment

It is highly recommended to use a Python virtual environment to manage dependencies.

```bash
# 1. Navigate to the project directory
cd modular_scanner

# 2. Create a virtual environment
python3 -m venv .venv

# 3. Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate

# 4. Install all required Python packages from requirements.txt
pip install -r requirements.txt





