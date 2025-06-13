# Modular Web Vulnerability Scanner

A custom, extensible vulnerability scanner written in Python, designed for learning and automating penetration testing tasks.

## Features

This tool is built with a modular architecture and currently supports the following functions:

-   **Directory & File Discovery**: Brute-forces common paths to find hidden resources (`dirscan`).
-   **HTTP Header Analysis**: Scans and analyzes response headers for technology fingerprinting and security configurations (`headerscan`).
-   **Port Scanning**: A wrapper for the **Nmap** tool to perform service and version detection on open ports (`portscan`).
-   **SQL Injection Detection**: Scans URL parameters and HTML forms for Error-Based SQL Injection vulnerabilities (`sqli`).
-   **SQL Injection Exploitation**: An optional wrapper for the **sqlmap** tool to exploit found vulnerabilities (`--exploit` flag).
-   **Full Scan Workflow**: A meta-module that chains directory discovery with SQLi scanning for automated find-and-exploit scenarios (`fullscan`).
-   **Reporting**: Automatically archives raw results from all scans into timestamped directories.

## Setup & Installation

Follow these steps to set up and run the scanner.

### 1. System Prerequisites

This tool uses external programs for some of its modules. You must install them using your system's package manager.

-   **Nmap**: Required for the `portscan` module.
    -   **macOS (Homebrew):** `brew install nmap`
    -   **Debian/Ubuntu:** `sudo apt-get install nmap`
-   **sqlmap**: Required for the `--exploit` functionality.
    -   **macOS (Homebrew):** `brew install sqlmap`
    -   **Debian/Ubuntu:** `sudo apt-get install sqlmap`

### 2. Python Environment

It is highly recommended to use a Python virtual environment.

```bash
#1.Navigate to the project directory
cd modular_scanner

#2. Create a virtual environment
python3 -m venv .venv

#3. Activate the virtual environment
#On macOS/Linux:
source .venv/bin/activate
#On Windows:
#.venv\Scripts\activate

# 4. Install all required Python packages from requirements.txt
pip install -r requirements.txt