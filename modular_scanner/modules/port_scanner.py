import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from utils.reporter import Reporter

class PortScanner:
    """wrapper for nmap for scanning ports"""
    def __init__(self, target_url:str, reporter:Reporter):
        parsed_url = urlparse(target_url)
        self.target_host = parsed_url.hostname
        self.reporter = reporter
        self.results = []

    def scan(self):
        if not self.target_host:
            print("[!] No target URL provided")
            return None

        print(f"[*] Scanning {self.target_host}...")
        command = ['nmap', '-sV', 'T4', '-oX', '-', self.target_host]

        try:
            process = subprocess.run(command, capture_output=True, text=True, check=True)
            nmap_output_xml = process.stdout
            self.reporter.log_raw('port_scanner_raw', {"raw_xml": nmap_output_xml})
            root = ET.fromstring(nmap_output_xml)

            for port in root.findall(".//port"):
                if port.find("./state").get("state") == "open":
                    port_id = port.get("portid")
                    service = port.find("./service")
                    service_name = service.get("name", "unknown")
                    product = service.get("product", "")
                    version = service.get("version", "")

                    full_service_info = f"{product} {version}".strip()

                    self.results.append({
                        "port": port_id,
                        "service": service_name,
                        "version": full_service_info,
                    })
            return self.results
        except FileNotFoundError:
            print("[!]nmap not found")
            return None
        except subprocess.CalledProcessError as e:
            print("[!]nmap command failed")
            print(f"Stderr: {e.stderr}")
            return None
