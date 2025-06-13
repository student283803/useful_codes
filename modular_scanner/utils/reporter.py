import os
import json
from datetime import datetime
from urllib.parse import urlparse
import threading

class Reporter:
    def __init__(self, base_dir: str = 'archive'):
        self.lock = threading.Lock()

    def setup_target(self, target_url: str):
        """creating unique catalogue for each target"""

        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname or "local target"
        timestamp = datetime.utcnow().strftime("%Y%/m%/d%/H%/M%/S")

        self.report_dir = os.path.join('archive', f'{hostname}_{timestamp}')

        try:
            os.makedirs(self.report_dir, exist_ok=True)
            print(f"Results will be stored in {self.report_dir}")
        except OSError as e:
            print(f"Failed to create directory {self.report_dir}: {e}")
            self.report_dir = None

    def log_raw(self, module_name: str, data: dict):
        if not self.report_dir:
            return
        with self.lock:
            file_path = os.path.join(self.report_dir, f'{module_name}_raw.json')
            with open(file_path, 'a', encoding='utf-8') as f:
                json.dump(data, f)
                f.write('\n')


