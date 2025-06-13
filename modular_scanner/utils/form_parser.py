from urllib.parse import urljoin
from bs4 import BeautifulSoup


def get_forms(http_client, url):
    """
    Finds and parses all HTML forms on a given URL.
    Returns a list of form detail dictionaries.
    """
    try:
        response = http_client.get(url)
        if not response:
            return []

        soup = BeautifulSoup(response.content, "lxml")
        forms = soup.find_all("form")

        form_details_list = []
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get")
            form_url = urljoin(url, action)

            inputs = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                inputs.append({"name": input_name, "type": input_type})

            form_details_list.append({
                "action": form_url,
                "method": method,
                "inputs": inputs
            })
        return form_details_list

    except Exception as e:
        print(f"[DEBUG] Error during form parsing at {url}: {e}")
        return []