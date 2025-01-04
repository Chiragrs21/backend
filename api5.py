import requests
import json


def certificates(domain):
    def search_certificates(domain):
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    # Example usage
    certificates = search_certificates(domain)

    if certificates:
        return json.dumps(certificates, ensure_ascii=False)
    else:
        return json.dumps("Not found")
