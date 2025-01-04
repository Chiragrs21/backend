import requests

def check_domain(domain):
    def check_host_status(host):
        url = f'https://dnsforfamily.com/api/checkHost?hostnames[]={host}'
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    # Example usage
    host = domain
    result = check_host_status(host)

    return result
