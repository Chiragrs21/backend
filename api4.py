import requests
def ipv6_location(ip):
    def get_geolocation(ip_address, api_key):
        url = f"https://ipgeolocation.abstractapi.com/v1/?api_key={api_key}&ip_address={ip_address}"
        response = requests.get(url)
        data = response.json()
        return data

    # Example usage
    api_key = "7f8fc4688a73459881f098adc7f7fe69"
    ip_address = ip  # only ipv6 works
    result = get_geolocation(ip_address, api_key)
    return result
