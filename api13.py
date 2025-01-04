import requests


def ip4_geolocator(ip):
    api_key = 'c8a1737b2e3a4b059cd160fef24ea2ab'
    url = f'https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}'

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return 'Failed to fetch data. Status code: {response.status_code}'
