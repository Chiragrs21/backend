import requests

# API key


def domain_search(domain):
    api_key = '24c7290cd73b2d0aaccc8148e6e811cf55dd23dd'

    # API endpoint URL
    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}'

    # Make the GET request
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        # Process the data as needed
        return data
    else:
        return 'Failed to retrieve data. Status code: {response.status_code}'
