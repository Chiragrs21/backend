import requests


def phone_lookup(phone_number):
    api_key = '96280930B3154968B4A646546F9DF23E'

    url = f'https://api.veriphone.io/v2/verify?phone={phone_number}&key={api_key}'

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return 'Failed to verify phone number. Status code: {response.status_code}'
