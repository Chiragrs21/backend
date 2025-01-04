import requests
import json


def domain_email_search(email):
    api_key = '6e3cda7b04a5ca3de452f20e3efb9d05682be41f'

    # API endpoint URL
    url = f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}'

    # Make the GET request
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        data = response.json()
        return data  # Print the verification result
    else:
        return 'Failed to verify email. Status code: {response.status_code}'
