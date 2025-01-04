import requests
import json


def upitobank(upi):

    # Define the API URL
    url = "https://api.invincibleocean.com/invincible/upiToBank"

    # Define the headers
    headers = {
        'Content-Type': 'application/json',
        # Replace with your actual clientId
        'clientId': 'aebcfa993ff9932cd93316e13ab2dff5:a5a5414585c198c5cc5f6481399dcd93',
        # Replace with your actual secretKey
        'secretKey': 'PO2aM5aMh3P9wpVGDmtAFBFyNH0jUfyo2v9YuNPERCJ1Y7jOee2dtkTwj2InHp9Mw'
    }

    # Define the payload
    payload = {
        "upiId": upi  # Replace with the actual UPI ID
    }

    # Send the POST request
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(payload))
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Print the JSON response from the API
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle exceptions and errors
        print("Error fetching data:", e)
