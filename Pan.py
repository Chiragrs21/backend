import requests
import json


def pan_details(number):
    url = "https://api.invincibleocean.com/invincible/panAllInOne"

    payload = json.dumps({
        "panNumber": number
    })
    headers = {
        'clientId': 'aebcfa993ff9932cd93316e13ab2dff5:a5a5414585c198c5cc5f6481399dcd93',
        'secretKey': 'PO2aM5aMh3P9wpVGDmtAFBFyNH0jUfyo2v9YuNPERCJ1Y7jOee2dtkTwj2InHp9Mw',
        'Content-Type': 'application/json'
    }

    response2 = requests.request(
        "POST", url, headers=headers, data=payload).json()

    return response2
