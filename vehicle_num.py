import requests
import json


def vehicle_num_out(number):
    url = "https://api.invincibleocean.com/invincible/vehicleRegistrations"

    payload = json.dumps({
        "vehicleNumber": number,
        "blacklistCheck": True
    })
    headers = {
        'clientId': 'aebcfa993ff9932cd93316e13ab2dff5:a5a5414585c198c5cc5f6481399dcd93',
        'secretKey': 'PO2aM5aMh3P9wpVGDmtAFBFyNH0jUfyo2v9YuNPERCJ1Y7jOee2dtkTwj2InHp9Mw',
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "POST", url, headers=headers, data=payload).json()

    return response
