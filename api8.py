import requests


def email_social_media(email):

    headers = {
        "X-API-KEY": "1b988c8a-7bca-4ad4-a6d8-fbc425b2b30e"
    }

    email_address = email
    url = f"https://api.us-east-1-main.seon.io/SeonRestService/email-api/v2/{email_address}"

    r = requests.get(url, headers=headers).json()

    return r
