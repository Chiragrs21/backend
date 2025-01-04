import requests


def ip_verification(ip):

    headers = {
        "X-API-KEY": "340d72ef-1310-419a-980f-e2f7d1abda1a"
    }

    url = f"https://api.us-east-1-main.seon.io/SeonRestService/ip-api/v1.1/{ip}"

    r = requests.get(url, headers=headers)

    return r.text
