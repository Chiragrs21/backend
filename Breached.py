import requests


def breaches(email):

    url = "https://breachdirectory.p.rapidapi.com/"
    querystring = {"func": "auto", "term": email}

    headers = {
        'x-rapidapi-host': "breachdirectory.p.rapidapi.com",
        'x-rapidapi-key': "fb065b8608msh38ec8b4dd9e9c3dp1cf800jsn7eb3f52e9dd6"
    }

    response = requests.get(url, headers=headers, params=querystring)

    return response.json()
