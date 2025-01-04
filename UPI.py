import requests
import json


def upi_details(number):
    url_mobile_upi = "https://api.invincibleocean.com/invincible/mobileUpi"

    payload_mobile_upi = json.dumps({
        "mobileNumber": number
    })

    headers = {
        'clientId': 'aebcfa993ff9932cd93316e13ab2dff5:a5a5414585c198c5cc5f6481399dcd93',
        'secretKey': 'PO2aM5aMh3P9wpVGDmtAFBFyNH0jUfyo2v9YuNPERCJ1Y7jOee2dtkTwj2InHp9Mw',
        'Content-Type': 'application/json'
    }

    try:
        response_mobile_upi = requests.post(
            url_mobile_upi, headers=headers, data=payload_mobile_upi)

        # Will raise HTTPError for bad responses
        response_mobile_upi.raise_for_status()

        if response_mobile_upi.status_code == 404:
            return "UPI not found"

        response_data = response_mobile_upi.json()

        if response_data.get("code") == 200:
            upi_details_list = response_data.get(
                "result", {}).get("upiDetailsList", [])
            result = [upi_detail["upiId"] for upi_detail in upi_details_list]

            url_upi_to_bank = "https://api.invincibleocean.com/invincible/upiToBank"
            headers = {
                'clientId': 'aebcfa993ff9932cd93316e13ab2dff5:a5a5414585c198c5cc5f6481399dcd93',
                'secretKey': 'PO2aM5aMh3P9wpVGDmtAFBFyNH0jUfyo2v9YuNPERCJ1Y7jOee2dtkTwj2InHp9Mw',
                'Content-Type': 'application/json'
            }

            for upi_id in result:
                print(upi_id)
                payload_upi_to_bank = json.dumps({
                    "upiId": upi_id
                })
                response_upi_to_bank = requests.post(
                    url_upi_to_bank, headers=headers, data=payload_upi_to_bank)

                # Will raise HTTPError for bad responses
                response_upi_to_bank.raise_for_status()
                response_upi_data = response_upi_to_bank.json()

                if response_upi_to_bank.status_code == 200 and response_upi_data.get("code") == 200:
                    return response_upi_data

            return "No valid UPI ID found"
        else:
            return "Error: Unable to retrieve UPI details"

    except requests.exceptions.HTTPError as http_err:
        return f"HTTP error occurred: {http_err}"
    except Exception as err:
        return f"Other error occurred: {err}"
