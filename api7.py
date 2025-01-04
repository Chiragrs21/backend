import requests
from urllib3.exceptions import InsecureRequestWarning


def email_reader(email):
    url = f'https://api.eva.pingutil.com/email?email={email}'

    # Disable SSL certificate verification (use with caution)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

        data = response.json()
        # Process the data here
        return data

    except requests.exceptions.HTTPError as http_err:
        return f'HTTP error occurred: {http_err}'  # e.g., 404, 500
    except requests.exceptions.ConnectionError as conn_err:
        return f'Connection error occurred: {conn_err}'  # Network issues
    except requests.exceptions.Timeout as timeout_err:
        return f'Timeout error occurred: {timeout_err}'  # Request timed out
    except requests.exceptions.RequestException as req_err:
        # Catch-all for other request-related errors
        return f'An error occurred: {req_err}'
    except ValueError as json_err:
        # Handle JSON decoding errors
        return f'JSON decoding failed: {json_err}'
