# requests_utils.py
import requests
import json
from apikey import apikey

def make_request(method, url, output_callback, **kwargs):
    headers = {"accept": "application/json", "x-apikey": apikey}
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, **kwargs)
        elif method == "POST":
            response = requests.post(url, headers=headers, **kwargs)
        else:
            output_callback("Invalid request method.")
            return

        if response.status_code == 200:
            response_data = response.json()
            output_callback(json.dumps(response_data, indent=4))
        else:
            error_message = f"Error: {response.status_code} - {response.text}"
            output_callback(error_message)
    except Exception as e:
        output_callback(f"Exception occurred: {str(e)}")
