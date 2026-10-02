import requests

def fetch_internal():
    # Hardcoded, no user input
    url = "https://api.internal.service/data"
    response = requests.get(url)
    return response.text
