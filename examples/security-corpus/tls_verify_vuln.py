import requests
import ssl
def insecure_request():
    requests.get("https://example.com", verify=False)
    ssl._create_unverified_context()
