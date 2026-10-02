import requests
import httpx
import urllib.request
def fetch_url(url):
    requests.get(url)
    httpx.post(url)
    urllib.request.urlopen(url)
