import requests
from flask import request, Flask

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "api.example.com"]

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not any(url.startswith(f"https://{d}/") for d in ALLOWED_DOMAINS):
        return "Invalid domain", 403
    response = requests.get(url)
    return response.text
