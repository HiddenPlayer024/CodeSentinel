import requests
from flask import request, Flask

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text
