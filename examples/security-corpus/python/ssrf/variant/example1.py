import urllib.request
from flask import request, Flask

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # using urllib instead of requests
    with urllib.request.urlopen(url) as response:
        return response.read()
