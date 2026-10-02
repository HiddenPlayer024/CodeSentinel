import os

def ping_localhost():
    # Only pings localhost, not user input
    os.system("ping -c 1 127.0.0.1")
