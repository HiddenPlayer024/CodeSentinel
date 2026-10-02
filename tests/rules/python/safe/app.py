import os
import subprocess
import hashlib
import yaml
import sqlite3

def safe_command(user_input):
    # shell=False and list of args
    subprocess.run(["ping", "-c", "4", user_input], shell=False)

def strong_crypto(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return m.hexdigest()

def safe_load(payload):
    return yaml.safe_load(payload)

def safe_sql(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
