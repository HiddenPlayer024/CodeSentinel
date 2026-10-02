import os
import subprocess
import hashlib
import yaml
import sqlite3

def dangerous_command(user_input):
    os.system("ping -c 4 " + user_input)
    subprocess.run(f"ls -la {user_input}", shell=True)

def weak_crypto(password):
    m = hashlib.md5()
    m.update(password.encode())
    return m.hexdigest()

def unsafe_load(payload):
    return yaml.load(payload)

def sql_inject(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")

def expose_secret():
    api_key = "AKIA1234567890ABCDEF" # Hardcoded secret
    return api_key

def insecure_randomness():
    import random
    return random.randint(1000, 9999) # Insecure crypto

def use_weak_cipher(key):
    from Crypto.Cipher import DES
    cipher = DES.new(key, DES.MODE_ECB) # Weak cryptography
    return cipher

def path_traversal(filename):
    f = open("/var/www/html/images/" + filename, "r") # Path traversal
    return f.read()

