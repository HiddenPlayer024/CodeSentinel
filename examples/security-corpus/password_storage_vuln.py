import hashlib
def hash_pass(password):
    hashlib.md5(password.encode())
    hashlib.sha1(password.encode())
