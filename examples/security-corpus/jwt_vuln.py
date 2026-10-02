import jwt
def decode_token(token):
    jwt.decode(token, verify_signature=False)
    jwt.decode(token, algorithms=['none'])
