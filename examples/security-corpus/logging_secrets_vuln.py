import logging
def log_creds(password, secret_token):
    logging.info(f"User logged in with password {password}")
    logging.debug(secret_token)
