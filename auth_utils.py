# auth_utils.py

import secrets
import datetime
import bcrypt

def generate_unique_token():
    return secrets.token_urlsafe(32)

def verify_reset_token(token):
    # Check if the token exists and hasn't expired (e.g., within the last 24 hours)
    # You should store reset tokens and their expiration timestamps in your database
    # and query the database to validate the token.
    # Here, we assume a simple dictionary for demonstration purposes.
    reset_tokens = {
        'token123': {'user_id': 1, 'expiration_time': datetime.datetime.now() + datetime.timedelta(hours=24)}
    }

    if token in reset_tokens:
        if datetime.datetime.now() < reset_tokens[token]['expiration_time']:
            return True

    return False

def update_password(user, new_password):
    user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    # Database update logic here
