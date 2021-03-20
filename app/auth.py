from flask import request, jsonify
from jose import jwt
import urllib
from .auth_consts import AUTH0_DOMAIN, API_AUDIENCE, ALGORITHMS, JWKS_URL, ISSUER
import json
from functools import wraps

class AuthError(Exception):
    def __init__(self, message, status_code):
        self.message = message
        self.status_code = status_code
    
    def to_dict(self):
        mdic = dict()
        mdic['message'] = self.message
        return mdic

def get_token_from_auth_header():
    """ Extracts the bearer token from the authorization header """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError("Missing authorization header", 401)
    parts = auth.split()
    if parts[0].casefold() != "bearer" or len(parts) != 2:
        raise AuthError("Invalid bearer token", 401)
    token = parts[1]
    return token

def get_public_key_by_kid(kid):
    """ Searches the JWKS for the key ID and returns the key.
        If no key was found, returns null.
    """
    response = urllib.request.urlopen(JWKS_URL.format(AUTH0_DOMAIN))
    pub_keys = json.load(response)
    for key in pub_keys["keys"]:
        if key["kid"] == kid:
            return key
    return None

def token_required(f):
    """ Checks JWT token existence and validity """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_auth_header()
        try:
            key_id = jwt.get_unverified_header(token).get('kid')
            if not key_id:
                raise AuthError("No key ID", 401)
            rsa_key = get_public_key_by_kid(key_id)
            if not rsa_key:
                raise AuthError("Could not find specified key", 401)
            payload = jwt.decode(
                token, 
                rsa_key, 
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer= ISSUER.format(AUTH0_DOMAIN),
                options= {'verify_exp': False} # The given bearer token is expired
            )
        except jwt.JWTError as e:
            raise AuthError("Invalid token. error: {}".format(e), 401)
        return f(*args,**kwargs)
    return decorated