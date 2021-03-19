from app import app
from flask import request, jsonify
from jose import jwt
from functools import wraps
import json
import urllib

AUTH0_DOMAIN = "staging-netapp-cloud-account.auth0.com"
API_AUDIENCE = "https://api.cloud.netapp.com"
ALGORITHMS = ["RS256"]
METADATA_ENDPOINT = "https://{0}/.well-known/jwks.json"

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def get_token_from_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"error" : "Missing authorization header"}, 401)
    parts = auth.split()
    if parts[0].casefold() != "bearer" or len(parts) != 2:
        raise AuthError({"error" : "Invalid bearer token"}, 401)
    token = parts[1]
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_auth_header()

        response = urllib.request.urlopen(METADATA_ENDPOINT.format(AUTH0_DOMAIN))
        pub_keys = json.load(response)
        try:
            key_id = jwt.get_unverified_header(token).get('kid')
            if not key_id:
                raise AuthError({"error" : "No key ID"}, 401)

            for key in pub_keys["keys"]:
                if key["kid"] == key_id:
                    rsa_key = {
                        "kty" : key["kty"],
                        "kid" : key["kid"],
                        "use" : key["use"],
                        "n" : key["n"],
                        "e" : key["e"]
                    }

            payload = jwt.decode(
                token, 
                rsa_key, 
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer= "https://" + AUTH0_DOMAIN + "/",
                options= {'verify_exp': False} # The given bearer token is expired
        )
        except Exception as e:
            raise AuthError({"message" : "Invalid token"}, 401)
        return f(*args,**kwargs)
    return decorated

@app.route('/api/health', methods=['GET'])
def health():
    return "status=1"


@app.route('/api/param-test/<param>', methods=['GET'])
@token_required
def param(param):
    return {"param" : param}