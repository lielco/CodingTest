from app import app, auth
from flask import jsonify

# error handling
@app.errorhandler(auth.AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.to_dict())
    response.status_code = ex.status_code
    return response

# routes
@app.route('/api/health', methods=['GET'])
def health():
    return "status=1"

@app.route('/api/param-test/<param>', methods=['GET'])
@auth.token_required
def param(param):
    return jsonify(param=param)