from app import app

@app.route('/api/health', methods=['GET'])
def health():
    return "status=1"

@app.route('/api/param/<param>', methods=['GET'])
def param(param):
    return {"param" : param}