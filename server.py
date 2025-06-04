# C. Code for Creating a Server
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import predict
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

@app.route('/api/check-url', methods=['POST'])
def check_url():
    try:
        url_data = request.json
        if not url_data or 'url' not in url_data:
            return jsonify({'error': 'No URL provided'}), 400
        
        url = url_data['url']
        if not is_valid_url(url):
            return jsonify({'error': 'Invalid URL format'}), 400

        result = predict.retrive_pred(url)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
