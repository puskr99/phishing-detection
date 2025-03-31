from flask import Flask, render_template, request, jsonify
from url_parser import extract_features_from_url


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/data', methods=['POST'])
def handle_data():
    try:
        data = request.json
        response = {
            "message": "Data received successfully",
            "data": data
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)