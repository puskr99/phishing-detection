from flask import Flask, render_template, request, redirect, url_for
import joblib
import numpy as np
from datetime import datetime
from url_parser import extract_features_from_url

app = Flask(__name__)

# Define expected feature order (must match model training data)
EXPECTED_FEATURES = [
    'qty_slash_url', 'length_url', 'qty_dot_directory', 'qty_hyphen_directory', 
    'qty_underline_directory', 'qty_questionmark_directory', 'directory_length', 
    'qty_hyphen_file', 'file_length', 'qty_dot_params', 'qty_questionmark_params', 
    'asn_ip', 'time_domain_activation', 'time_domain_expiration', 'ttl_hostname',
]

# Paths to model files
MODEL_PATH = 'code/model.pkl'
SCALER_PATH = 'code/scaler.pkl'

# Try loading model & scaler
try:
    model = joblib.load(open(MODEL_PATH, 'rb'))
    scaler = joblib.load(open(SCALER_PATH, 'rb'))
    print("Model and scaler loaded successfully")
except Exception as e:
    print(f"Error loading model/scaler: {e}")
    model = None
    scaler = None

# Precomputed median values for missing feature handling
feature_medians = { 
    'qty_dot_url': 1, 'qty_hyphen_url': 0, 'qty_underline_url': 0, 'qty_slash_url': 3,
    'qty_questionmark_url': 0, 'qty_equal_url': 1, 'qty_at_url': 0, 'qty_and_url': 0,
    'qty_exclamation_url': 0, 'qty_space_url': 0, 'qty_ip_resolved': 0, 'qty_nameservers': 2,
    'qty_mx_servers': 1, 'ttl_hostname': 300, 'tls_ssl_certificate': 1, 'qty_redirects': 1,
    'url_google_index': 1, 'domain_google_index': 1, 'url_shortened': 0
}

def validate_and_order_features(raw_features):
    """Ensure correct feature order and handle missing features"""
    validated = {feature: raw_features.get(feature, feature_medians.get(feature, 0)) for feature in EXPECTED_FEATURES}
    return [validated[f] for f in EXPECTED_FEATURES]

def predict_phishing(url):
    """Complete phishing prediction pipeline"""
    if model is None or scaler is None:
        raise Exception("Model or scaler is not loaded")

    # Extract features
    raw_features = extract_features_from_url(url)

    # Validate and order features
    ordered_features = validate_and_order_features(raw_features)
    features_array = np.array(ordered_features).reshape(1, -1)

    # Scale features
    scaled_features = scaler.transform(features_array)

    # Make prediction
    prediction = model.predict(scaled_features)[0]
    probability = model.predict_proba(scaled_features)[0][1]

    return {
        'prediction': prediction,
        'probability': probability,
        'features': raw_features,
        'scaled_features': scaled_features[0].tolist(),
        'feature_names': EXPECTED_FEATURES
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url', '').strip()
    if not url:
        return redirect(url_for('home'))

    start_time = datetime.now()

    try:
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Get prediction
        result = predict_phishing(url)
        scan_time = (datetime.now() - start_time).total_seconds()

        # Prepare response
        response = {
            'url': url,
            'status': 'Phishing' if result['prediction'] == 1 else 'Legitimate',
            'confidence': round(result['probability'] * 100, 2),
            'features': result['features'],
            'scaled_features': dict(zip(result['feature_names'], result['scaled_features'])),
            'scan_time': round(scan_time, 2),
            'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'feature_names': result['feature_names']
        }

        return render_template('result.html', result=response)

    except Exception as e:
        return render_template('result.html', error=str(e), url=url, scan_time=round((datetime.now() - start_time).total_seconds(), 2))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
