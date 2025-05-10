from flask_socketio import SocketIO, emit
from flask import Flask, render_template, request
from url_parser import extract_url_features
import joblib
import numpy as np

app = Flask(__name__)
socketio = SocketIO(app)

# Define expected feature order (must match model training data)
# Expected features for the model
EXPECTED_FEATURES = [
    'qty_slash_url', 'length_url', 'qty_dot_directory', 'qty_hyphen_directory',
    'qty_underline_directory', 'qty_questionmark_directory', 'directory_length',
    'qty_hyphen_file', 'file_length', 'qty_dot_params', 'qty_questionmark_params',
    'asn_ip', 'time_domain_activation', 'time_domain_expiration', 'ttl_hostname',
]

# Paths to model files
MODEL_PATH = '../code/model.pkl'
SCALER_PATH = '../code/scaler.pkl'

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


# def validate_and_order_features(raw_features):
#     """Ensure correct feature order and handle missing features"""
#     validated = {feature: raw_features.get(feature, feature_medians.get(feature, 0)) for feature in EXPECTED_FEATURES}
#     return [validated[f] for f in EXPECTED_FEATURES]


def validate_features(features):
    """
    Validate and order features to match EXPECTED_FEATURES.
    """
    # Ensure all features are present and in the correct order
    validated_features = [features.get(key, -1) for key in EXPECTED_FEATURES]
    return np.array(validated_features).reshape(1, -1)  # Reshape for model input


def predict_phishing(features):
    """Complete phishing prediction pipeline"""
    if model is None or scaler is None:
        raise Exception("Model or scaler is not loaded")

    # Extract and validate features
    ordered_features = validate_features(features)
    features_array = np.array(ordered_features).reshape(1, -1)

    # Scale features
    scaled_features = scaler.transform(features_array)
    print("Scaled features")
    # Make prediction
    prediction = model.predict(scaled_features)[0]
    prediction_probabilities = model.predict_proba(scaled_features)[0]
    print("Scaled features 2")

    print(len(ordered_features.reshape(-1, 1)), len(EXPECTED_FEATURES))

    return {
        'prediction': int(prediction),
        'probabilities': prediction_probabilities.tolist(),  # Convert to list
        'features': ordered_features.reshape(-1, 1).tolist(),  # Convert to list
        'scaled_features': scaled_features[0].tolist(),  # Convert to list
        'feature_names': EXPECTED_FEATURES
    }

@socketio.on('start_scan')
def handle_scan(data):
    url = data.get('url', '').strip()
    if not url:
        emit('scan_update', {'error': 'Invalid URL'})
        return

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        def send_update(message):
            emit('scan_update', {'message': message})

        send_update("Starting URL scan...")
        features = extract_url_features(url, callback=send_update)
        print("Features ",features)
        send_update("Features extracted successfully.")

        # Prediction step
        send_update("Running the prediction model...")
        prediction_result = predict_phishing(features)

        send_update("Prediction complete. Preparing response.")
        emit('scan_complete', prediction_result)
    except Exception as e:
        emit('scan_update', {'error': str(e)})

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)



