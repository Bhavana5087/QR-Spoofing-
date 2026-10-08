from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
import os
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

# Load trained model safely
MODEL_PATH = "pickle/model.pkl"
gbc = None
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as file:
            gbc = pickle.load(file)
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Error loading model from {MODEL_PATH}: {e}")
else:
    print(f"Model file {MODEL_PATH} not found!")

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            return render_template("index.html", xx=-1, error="Please enter a valid URL or QR content.")

        try:
            # Initialize feature extraction
            obj = FeatureExtraction(url)
            
            # ✅ Handle non-URL QR (e.g., UPI, plain text)
            if getattr(obj, "is_non_url", False):
                return render_template("index.html", xx=-2, url=url)
            
            # Validate model is loaded
            if gbc is None:
                return render_template("index.html", xx=-1, url=url, error="Classifier model is currently unavailable.")

            # Validate feature vector
            features = obj.getFeaturesList()
            if not features or len(features) != 30:
                return render_template("index.html", xx=-1, url=url, error="Failed to extract 30 features from the URL.")

            # Prepare for prediction
            x = np.array(features).reshape(1, 30)
            
            # Run prediction and calculate probability
            # Classes are [-1, 1], so class 1 (non-phishing) probability is at index 1
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

            return render_template("index.html", xx=round(float(y_pro_non_phishing), 2), url=url)
            
        except Exception as e:
            print(f"Error during prediction: {e}")
            return render_template("index.html", xx=-1, url=url, error=f"Analysis error: {str(e)}")

    return render_template("index.html", xx=-1)

if __name__ == "__main__":
    app.run(debug=True, port=8001)
