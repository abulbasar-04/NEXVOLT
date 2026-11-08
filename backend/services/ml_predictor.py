from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from services.feature_extraction import extract_url_features


MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"
model = joblib.load(MODEL_PATH)

# Exact trusted-domain roots
TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "paypal.com",
    "example.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
}


def is_trusted_domain(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        hostname = (parsed.hostname or "").lower().rstrip(".")

        if not hostname:
            return False

        for domain in TRUSTED_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return True

        return False

    except Exception:
        return False


def predict_url(url: str):

    # Trusted domain override
    if is_trusted_domain(url):
        return {
            "prediction": "Legitimate",
            "phishing_probability": 0.0,
            "legitimate_probability": 100.0,
            "message": "Trusted domain match. URL path still requires security checks.",
        }

    features = extract_url_features(url)
    input_data = pd.DataFrame([features])

    prediction = model.predict(input_data)[0]
    probabilities = model.predict_proba(input_data)[0]

    phishing_probability = probabilities[
        list(model.classes_).index(0)
    ]

    legitimate_probability = probabilities[
        list(model.classes_).index(1)
    ]

    verdict = "Phishing" if prediction == 0 else "Legitimate"

    return {
        "prediction": verdict,
        "phishing_probability": round(
            float(phishing_probability) * 100, 2
        ),
        "legitimate_probability": round(
            float(legitimate_probability) * 100, 2
        ),
    }
