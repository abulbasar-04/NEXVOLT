
import joblib
import pandas as pd

from services.feature_extraction import extract_url_features


# Load trained model
model = joblib.load("services/phishing_model.pkl")


def predict_url(url: str):

    # Extract URL features
    features = extract_url_features(url)

    # Convert features into DataFrame
    input_data = pd.DataFrame([features])

    # Predict label
    prediction = model.predict(input_data)[0]

    # Predict probability
    probabilities = model.predict_proba(input_data)[0]

    phishing_probability = probabilities[
        list(model.classes_).index(0)
    ]

    legitimate_probability = probabilities[
        list(model.classes_).index(1)
    ]

    # Convert prediction
    if prediction == 0:
        verdict = "Phishing"
    else:
        verdict = "Legitimate"

    return {
        "prediction": verdict,
        "phishing_probability": round(
            float(phishing_probability) * 100, 2
        ),
        "legitimate_probability": round(
            float(legitimate_probability) * 100, 2
        )
    }
