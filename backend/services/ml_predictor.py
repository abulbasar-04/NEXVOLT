from pathlib import Path
import joblib
import pandas as pd

from services.feature_extraction import extract_url_features


MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"
model = joblib.load(MODEL_PATH)

def predict_url(url: str):
    features = extract_url_features(url)
    input_data = pd.DataFrame([features])

    prediction = model.predict(input_data)[0]
    probabilities = model.predict_proba(input_data)[0]

    class_indexes = {label: index for index, label in enumerate(model.classes_)}
    if 0 not in class_indexes or 1 not in class_indexes:
        raise ValueError("The phishing model must expose classes 0 and 1.")

    phishing_probability = probabilities[class_indexes[0]]
    legitimate_probability = probabilities[class_indexes[1]]

    verdict = "Phishing" if prediction == 0 else "Legitimate"

    return {
        "prediction": verdict,
        "phishing_probability": round(
            float(phishing_probability) * 100, 2
        ),
        "legitimate_probability": round(
            float(legitimate_probability) * 100, 2
        ),
        "model_source": "trained_model",
    }
