from fastapi import FastAPI
import joblib
import numpy as np
from extract_features import extract_features
from layer1 import layer1_rule_based

app = FastAPI()

model = joblib.load("voting_model.pkl")

FEATURE_ORDER = [
    "D1","L1","L2","L3","L4","L5","L6","L7","L8","L9",
    "L10","L11","L12","L13","L14","L15","L16","L17","L18","L19"
]

@app.post("/predict")
def predict(url: str):
    features = extract_features(url)

    # Layer 1
    if layer1_rule_based(features) == 1:
        return {
            "url": url,
            "prediction": "phishing",
            "layer": "rule-based",
            "confidence": 1.0
        }

    # Layer 2
    X = np.array([[features[f] for f in FEATURE_ORDER]])
    prob = model.predict_proba(X)[0][1]

    return {
        "url": url,
        "prediction": "phishing" if prob > 0.5 else "benign",
        "layer": "ml",
        "confidence": round(float(prob), 3)
    }
