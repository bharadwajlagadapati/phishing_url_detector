from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import joblib
import numpy as np

from features import extract_features
from layer1 import layer1_rule_based

app = FastAPI()

templates = Jinja2Templates(directory="templates")

# Load model
model = joblib.load("voting_model.pkl")

FEATURE_ORDER = [
    "D1","L1","L2","L3","L4","L5","L6","L7","L8","L9",
    "L10","L11","L12","L13","L14","L15","L16","L17","L18","L19"
]

# ---------------- HOME PAGE ----------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "prediction": None,
            "confidence": None,
            "layer": None,
            "url": None
        }
    )

# ---------------- UI PREDICTION ----------------
@app.post("/predict-ui", response_class=HTMLResponse)
def predict_ui(request: Request, url: str = Form(...)):

    features = extract_features(url)

    # -------- Layer 1 (Rule-based) --------
    if layer1_rule_based(features) == 1:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "url": url,
                "prediction": "phishing",
                "layer": "rule-based",
                "confidence": 1.0
            }
        )

    # -------- Layer 2 (ML model) --------
    X = np.array([[features[f] for f in FEATURE_ORDER]])
    prob = model.predict_proba(X)[0][1]

    prediction = "phishing" if prob > 0.5 else "benign"

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "url": url,
            "prediction": prediction,
            "layer": "ml",
            "confidence": round(float(prob), 3)
        }
    )
