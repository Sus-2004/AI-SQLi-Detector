# predictor_core.py
import os
import re
import joblib

# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "ml_pipeline", "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "model.pkl")
VECT_PATH = os.path.join(ARTIFACTS_DIR, "vectorizer.pkl")

# Load model and vectorizer
if not os.path.exists(MODEL_PATH) or not os.path.exists(VECT_PATH):
    raise FileNotFoundError(f"Model or vectorizer not found in {ARTIFACTS_DIR}. Run training first.")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECT_PATH)

# Rule-based quick check for obvious SQL injections
RULE_PATTERNS = [
    r"\bor\b\s+1\s*=\s*1",
    r"--",                # comment
    r";",                 # stacked queries
    r"\bunion\b",
    r"\bdrop\b|\bdelete\b|\binsert\b|\bupdate\b",
    r"xp_cmdshell|\bsleep\s*\(",
    r"information_schema",
    r"concat\s*\("
]
COMPILED = [re.compile(p, re.IGNORECASE) for p in RULE_PATTERNS]

def rule_check(query: str):
    q = (query or "").lower()
    for pat in COMPILED:
        if pat.search(q):
            return True, pat.pattern
    return False, None

def interpret_label(label):
    # Convert model output to boolean
    if isinstance(label, (int, float)):
        return int(label) == 1
    return str(label).lower() in ("1", "sqli", "malicious", "true", "yes")

def predict_query(query: str):
    """
    Returns: dict with 'label', 'confidence', 'reason'
    """
    query = (query or "").strip()
    # 1) Rule check
    is_sus, pat = rule_check(query)
    if is_sus:
        return {"label": "sqli", "confidence": 1.0, "reason": f"rule:{pat}"}

    # 2) ML check
    X = vectorizer.transform([query])
    try:
        pred = model.predict(X)[0]
    except Exception:
        return {"label": "sqli", "confidence": None, "reason": "model_error"}

    confidence = None
    try:
        proba = model.predict_proba(X)[0]
        confidence = float(max(proba))
    except Exception:
        confidence = None

    is_sqli = interpret_label(pred)
    return {"label": "sqli" if is_sqli else "safe", "confidence": confidence, "reason": "ml"}