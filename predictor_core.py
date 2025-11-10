# backend_api/predictor_core.py
import os
import re
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(_file_)))
ARTIFACTS_DIR = os.path.normpath(os.path.join(BASE_DIR, "ml_pipeline", "artifacts"))

MODEL_PATH = os.path.join(ARTIFACTS_DIR, "model.pkl")
VECT_PATH = os.path.join(ARTIFACTS_DIR, "vectorizer.pkl")

if not os.path.exists(MODEL_PATH) or not os.path.exists(VECT_PATH):
    raise FileNotFoundError(f"Model or vectorizer not found in {ARTIFACTS_DIR}. Run training first.")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECT_PATH)

# Conservative rule-based patterns (only clear attack signatures)
RULE_PATTERNS = [
    r"\b(or)\s+1\s*=\s*1\b",            # OR 1=1
    r"(--|#)\s*$",                      # comment at end
    r"\bunion\s+select\b",              # UNION SELECT
    r"\b(select)\s+password\b",         # selecting password column
    r"\b(drop)\s+table\b",              # destructive
    r"\b(delete)\s+from\b",             
    r"\b(insert)\s+into\b",
    r"\b(update)\b",
    r"\bxp_cmdshell\b|\bsleep\s*\(",    # MSSQL/sys/time
    r"information_schema"               # schema enumeration
]
COMPILED = [re.compile(p, re.IGNORECASE) for p in RULE_PATTERNS]

def rule_check(q: str):
    s = (q or "")
    for pat in COMPILED:
        if pat.search(s):
            return True, pat.pattern
    return False, None

def interpret_label(label):
    if isinstance(label, (int, float)):
        return int(label) == 1
    return str(label).lower() in ("1", "sqli", "malicious", "true", "yes")

def predict_query(query: str):
    q = (query or "").strip()
    # rule-based
    is_sus, pat = rule_check(q)
    if is_sus:
        return {"label": "sqli", "confidence": 1.0, "reason": f"rule:{pat}"}

    # ml-based
    try:
        X = vectorizer.transform([q])
        pred = model.predict(X)[0]
        confidence = None
        try:
            proba = model.predict_proba(X)[0]
            confidence = float(max(proba))
        except Exception:
            confidence = None
        is_sqli = interpret_label(pred)
        return {"label": "sqli" if is_sqli else "safe", "confidence": confidence, "reason": "ml"}
    except Exception as e:
        # log or inspect e during dev
        return {"label": "safe", "confidence": None, "reason": "model_error"}
