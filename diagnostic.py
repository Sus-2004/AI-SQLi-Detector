# diagnostic.py
import os, joblib
base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_pipeline", "artifacts")
print("Artifacts dir:", base)
print("Files:", os.listdir(base))
vecp = os.path.join(base, "vectorizer.pkl")
modp = os.path.join(base, "model.pkl")
print("Vectorizer exists:", os.path.exists(vecp))
print("Model exists:", os.path.exists(modp))
if os.path.exists(vecp) and os.path.exists(modp):
    vect = joblib.load(vecp)
    model = joblib.load(modp)
    tests = [
        "SELECT * FROM users WHERE id=1",
        "' OR '1'='1",
        "admin' --",
        "UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --",
        "OR 1=1"
    ]
    for t in tests:
        x = vect.transform([t])
        p = model.predict(x)[0]
        proba = None
        try:
            proba = model.predict_proba(x)[0]
        except Exception:
            proba = None
        print("QUERY:", t)
        print(" PRED:", p, " PROBA:", proba)
else:
    print("No model or vectorizer found - run training.")
