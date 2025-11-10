# predictor_core.py
import os, re, joblib

BASE = os.path.dirname(os.path.dirname(os.path.abspath(_file_)))
ARTIFACTS = os.path.join(BASE, "ml_pipeline", "artifacts")
MODEL = os.path.join(ARTIFACTS, "model.pkl")
VECT = os.path.join(ARTIFACTS, "vectorizer.pkl")

if not (os.path.exists(MODEL) and os.path.exists(VECT)):
    raise FileNotFoundError(f"Model/vectorizer missing in {ARTIFACTS}")

model = joblib.load(MODEL)
vectorizer = joblib.load(VECT)

# safer rule patterns (avoid overly broad ones like ';' or 'concat(')
RULES = [
  r"\bor\b\s+1\s*=\s*1",           # OR 1=1
  r"(--|#)",                       # end-of-line comment
  r"\bunion\s+select\b",           # UNION SELECT
  r"\bdrop\s+table\b",             # drop table
  r"\bdelete\s+from\b",            # delete from
  r"\binsert\s+into\b",            # insert into
  r"\bupdate\s+\w+\s+set\b",       # update ... set
  r"xp_cmdshell|\bsleep\s*\(",     # dangerous funcs
  r"information_schema"            # schema enumeration
]
COMPILED = [re.compile(p, re.IGNORECASE) for p in RULES]

def rule_check(q):
    s = (q or "")
    for pat in COMPILED:
        if pat.search(s):
            return True, pat.pattern
    return False, None

def interpret_label(lbl):
    if isinstance(lbl, (int, float)):
        return int(lbl) == 1
    return str(lbl).lower() in ("1","sqli","malicious","true","yes")

def predict_query(query):
    q = (query or "").strip()
    # rule
    is_sus, pat = rule_check(q)
    if is_sus:
        return {"label":"sqli","confidence":1.0,"reason":f"rule:{pat}"}
    # ML
    try:
        X = vectorizer.transform([q])
        pred = model.predict(X)[0]
        proba = None
        try:
            proba = float(max(model.predict_proba(X)[0]))
        except Exception:
            proba = None
        sqli = interpret_label(pred)
        return {"label":"sqli" if sqli else "safe","confidence":proba,"reason":"ml"}
    except Exception as e:
        # conservative: mark safe if model fails? here we mark 'safe' but you can choose sqli
        return {"label":"safe","confidence":None,"reason":"model_error"}
