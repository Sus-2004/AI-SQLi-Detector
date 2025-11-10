# server.py
import sys
import os
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS

# ---- Helpful prints for debugging (so terminal is never "silent") ----
print("=== Starting import of server.py ===")

# Make sure current dir is backend_api so relative imports work when running from that folder
# (If you run from project root, Python still finds backend_api package files)
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
print("Current backend_api directory:", THIS_DIR)
sys.path.insert(0, THIS_DIR)

# ---- Import predictor and db helper with friendly error messages ----
try:
    from predictor_core import predict_query
except Exception as e:
    print("ERROR importing predictor_core:", e)
    traceback.print_exc()
    # Re-raise so the user can see the error and fix model/artifacts
    raise

try:
    from db_logger import init_db, log_query, get_stats
except Exception as e:
    print("ERROR importing db_logger:", e)
    traceback.print_exc()
    raise

print("Imported predictor_core and db_logger successfully.")
print("=== server.py imports complete ===\n")

# ---- Flask app setup ----
app = Flask(__name__)
CORS(app)  # allow frontend on other origin/port to call this API

# initialize DB (creates file/table if missing)
try:
    init_db()
    print("Database initialized (or already present).")
except Exception as e:
    print("Error initializing DB:", e)
    traceback.print_exc()
    # continue; DB errors will surface when endpoints are hit

# ---- Routes ----
@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok", "message": "AI SQLi Detector backend running"}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route("/check", methods=["POST"])
def check_query():
    """
    Expects JSON: { "query": "<SQL query>" }
    Returns JSON from predictor: { label: 'sqli'|'safe', confidence: float|None, reason: str|None }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not data or "query" not in data:
        return jsonify({"error": "Missing 'query' in request body"}), 400

    query = data.get("query", "") or ""
    # Protect: ensure it's a string
    if not isinstance(query, str):
        return jsonify({"error": "'query' must be a string"}), 400

    try:
        result = predict_query(query)
    except Exception as e:
        # don't crash the server; return safe fallback and log error to console
        print("Error during prediction:", e)
        traceback.print_exc()
        result = {"label": "safe", "confidence": None, "reason": "prediction_error"}

    # Log query and label (safe/sqli) for stats
    try:
        label = result.get("label", "safe")
        log_query(query, label)
    except Exception as e:
        print("Warning: failed to log query:", e)
        traceback.print_exc()

    return jsonify(result)

@app.route("/stats", methods=["GET"])
def stats():
    try:
        s = get_stats()
        return jsonify(s)
    except Exception as e:
        print("Error fetching stats:", e)
        traceback.print_exc()
        return jsonify({"error": "failed to fetch stats"}), 500

# ---- Run server ----
if __name__ == "_main_":
    print("Starting Flask server at http://127.0.0.1:5000")
    # Use 0.0.0.0 if you want it reachable on your LAN; use 127.0.0.1 for localhost-only
    app.run(host="127.0.0.1", port=5000, debug=True)