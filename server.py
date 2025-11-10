# backend_api/server.py
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from predictor_core import predict_query
from db_logger import init_db, log_query, get_stats

app = Flask(_name_)
# Allow all origins (acceptable for your demo). For production lock to specific origins.
CORS(app, resources={r"/": {"origins": ""}})

# initialize DB (creates DB file & table if missing)
init_db()

@app.route("/check", methods=["POST"])
def check_query():
    data = request.get_json(force=True) or {}
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"label": "error", "reason": "No query provided"}), 400

    result = predict_query(query)  # dict with label/confidence/reason
    # store reason too
    log_query(query, result.get("label", "unknown"), result.get("reason"))
    return jsonify(result)

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(get_stats())

if _name_ == "_main_":
    # port and host configurable via env (useful on hosting platforms)
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    print(f"Server running at http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
