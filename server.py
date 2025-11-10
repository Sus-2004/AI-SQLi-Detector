# server.py
import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from predictor_core import predict_query
from db_logger import init_db, log_query, get_stats, export_logs_csv

app = Flask(_name_)
CORS(app)
init_db()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"})

@app.route("/check", methods=["POST"])
def check():
    body = request.get_json(force=True)
    q = body.get("query","").strip()
    if not q:
        return jsonify({"label":"error","reason":"no query provided"}), 400
    res = predict_query(q)
    # log with reason
    log_query(q, res.get("label","safe"), res.get("reason"))
    return jsonify(res)

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(get_stats())

# optional: download CSV of logs (simple)
@app.route("/export_logs", methods=["GET"])
def export_logs():
    csv_path = export_logs_csv()
    if not csv_path:
        return jsonify({"error":"no logs"}), 404
    return send_file(csv_path, mimetype="text/csv", download_name="logs.csv", as_attachment=True)

if _name_ == "_main_":
    # listen on all interfaces for mobile access
    port = int(os.environ.get("PORT", 5000))
    print(f"Server running at http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
