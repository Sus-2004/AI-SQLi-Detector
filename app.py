# app.py
from flask import Flask, request, jsonify 
from flask_cors import CORS 
from predictor_core import predict_query
from db_logger import log_query, get_stats

app = Flask(__name__)
CORS(app)

@app.route("/check", methods=["POST"])
def check_query():
    data = request.json
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"label": "empty", "reason": "No query provided"})

    result = predict_query(query)
    log_query(query, result['label'], result.get('reason'))
    return jsonify(result)

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(get_stats())

if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000,debug=True)
