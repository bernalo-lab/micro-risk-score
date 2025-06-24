from flask import Flask, request, jsonify
from datetime import datetime, timezone
from flask_cors import CORS
from scoring import calculate_risk_score
from pymongo import MongoClient
import os

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://micro-risk-score.vercel.app"}}, supports_credentials=True)

# Replace this with your actual connection string (use environment variable ideally)
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://toyinsogeke:pHCxSon6SckWubCE@financial-sandbox.haxec4g.mongodb.net/?retryWrites=true&w=majority&appName=financial-sandbox")
client = MongoClient(MONGO_URI)
db = client["risklogDB"]
collection = db["submissions"]

@app.route('/api/global-risk-score', methods=['POST'])
def global_risk_score():
    try:
        data = request.get_json()
        result = calculate_risk_score(data)

        # Log to MongoDB with full PII and scoring data
        log_data = {
            "timestamp": datetime.now(timezone.utc),
            "first_name": data.get("firstName"),
            "last_name": data.get("lastName"),
            "email": data.get("email"),
            "postcode": data.get("postcode"),
            "country": data.get("country"),
            "id_type": data.get("idType"),
            "linkedin": data.get("linkedin"),
            "github": data.get("github"),
            "payment_history": data.get("paymentHistory"),
            "reputation_score": data.get("reputationScore"),
            "score": result["score"],
            "confidence": result["confidence"],
            "factors": result["factors"]
        }

        collection.insert_one(log_data)

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin-data', methods=['POST'])
def admin_data():
    try:
        data = request.get_json()
        password = data.get("password")
        admin_password = os.getenv("ADMIN_PASSWORD", "changeme")  # Set this in Render settings

        if password != admin_password:
            return jsonify({"error": "Unauthorized"}), 401

        # Query the last 100 records
        entries = list(collection.find({}).sort("timestamp", -1).limit(100))

        # Prepare for frontend (convert ObjectId and datetime)
        def format_entry(e):
            return {
                "first_name": e.get("first_name"),
                "last_name": e.get("last_name"),
                "email": e.get("email"),
                "country": e.get("country"),
                "score": float(e.get("score", 0)),
                "confidence": float(e.get("confidence", 0)),
                "timestamp": e.get("timestamp", datetime.utcnow()).isoformat()
            }

        formatted = [format_entry(e) for e in entries]
        return jsonify({"entries": formatted}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
