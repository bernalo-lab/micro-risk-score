from flask import Flask, request, jsonify
from datetime import datetime
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

        log_data = {
            "timestamp": datetime.utcnow(),
            "first_name": data.get("first_name"),
            "last_name": data.get("last_name"),
            "email": data.get("email"),
            "postcode": data.get("postcode"),
            "country": data.get("country"),
            "id_type": data.get("id_type"),
            "linkedin": data.get("linkedin"),
            "github": data.get("github"),
            "payment_history": data.get("payment_history"),
            "reputation_score": data.get("reputation_score"),
            "score": result["score"],
            "confidence": result["confidence"],
            "factors": result["factors"]
        }

        collection.insert_one(log_data)

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
