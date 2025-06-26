from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import jwt
import bcrypt

load_dotenv()
print("🔍 Loaded Environment Variables:")
print("EMAIL_HOST:", os.getenv("EMAIL_HOST"))
print("EMAIL_PORT:", os.getenv("EMAIL_PORT"))
print("EMAIL_USER:", os.getenv("EMAIL_USER"))
print("EMAIL_FROM:", os.getenv("EMAIL_FROM"))
print("MONGO_URI (partial):", os.getenv("MONGO_URI", "")[:30] + "...")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://micro-risk-score.vercel.app"}}, supports_credentials=True)

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client["risklogDB"]
users = db["users"]
submissions = db["submissions"]

# Flask-Mail setup
app.config.update(
    MAIL_SERVER=os.getenv("EMAIL_HOST"),
    MAIL_PORT=int(os.getenv("EMAIL_PORT", 587)),
    MAIL_USERNAME=os.getenv("EMAIL_USER"),
    MAIL_PASSWORD=os.getenv("EMAIL_PASS"),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False
)
mail = Mail(app)


@app.route("/api/debug-env")
def debug_env():
    return {
        "EMAIL_HOST": os.getenv("EMAIL_HOST"),
        "EMAIL_PORT": os.getenv("EMAIL_PORT"),
        "EMAIL_FROM": os.getenv("EMAIL_FROM")
    }


# Token signing
serializer = URLSafeTimedSerializer(os.getenv("JWT_SECRET"))
JWT_SECRET = os.getenv("JWT_SECRET")
EMAIL_FROM = os.getenv("EMAIL_FROM", "no-reply@example.com")

@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        name = data.get("name")

        if users.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 409

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        token = serializer.dumps(email, salt="email-confirm")

        print("📤 Using SMTP Host(in Register):", app.config["MAIL_SERVER"])

        users.insert_one({
            "email": email,
            "password": hashed,
            "name": name,
            "verified": False,
            "created_at": datetime.utcnow()
        })

        print("📤 SMTP Username(in Register):", app.config["MAIL_USERNAME"])

        link = f"{request.host_url}api/verify/{token}"
        msg = Message("Confirm Your Email", sender=EMAIL_FROM, recipients=[email])
        msg.body = f"Welcome to RiskPeek! Please verify your email: {link}"
        try:
            print("✅ Attempting to send email...")
            mail.send(msg)
            print(f"✅ Email sent to {email}")
        except Exception as mail_error:
            print(f"❌ Failed to send email: {mail_error}")

        return jsonify({"message": "User registered. Check email to verify."}), 201
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route("/api/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)
        result = users.update_one({"email": email}, {"$set": {"verified": True}})
        if result.modified_count:
            return redirect("https://micro-risk-score.vercel.app?verified=true")
        return "Already verified", 200
    except Exception as e:
        return f"Invalid or expired token: {str(e)}", 400

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not user.get("verified"):
            return jsonify({"error": "Email not verified"}), 403

        if not bcrypt.checkpw(password.encode(), user["password"]):
            return jsonify({"error": "Invalid credentials"}), 401

        payload = {
            "email": email,
            "exp": datetime.utcnow() + timedelta(hours=12)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token, "verified": True}), 200
    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

def advanced_risk_score(data):
    score = 0
    factors = []
    confidence = 0

    # Define scoring weights
    weights = {
        'payment_history': 30,
        'reputation_score': 20,
        'linkedin': 10,
        'github': 10,
        'country_risk': 20,
        'address_provided': 5,
        'id_provided': 5
    }

    # Payment history factor
    if data.get('payment_history'):
        score += weights['payment_history']
        factors.append("Payment History")

    # Reputation score (0-10 scale)
    try:
        rep_score = float(data.get('reputation_score', 0))
        score += (rep_score / 10.0) * weights['reputation_score']
        if rep_score > 0:
            factors.append("Reputation Score")
    except ValueError:
        pass

    # LinkedIn presence
    if data.get('linkedin'):
        score += weights['linkedin']
        factors.append("LinkedIn")

    # GitHub presence
    if data.get('github'):
        score += weights['github']
        factors.append("GitHub")

    # Country risk adjustment
    high_risk_countries = ['Nigeria', 'Iran', 'North Korea', 'Pakistan', 'Albania', 'Bangladesh']
    low_risk_countries = ['USA', 'UK', 'Germany', 'Canada', 'Singapore', 'Australia', 'Germany']
    country = data.get('country', '').strip()

    if country in high_risk_countries:
        score += 0
        factors.append("High Risk Country")
    elif country in low_risk_countries:
        score += weights['country_risk']
        factors.append("Low Risk Country")
    else:
        score += weights['country_risk'] / 2
        factors.append("Medium Risk Country")

    # Address check
    if data.get('postcode'):
        score += weights['address_provided']
        factors.append("Address")

    # ID check
    if data.get('id_type'):
        score += weights['id_provided']
        factors.append("ID Provided")

    # Confidence score proportional to score, max 100
    confidence = min(100, 50 + int(score / 2))

    return int(score), int(confidence), factors

@app.route("/api/global-risk-score", methods=["POST"])
def global_risk_score():
    try:
        data = request.get_json()
        score, confidence, factors = advanced_risk_score(data)
        result = {
            "score": score,
            "confidence": confidence,
            "factors": factors # ["Payment History", "Reputation Score"] - Dynamically generated if needed
        }
        
        is_freemium = data.get("submitted_via_form", "false") == "false"

        if not is_freemium:
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
                "factors": result["factors"],
                "device_type": data.get("device_type", "Unknown"),
                "submitted_via_form": "true"
            }
            submissions.insert_one(log_data)
        else:
            print("🆓 Freemium user - result not saved to DB.")

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Risk score calculation failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)