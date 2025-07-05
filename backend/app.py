from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
#from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import jwt
import bcrypt
import requests
from flasgger import Swagger

load_dotenv()
print("🔍 Loaded Environment Variables:")
print("EMAIL_HOST:", os.getenv("EMAIL_HOST"))
print("EMAIL_PORT:", os.getenv("EMAIL_PORT"))
print("EMAIL_USER:", os.getenv("EMAIL_USER"))
print("EMAIL_FROM:", os.getenv("EMAIL_FROM"))
print("MONGO_URI (partial):", os.getenv("MONGO_URI", "")[:30] + "...")

JWT_SECRET = os.getenv("JWT_SECRET")
EMAIL_FROM = os.getenv("EMAIL_FROM", "no-reply@example.com")

# Store your keys securely (env vars or config)
print("RECAPTCHA_SECRET_KEY:", os.getenv("YOUR_RECAPTCHA_SECRET_KEY"))
print("RECAPTCHA_SITE_KEY:", os.getenv("YOUR_RECAPTCHA_SITE_KEY"))

app = Flask(__name__)
CORS(app,
     supports_credentials=True,
     resources={r"/*": {"origins": [
         "https://www.riskpeek.tech",
         "https://riskpeek.tech"
     ]}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

swagger = Swagger(app)

app.secret_key = os.getenv("YOUR_RECAPTCHA_SECRET_KEY")  # Needed for flash messages

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client["risklogDB"]
users = db["users"]
submissions = db["submissions"]
accessOthers = db["accessOthers"]

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

#jwt = JWTManager(app)

from functools import wraps
from flask import request, Response

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        expected_password = os.getenv("ADMIN_PASSWORD")
        if not auth or auth.username != "admin" or auth.password != expected_password:
            return Response(
                "Access Denied: Invalid credentials\n",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated


@app.route("/api/debug-env")
def debug_env():
    return {
        "EMAIL_HOST": os.getenv("EMAIL_HOST"),
        "EMAIL_PORT": os.getenv("EMAIL_PORT"),
        "EMAIL_FROM": os.getenv("EMAIL_FROM")
    }

@app.route("/api/submissions", methods=["GET"])
def get_submissions():
    try:
        all_data = list(submissions.find({}, {"_id": 0}))  # exclude MongoDB _id
        return jsonify(all_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Token signing
serializer = URLSafeTimedSerializer(os.getenv("JWT_SECRET"))

@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        name = data.get("name")
        recaptcha_token = data.get("recaptchaToken")
        role = data.get("role")

        # Check reCAPTCHA token
        if not recaptcha_token:
            return jsonify({"error": "reCAPTCHA token is missing."}), 400

        recaptcha_secret = os.getenv("RECAPTCHA_SECRET_KEY")
        verify_response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": recaptcha_secret,
                "response": recaptcha_token
            }
        )
        verify_result = verify_response.json()

        if not verify_result.get("success"):
            return jsonify({"error": "Failed reCAPTCHA verification."}), 400

        # Continue with registration
        if users.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 409

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        token = serializer.dumps(email, salt="email-confirm")
 
        users.insert_one({
            "email": email,
            "password": hashed,
            "name": name,
            "verified": False,
            "created_at": datetime.utcnow(),
            "consent": False,
            "apiAccess": False,
            "role": role,
            "token_generations_today": 0,
            "last_token_reset_date": datetime.utcnow()

        })

        link = f"{request.host_url}api/verify/{token}"
        msg = Message("Confirm Your Email", sender=EMAIL_FROM, recipients=[email])
        msg.body = f"Welcome to RiskPeek! Please verify your email: {link}"

        try:
            mail.send(msg)
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

@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():

    if request.method == "OPTIONS":
        return '', 200

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

        return jsonify(
          {
            "token": token,
            "verified": True,
            "role": user.get("role")
          }
        ), 200
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
    if data.get('paymentHistory'):
        score += weights['payment_history']
        factors.append("Payment History")

    # Reputation score (0-10 scale)
    try:
        rep_score = float(data.get('reputationScore', 0))
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
    if data.get('idType'):
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
            # validate reCAPTCHA token
            recaptcha_token = data.get("recaptchaToken")

            # Check reCAPTCHA token
            if not recaptcha_token:
              return jsonify({"error": "reCAPTCHA token is missing."}), 400

            recaptcha_secret = os.getenv("RECAPTCHA_SECRET_KEY")
            verify_response = requests.post(
              "https://www.google.com/recaptcha/api/siteverify",
              data={
                "secret": recaptcha_secret,
                "response": recaptcha_token
              }
            )
            verify_result = verify_response.json()
            if not verify_result.get("success"):
              return jsonify({"error": "Failed reCAPTCHA verification."}), 400

            print("🆓 Freemium user - result not saved to DB.")

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Risk score calculation failed: {str(e)}"}), 500

@app.route("/api/assessment-risk-score", methods=["POST"])
def assessment_risk_score():

    try:
        data = request.get_json()

        # Validate data
        if not data.get("submitted_By"):
            return jsonify({"error": "Invalid Submitted By Email"}), 401

        if not data.get("assessedEmail"):
            return jsonify({"error": "Invalid Assessed Email"}), 401

        log_data = {
          "timestamp": datetime.now(timezone.utc),
                "submittedBy": data.get("submitted_By"),
                "assessedEmail": data.get("assessedEmail"),
                "legalName": data.get("legalName"),
                "taxId": data.get("taxId"),
                "businessNumber": data.get("businessNumber"),
                "countryOfIncorporation": data.get("country"),
                "addressProof": data.get("addressProof"),
                "linkedin": data.get("linkedin"),
                "website": data.get("website"),
                "yearsActive": data.get("yearsActive"),
                "numberOfEmployees": data.get("employees"),
                "legalDisputes": data.get("legalDisputes"),
                "paymentHistory": data.get("paymentHistory"),
                "annualRevenue": data.get("annualRevenue"),
                "creditScore": data.get("creditScore"),
                "bankVerification": data.get("bankVerification"),
                "amlStatus": data.get("amlStatus"),
                "sanctionsScreening": data.get("sanctionsScreening"),
                "gdprCompliance": data.get("gdprCompliance"),
                "reputationScore": data.get("reputationScore"),
                "gdprCompliance": data.get("gdprCompliance"),
                "domainAge": data.get("domainAge"),
                "socialMediaPresence": data.get("socialMediaPresence"),
                "score": data.get("score"),
                "confidence": data.get("confidence", "0"),
                "riskCategory": data.get("riskCategory"),
                "device_type": data.get("device_type", "Unknown"),
                "observation": data.get("observation"),
                "notes": data.get("notes"),
                "submitted_via_form": "true"
            }
        accessOthers.insert_one(log_data)

        # ✅ IMPORTANT: Add this success response
        return jsonify({"message": "Assessment record saved successfully."}), 201

    except Exception as e:
        return jsonify({"error": f"Assessment Risk score DB insertion failed: {str(e)}"}), 500

@app.route("/admin-dashboard")
@admin_required
def admin_dashboard():
    return "<h1>Admin Dashboard: Access Granted</h1>"


from flask import send_file
import io
import pandas as pd
from bson.json_util import dumps

@app.route("/api/profile", methods=["GET", "PUT", "OPTIONS"])
def user_profile():

    if request.method == "OPTIONS":
        return '', 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = users.find_one({"email": payload["email"]})
        if request.method == "GET":
            return jsonify({
                "name": user.get("name"),
                "email": user.get("email"),
                "consent": user.get("consent", False)
            }), 200
        elif request.method == "PUT":
            data = request.get_json()
            users.update_one({"email": payload["email"]}, {
                "$set": {
                    "name": data.get("name"), # "email": data.get("email"),
                    "consent": data.get("consent", False)
                }
            })
            return jsonify({"message": "Profile updated"}), 200
    except Exception as e:
        return jsonify({"error": f"Profile access failed: {str(e)}"}), 401

@app.route("/api/score-history", methods=["GET", "OPTIONS"])
def score_history():

    if request.method == "OPTIONS":
        return '', 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        history = list(submissions.find({"email": payload["email"]}, {
            "_id": 0,
            "timestamp": 1,
            "score": 1,
            "confidence": 1,
            "factors": 1
        }).sort("timestamp", -1))
        return jsonify(history), 200
    except Exception as e:
        return jsonify({"error": f"History access failed: {str(e)}"}), 401

@app.route("/download/csv")
def export_csv():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data_type = request.args.get("type", "history")  # default to 'history'

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        if data_type == "assessments":
            records = list(accessOthers.find({"submittedBy": payload["email"]}))
            filename = "riskpeek_assessments.csv"
        else:
            records = list(submissions.find({"email": payload["email"]}))
            filename = "riskpeek_score_history.csv"

        if not records:
            return '', 204

        df = pd.DataFrame(records)
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)

        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        return jsonify({"error": f"CSV export failed: {str(e)}"}), 401

@app.route("/download/pdf")
def export_pdf():
    from fpdf import FPDF
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    data_type = request.args.get("type", "history")  # default to 'history'

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_email = payload["email"]

        if data_type == "assessments":
            records = list(accessOthers.find({"submittedBy": user_email}))
            filename = "riskpeek_assessments.pdf"
            title = "RiskPeek - Assessments I've Made"
        else:
            records = list(submissions.find({"email": user_email}))
            filename = "riskpeek_score_history.pdf"
            title = "RiskPeek - My History"

        if not records:
            return '', 204

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=title, ln=True, align="C")
        pdf.ln(10)

        for item in records:
            timestamp = str(item.get('timestamp', ''))
            score = str(item.get('score', ''))
            confidence = str(item.get('confidence', ''))

            if data_type == "assessments":
                risk_category = item.get('riskCategory', '')
                pdf.multi_cell(
                    0,
                    10,
                    txt=f"{timestamp}\nScore: {score}\nConfidence: {confidence}%\nRisk Category: {risk_category}",
                    border=0,
                    align="L"
                )
            else:
                factors = ", ".join(item.get('factors', []))
                pdf.multi_cell(
                    0,
                    10,
                    txt=f"{timestamp}\nScore: {score}\nConfidence: {confidence}%\nFactors: {factors}",
                    border=0,
                    align="L"
                )

            pdf.ln(5)  # spacing between records

        # ✅ Get PDF content correctly
        pdf_output_bytes = pdf.output(dest='S').encode('latin1')

        return send_file(
            io.BytesIO(pdf_output_bytes),
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )

    except Exception as e:
        return jsonify({"error": f"PDF export failed: {str(e)}"}), 401

@app.route("/api/assessments", methods=["GET", "OPTIONS"])
def user_assessments():

    if request.method == "OPTIONS":
        return '', 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_email = payload["email"]
        results = list(accessOthers.find(
            {"submittedBy": user_email},
            {"_id": 0, "timestamp": 1, "submittedBy": 1, "assessedEmail": 1, "score": 1, "confidence": 1, "riskCategory": 1}
        ).sort("timestamp", -1))
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": f"Assessment fetch failed: {str(e)}"}), 401

@app.route("/api/recaptcha-sitekey")
def recaptcha_sitekey():
    return jsonify({"siteKey": os.getenv("RECAPTCHA_SITE_KEY")})

@app.route('/api/generate-token', methods=['POST'])
def generate_token():
    user = get_authenticated_user()
    data = request.json
    duration = int(data['duration'])

    if duration > 12:
        return jsonify({"error": "Max 12 hours allowed."}), 400

    # Check daily limit
    if user.token_generations_today >= 2:
        return jsonify({"error": "Daily limit reached."}), 400

    exp = datetime.utcnow() + timedelta(hours=duration)
    payload = {
        "userId": str(user.id),
        "role": "developer",
        "apiAccess": True,
        "exp": exp,
        "email": str(user.email)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm="HS256")

    # Update usage counter
    user.token_generations_today += 1
    user.save()

    return jsonify({"token": token})

# Secret key to sign tokens
JWT_ALGORITHM = 'HS256'

@app.route('/api/generate-token-duration', methods=['POST'])
def generate_token_duration():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if not data or 'duration' not in data:
            return jsonify({'error': 'Missing duration'}), 400

        duration_str = data['duration'].lower()
        email = data['email']

        
        durations_map = {
            '6 hours': timedelta(hours=6),
            '12 hours': timedelta(hours=12),
            '18 hours': timedelta(hours=18),
            '24 hours': timedelta(hours=24),
        }

        expiry_delta = durations_map.get(duration_str)
        if not expiry_delta:
            return jsonify({'error': 'Invalid duration'}), 400

        expiration = datetime.utcnow() + expiry_delta

        payload = {
            'sub': 'api_access',
            'exp': expiration,
            'scope': 'developer_api',
            'email': email
        }

        if not JWT_SECRET:
            return jsonify({'error': 'JWT_SECRET is not configured'}), 500

        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        return jsonify({
          'token': token,
          'expiresAt': expiration.isoformat() + 'Z'
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route("/api/toggle-api-access", methods=["POST"])
def toggle_api_access():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = users.find_one({"email": payload["email"]})
        if not user:
            return jsonify({"error": "User not found"}), 404

        current_status = user.get("apiAccess", False)
        new_status = not current_status

        users.update_one({"email": payload["email"]}, {"$set": {"apiAccess": new_status}})

        return jsonify({"apiAccess": new_status}), 200
    except Exception as e:
        return jsonify({"error": f"Toggling failed: {str(e)}"}), 400

## Start API
# Example allowed fields
ALLOWED_FIELDS = {
    "legalName",
    "taxId",
    "creditScore",
    "confidence",
    "riskCategory"
    # Add more fields as needed
}

# Dummy user lookup
def get_user_by_email(email):
    return users.find_one({"email": email})

@app.route("/api/auth-login", methods=["POST"])
def auth_login():
    """
User Login

---
tags:
  - Authentication
consumes:
  - application/json
parameters:
  - in: body
    name: body
    required: true
    schema:
      type: object
      properties:
        email:
          type: string
        password:
          type: string
        duration:
          type: integer
          description: Maximum Duration 12 hours.
          Default: 3 hours
      required:
        - email
        - password
responses:
  "200":
    description: Successful login
    schema:
      type: object
      properties:
        token:
          type: string
        expiresAt:
          type: string
  "400":
    description: Invalid credentials - Missing email or password
  "401":
    description: Invalid credentials
  "402":
    description: Unauthorised API access
    """

    data = request.json
    email = data.get("email")
    password = data.get("password")
    duration = data.get("duration")

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    user = get_user_by_email(email)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    if not user.get("apiAccess"):
        return jsonify({"error": "Unauthorised API access"}), 402

    # Set default duration if not provided
    if not duration:
        duration = 3
    else:
        try:
            duration = int(duration)
        except ValueError:
            return jsonify({"error": "Invalid duration format"}), 400

    # Cap maximum duration to 12 hours
    if duration > 12:
        duration = 12

    expiration = datetime.utcnow() + timedelta(hours=duration)

    payload = {
        'sub': 'api_access',
        'exp': expiration,
        'scope': 'developer_api',
        'email': email
    }

    if not JWT_SECRET:
        return jsonify({'error': 'JWT_SECRET is not configured'}), 500

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return jsonify({
        'token': token,
        'expiresAt': expiration.isoformat() + 'Z'
    }), 200

@app.route("/api/transaction-analysis", methods=["GET"])
def transaction_analysis():

# Start YAML Endpoint Logic
    """
Retrieve Consented Records

---
tags:
  - Data Access
parameters:
  - in: header
    name: Authorization
    required: true
    type: string
    description: |
      Bearer token obtained from login.
      Example: Bearer yourtoken
  - in: query
    name: fields
    required: true
    type: string
    description: |
      Comma-separated list of fields to retrieve (max 5).
      Example: legalName,confidence,creditScore
  - in: query
    name: limit
    type: integer
    description: |
      Max number of records to return.
      Default: 20
  - in: query
    name: confidenceMin
    type: number
    description: |
      Minimum confidence value to filter records.
      Example: 50
  - in: query
    name: confidenceMax
    type: number
    description: |
      Maximum confidence value to filter records
  - in: query
    name: creditScoreMin
    type: integer
    description: |
      Minimum credit score to filter records.
      Example: 500
  - in: query
    name: creditScoreMax
    type: integer
    description: |
      Maximum credit score to filter records
responses:
  "200":
    description: |
      Records retrieved successfully
    schema:
      type: object
      properties:
        data:
          type: array
          items:
            type: object
  "400":
    description: |
      Bad request (e.g., invalid fields or parameters)
  "401":
    description: |
      Unauthorized or invalid token
  "403":
    description: |
      User does not have API access
    """
# End YAML Endpoint Logic

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401

    token = auth_header.split(" ")[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = decoded.get("email")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Get Developer details
    user = get_user_by_email(email)

    # Validate Developer email
    if not user:
        return jsonify(
          {
            "error": "Unauthorized User",
            "email": email
          }
        ), 403

    # Does Developer has the right to access the APIs?
    if not user["apiAccess"]:
        return jsonify({"error": "Unauthorized API Access"}), 403

    # Start process to retrieve data
    fields_param = request.args.get("fields")
    if not fields_param:
        return jsonify({"error": "You must specify fields"}), 400

    fields = [f.strip() for f in fields_param.split(",")]
    if len(fields) > 5:
        return jsonify({"error": "You can select up to 5 fields only."}), 400

    if not all(f in ALLOWED_FIELDS for f in fields):
        return jsonify({"error": "Invalid fields requested"}), 400

    limit_param = request.args.get("limit", "20")
    try:
        limit = min(int(limit_param), 100)
    except ValueError:
        return jsonify({"error": "Invalid limit"}), 400

    # Dummy records for demonstration
    records = [
        {f: f"Example-{i}" for f in fields} for i in range(1, limit + 1)
    ]

    # Real data
    # Need to return data where 'Consent' has been given by person who submitted data
    # Query to run - SELECT * FROM accessOthers WHERE submittedBy IN (SELECT submittedBy from submissions WHERE consent = true)
    # 1) Find all consented emails
    consented_emails = users.distinct("email", {"consent": True})

    # 2) Base query for consented records
    query = {
      "submittedBy": {"$in": consented_emails}
    }

    # 3) Add optional filters
    confidence_min = request.args.get("confidenceMin")
    confidence_max = request.args.get("confidenceMax")
    credit_score_min = request.args.get("creditScoreMin")
    credit_score_max = request.args.get("creditScoreMax")

    # Confidence
    if confidence_min or confidence_max:
        query["confidence"] = {}
    if confidence_min:
        query["confidence"]["$gte"] = float(confidence_min)
    if confidence_max:
        query["confidence"]["$lte"] = float(confidence_max)

    # Credit Score Query
    if credit_score_min or credit_score_max:
        query["creditScore"] = {}
    if credit_score_min:
        query["creditScore"]["$gte"] = int(credit_score_min)
    if credit_score_max:
        query["creditScore"]["$lte"] = int(credit_score_max)

    # 4) Build projection dict to include only requested fields
    projection = {f: 1 for f in fields}
    projection["_id"] = 0  # Exclude Mongo _id

    # 5) Execute query with projection and limit
    records = list(
      accessOthers.find(query, projection).sort("timestamp", -1).limit(limit)
    )

    # 6) Years Active
    years_active_min = request.args.get("yearsActiveMin")
    if years_active_min:
        query["yearsActive"] = {"$gte": int(years_active_min)}

    return jsonify({"data": records})

## End API

# (any other routes)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
