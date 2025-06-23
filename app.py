from flask import Flask, request, jsonify
from flask_cors import CORS
import random

app = Flask(__name__)
CORS(app)

@app.route('/api/risk-score', methods=['POST'])
def risk_score():
    data = request.get_json()

    score = round(random.uniform(10, 90), 2)
    confidence = round(random.uniform(75, 99), 1)
    factors = []

    if 'driver' in data['occupation'].lower():
        factors.append("High road exposure")
    if 'postcode' in data and data['postcode'].startswith('L'):
        factors.append("Higher regional risk")
    if data['company']:
        factors.append("Digital footprint detected")
    if not factors:
        factors = ["Standard occupational risk"]

    return jsonify({
        'score': score,
        'confidence': confidence,
        'factors': factors
    })

if __name__ == '__main__':
    app.run(debug=True)
