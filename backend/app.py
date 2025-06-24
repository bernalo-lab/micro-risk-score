
from flask import Flask, request, jsonify
from flask_cors import CORS
from scoring import calculate_risk_score

CORS(app, resources={r"/api/*": {"origins": "https://micro-risk-score.vercel.app"}}, supports_credentials=True)

@app.route('/api/global-risk-score', methods=['POST'])
def global_risk_score():
    try:
        data = request.get_json()
        result = calculate_risk_score(data)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
