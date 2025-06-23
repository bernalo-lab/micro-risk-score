# Micro Risk Score API

This repo contains both the frontend and backend for a lightweight AI-powered risk scoring service.

## 🔧 Backend (Flask on Render)
- Files: `app.py`, `requirements.txt`
- Deploy via: https://render.com
- Make sure Render uses `python app.py` as the start command and port `5000`.

## 🌐 Frontend (Vercel)
- File: `index.html`
- Fetch API: `https://risk-api.onrender.com/api/risk-score`
- Just upload to Vercel as a static site or connect to GitHub for CI/CD.

## 🔁 API Endpoint
`POST https://risk-api.onrender.com/api/risk-score`
Returns JSON with:
- `score`: float
- `confidence`: float
- `factors`: list of strings

Enjoy!
