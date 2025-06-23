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
=======
# micro-risk-score
🔍 Lightweight AI-powered micro risk scoring API for gig workers and SMEs. Built with Flask and TailwindCSS. Instant insights via a simple POST request.

# 🔍 Micro Risk Score API

AI-powered risk scoring API for freelancers, gig workers, and small businesses.  
Built with Flask (backend) and TailwindCSS (frontend).

## 🚀 Live Demo
👉 [Visit Site](https://your-vercel-app.vercel.app)  
👉 API Base: `https://your-render-app.onrender.com/api/risk-score`

## 📦 Features
- Real-time risk scoring based on job, location, and digital footprint
- JSON API ready to plug into apps and dashboards
- Fully open-source and easy to customise

## 📂 Tech Stack
- Flask + Python
- TailwindCSS + HTML + Vanilla JS
- Hosted on Render + Vercel

## 📄 License
MIT — feel free to use, fork, or adapt.

