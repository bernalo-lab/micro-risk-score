# 🌍 RiskPeek Global – AI-Powered Risk Scoring Platform

**RiskPeek** is an AI-powered micro risk scoring engine designed for global freelancers, micro-businesses, and independent professionals. It helps assess financial and professional trustworthiness in real-time using an open, tiered model.

🔗 [Live Frontend (Vercel)](https://micro-risk-score.vercel.app)  
🔗 [Live Backend API (Render)](https://micro-risk-score.onrender.com/api/global-risk-score)

---

## 🚀 Features

- 🌐 **Global-Ready**: Supports inputs across all geographies
- 🧠 **AI-Informed Logic**: Uses signals from identity, financial, and reputation inputs
- 🔒 **Privacy-Conscious**: Client-side only form + CORS-enabled secure backend
- 🧩 **Modular Scoring Engine**: Easily extendable tiers (basic info, ID, history, digital footprint)

---

## 📊 Scoring Tiers

| Tier | Data Evaluated                             | Impact on Score         |
|------|--------------------------------------------|--------------------------|
| 1️⃣  | Name, Email, Postcode, Country             | Basic trustworthiness   |
| 2️⃣  | ID Type, LinkedIn, GitHub profiles         | Work verification       |
| 3️⃣  | Payment history, Digital reputation        | Financial credibility   |

---

## 🧪 Try It Locally

### Backend (Flask API)

```bash
cd backend
pip install -r ../requirements.txt
python app.py
```

Endpoint: `POST /api/global-risk-score`

### Frontend

Open in browser:

```bash
cd frontend
open index.html
```

> Edit endpoint in `index.html` if using local backend:  
> Replace `https://micro-risk-score.onrender.com` with `http://127.0.0.1:5000`

---

## 📦 Tech Stack

- **Frontend**: HTML5 + TailwindCSS
- **Backend**: Python Flask
- **Deployment**: Vercel (frontend), Render (API)

---

## 🔧 Project Structure

```
riskpeek-global/
│
├── backend/
│   ├── app.py          # Flask API
│   └── scoring.py      # Modular scoring logic
│
├── frontend/
│   └── index.html      # Global scoring form
│
├── requirements.txt
└── README.md
```

---

## 🤝 Contribute / Collaborate

We welcome PRs, improvements, and ideas. Ideal ways to contribute:
- Add scoring rules for new geographies
- Connect external data (gov APIs, credit bureaus)
- Build mobile-friendly or React UI
- Translate for global audiences

---

## 📧 Contact

📨 hello@riskpeek.com  
🧑‍💼 Project by [Bernalo Labs](https://bernalo.com)  

---

## 📄 License

MIT – Free to use, improve, fork, and deploy commercially.
