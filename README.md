# CyberGuard Hub

**A unified digital-safety workspace for the Navratri Codeathon cybersecurity track.** CyberGuard brings scam-message analysis, phishing URL indicators, media inspection, code auditing, and correlated message triage into one dashboard. Every module returns observable signals, plain-language guidance, and clear limitations.

## The product

- **Smart triage:** paste an SMS, email, or chat. The app checks its wording and every embedded link together, then explains the correlated signals in one report.
- **Scam message analyzer:** deterministic checks for urgency, credential/OTP requests, payment lures, links, and impersonation cues. Includes selected English, Hindi, and Gujarati patterns; this is not broad multilingual understanding.
- **Link scanner:** checks URL text for punycode, raw IPs, shorteners, long domains, brand-like subdomains, and other patterns. It never visits the destination, calls a reputation service, or declares a link safe.
- **Media inspection:** accepts image, audio, and video uploads. For images, reports format, dimensions, and EXIF presence. It does not detect deepfakes; audio and video are not parsed in this prototype.
- **Code audit:** checks selected patterns for SQL/shell injection, hard-coded credentials, unsafe deserialization, dynamic code execution, XSS sinks, disabled TLS verification, and Solidity anti-patterns. Findings include line numbers and safer next steps. It is not a full parser.
- **AI explanation:** optional Groq-first, Gemini-fallback provider routing. AI receives sanitized finding labels, not the submitted message, source code, full URL, or uploaded file. If neither provider is configured or both are unavailable, local analysis still works.
- **On-device report workspace:** scan history stores only short summaries and finding labels in this browser's local storage. It does not save original submitted content. Reports can be copied, exported as JSON, or printed/saved as PDF.
- **Safety and privacy UI:** consistent module navigation, demo inputs, upload limits, clear risk semantics, and a privacy explainer.

Scores are **indicator scores, not calibrated probabilities**. A low score never means that content is safe. The tool is a hackathon prototype, not a security certification or incident-response service.

## Run locally

Requirements: Python 3.11 or newer.

```bash
git clone https://github.com/manthankro/CyberGuard-Hub.git
cd CyberGuard-Hub
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env             # Optional: add provider keys
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. Interactive API documentation is at `/docs`; service and provider status is at `/health`.

### Optional AI setup

Set `GROQ_API_KEY` and/or `GEMINI_API_KEY` as environment secrets. When both are present, Groq is tried first and Gemini is used if Groq is unavailable. Do not put keys in frontend files or commit `.env`. Local analyzers work without either key. Provider models can be changed through `GROQ_MODEL` and `GEMINI_MODEL`.

## Deploy on Render

The GitHub repository is [manthankro/CyberGuard-Hub](https://github.com/manthankro/CyberGuard-Hub).

1. In Render, select **New + → Blueprint** and connect the repository.
2. Render reads `render.yaml` and builds the included Dockerfile.
3. Add `GROQ_API_KEY` and/or `GEMINI_API_KEY` in the service's secret environment variables if you want AI explanations. The blueprint prompts for both as optional secrets.
4. Deploy and verify `/health`, then open the service URL.

The container binds to Render's `PORT`; `/health` is configured as the service health check. Any Docker-capable host can use the same image. The free Render service can sleep while idle.

## API

- `POST /api/analyze/triage` — `{"content":"message with a link"}`
- `POST /api/analyze/text` — `{"text":"..."}`
- `POST /api/analyze/url` — `{"url":"https://..."}`
- `POST /api/analyze/code` — `{"code":"..."}`
- `POST /api/analyze/media` — multipart form field `file`
- `GET /api/modules`
- `GET /health`

## Tests

```bash
pip install -r requirements.txt
pytest -q
node --check static/app.js
```

## Safety, privacy, and disclosure

CyberGuard does not persist submitted content on the server. Browser history stores a short report locally and can be cleared in the History view. For optional AI explanations, the server sends sanitized finding labels to the configured provider; do not submit secrets or sensitive personal information. Uploads are limited by `MAX_UPLOAD_MB`.

This is a new standalone implementation. Pramanix AI was used only as a product-structure reference; this repository does not copy from or modify it. Before presenting, check the organizers' rules on AI-assisted code, pre-existing work, and outside libraries, and accurately describe your team's contributions.
