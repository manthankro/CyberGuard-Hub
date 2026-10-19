# CyberGuard Hub

A standalone, deployable digital-safety dashboard for the Navratri Codeathon 2026 cybersecurity track. It brings four focused tools into one interface: suspicious-message signals, URL text heuristics, cautious media metadata inspection, and lightweight code-pattern auditing.

## What works

- **Scam message analyzer:** deterministic checks for urgency, credential/OTP requests, payment lures, links, and impersonation cues. Signals are language-pattern based and include a few Hindi/Gujarati terms; this is not broad multilingual understanding.
- **Link scanner:** inspects the URL string for patterns such as punycode, raw IPs, shorteners, long domains, and brand-like subdomains. It deliberately does not fetch URLs, query registration/reputation services, or certify safety. This avoids turning the scanner into an SSRF proxy.
- **Media check:** accepts image/audio/video uploads; for images it reports basic format, dimensions, and EXIF presence. It does not identify deepfakes or authentic media. Audio/video are not parsed in this prototype.
- **Code audit:** checks a small set of patterns for SQL/shell injection, hard-coded credentials, unsafe deserialization, and selected Solidity anti-patterns. It is not a full parser or replacement for language-specific scanners.
- **Optional Gemini explanation:** if configured, Gemini explains deterministic findings. The app still works without a key, and falls back to local analysis if the provider is unavailable. AI explanations are advisory and can be wrong.

Scores are **indicator scores, not calibrated probabilities**. A low score never means that content is safe.

## Run locally

Requirements: Python 3.11 or newer.

```bash
cd cyberguard-hub
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env             # Optional: add GEMINI_API_KEY
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. API documentation is at `/docs`; liveness/configuration is at `/health`.

Without Gemini, every local analyzer remains usable. To enable optional explanations, create a Gemini API key in the provider console and set it only as the `GEMINI_API_KEY` environment variable or in an untracked local `.env` file. Never commit credentials or put them in frontend code.

## Deploy on Render (Docker)

1. Push this folder as a new GitHub repository.
2. In Render, choose **New + → Blueprint**, connect the new repository, and let it read `render.yaml`.
3. Set `GEMINI_API_KEY` in the service's secret environment variables if you want AI explanations. Leave it unset for local-rule-only mode.
4. Deploy, then check `/health` and open the service root.

The included Dockerfile binds to Render's `PORT`, and the blueprint uses `/health` as its health check. Any Docker-capable host can use the same image. The free Render instance may sleep when idle; the first request after inactivity can take longer.

## Tests

```bash
pip install -r requirements.txt
pytest -q
```

## API

- `POST /api/analyze/text` — `{"text":"..."}`
- `POST /api/analyze/url` — `{"url":"https://..."}`
- `POST /api/analyze/code` — `{"code":"..."}`
- `POST /api/analyze/media` — multipart form field `file`
- `GET /health`

## Safety and privacy notes

The service does not persist submitted data. Gemini receives the analyzer's findings/context when configured; avoid sending secrets or sensitive personal data. Upload size is limited by `MAX_UPLOAD_MB`. This is a hackathon prototype, not professional incident response or a security certification. A malicious or compromised URL should not be opened from the report; independently verify via known-good channels.

## Hackathon disclosure

This repository is a new, standalone implementation and does not copy from or modify Pramanix AI. It uses optional third-party Gemini services and open-source dependencies listed in `requirements.txt`. Before presenting, check the organizers' rules on AI-assisted code, pre-existing work, outside libraries, and disclosure; describe your team's actual contributions accurately.

## Push this project to a new GitHub repository

Create an empty repository on GitHub (do not initialize it with a README), then from this folder run:

```bash
git init
git add .
git commit -m "Build CyberGuard Hub prototype"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/cyberguard-hub.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Confirm `.env` is not staged before pushing. This workspace has not created or published a GitHub repository.
