<p align="center">
  <img src="static/logo.jpg" alt="CyberGuard Hub - Check before you click" width="650"/>
</p>

# CyberGuard Hub

**A unified digital-safety workspace for the Navratri Codeathon cybersecurity track.** CyberGuard brings scam-message analysis, phishing URL indicators, media inspection, code auditing, and correlated message triage into one dashboard. Every module returns observable signals, plain-language guidance, and clear limitations.

## The product

- **Smart triage:** paste an SMS, email, or chat. The app checks its wording and every embedded link together, then explains the correlated signals in one report.
- **Scam message analyzer (Module 2):** transparent phrase rules for urgency, credential/OTP requests, payment lures, links, and impersonation cues. Includes selected English, Hindi (Devanagari), and Gujarati patterns; it is not broad multilingual understanding.
- **URL scanner (Module 1):** checks URL text for punycode, raw IPs, shorteners, long/deep domains, user-info syntax, brand-like subdomains, and simple one-edit/brand-like domain lookalikes. Each indicator explains why it matters and suggests a safer action. It never opens the destination or calls a reputation service. Results separately report URL format and public DNS lookup; resolution does not indicate safety.
- **Code auditor (Module 4):** checks selected patterns for SQL/shell injection, hard-coded credentials, unsafe deserialization, dynamic code execution, XSS sinks, disabled TLS verification, and Solidity anti-patterns. Findings include rule IDs, line numbers, evidence, impact, and fixes. It is not a full parser.
- **Media verification (Module 3):** inspects supported image signatures, MIME/extension mismatches, dimensions, metadata presence, and a SHA-256 file fingerprint. Damaged or unsupported image bytes return an explicit finding instead of a server parsing error. Audio uploads are hashed and sized but not parsed. Video uploads are hashed and sized; with consent, supported video files can also receive a short Gemini content description, not an authenticity check. With explicit opt-in, supported images and MP4/WebM/QuickTime videos can be sent to Gemini for a short description. It is not a forensic deepfake detector and never returns an authenticity verdict.
- **Explainable cybersecurity:** findings include evidence, why a signal matters, and a next step. Scores are indicator scores—not probabilities. Optional Groq/Gemini text explanations follow `AI_PROVIDER_ORDER` and receive sanitized finding labels, not the submitted message, source code, or full URL. Gemini media observations have a separate opt-in and send the selected supported image/video to Google. If providers are unavailable, local analysis still works.
- **Scam Pause family help card:** after message or smart-triage analysis, the browser creates an English, Hindi, or Gujarati action card from matched signal categories. It explains the likely request and safer next steps. Copy/download includes only broad signal labels and guidance; it excludes the original text, links, phone numbers, and account details. It is a user-controlled local export, not automatic message forwarding.
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

Set `GROQ_API_KEY` and/or `GEMINI_API_KEY` as server-side environment secrets. The server tries providers in `AI_PROVIDER_ORDER` (default `groq,gemini`). Set `AI_PROVIDER_ORDER=gemini,groq` to prefer Gemini. If neither provider is configured or both fail, local rules remain available. Do not put keys in frontend files or commit `.env`. Local analyzers work without either key. The default Groq model is `openai/gpt-oss-120b`; the previous `llama-3.3-70b-versatile` model was deprecated by Groq on August 16, 2026. If you have set `GROQ_MODEL` manually in Vercel, update it too.

## Deploy on Vercel

This repository includes the FastAPI entrypoint Vercel detects at `app/index.py`; the dashboard and API are served from the same app and origin.

1. Import `manthankro/CyberGuard-Hub` into Vercel and keep the project root at the repository root.
2. In **Project Settings → Environment Variables**, add `GROQ_API_KEY` with your Groq key. Add it to Production and Preview if both should use AI explanations. Keep the key out of GitHub and browser code.
3. If `GROQ_MODEL` already exists in Vercel, set it to `openai/gpt-oss-120b` or remove it to use the app default. The UI shows whether a key is configured, and a report shows whether Groq actually returned an explanation.
4. Deploy or redeploy, then open `/health`. It should return `status: ok`, `providers.groq: true`, and `max_upload_mb: 4`. If the key was added after an earlier deployment, redeploy so the new environment value is applied.

Vercel Functions limit request bodies to 4.5 MB, so media uploads are capped at 4 MB on Vercel (including multipart overhead). Other hosts use `MAX_UPLOAD_MB`. Optional Gemini media observations support common images and MP4/WebM/QuickTime videos under the upload limit, require `GEMINI_API_KEY`, and require explicit user opt-in. They describe media; they do not determine whether it is authentic or a deepfake.

## Deploy on Render

The GitHub repository is [manthankro/CyberGuard-Hub](https://github.com/manthankro/CyberGuard-Hub).

1. In Render, select **New + → Blueprint** and connect the repository.
2. Render reads `render.yaml` and builds the included Dockerfile.
3. Add `GROQ_API_KEY` and/or `GEMINI_API_KEY` in the service's secret environment variables if you want optional AI explanations. Gemini is also required for explicitly opted-in image/video observations. The blueprint prompts for both as optional secrets.
4. Deploy and verify `/health`, then open the service URL.

The container binds to Render's `PORT`; `/health` is configured as the service health check. Any Docker-capable host can use the same image. The free Render service can sleep while idle.

## API

- `POST /api/analyze/triage` — `{"content":"message with a link"}`
- `POST /api/analyze/text` — `{"text":"..."}`
- `POST /api/analyze/url` — `{"url":"https://..."}`
- `POST /api/analyze/code` — `{"code":"..."}`
- `POST /api/analyze/media` — multipart fields `file` and optional `ai_visual_review=false`; set the latter to `true` only when you consent to send a supported image or video to Gemini. The optional review supports images and MP4/WebM/QuickTime video and is not a deepfake verdict.
- `GET /api/modules`
- `GET /api/rules` — transparent heuristic catalog with rule IDs, descriptions, and mitigations
- `GET /health`

## Tests

```bash
pip install -r requirements.txt
pytest -q
node --check static/app.js
node --test tests/test_safety_card.cjs
```

## Safety, privacy, and disclosure

CyberGuard does not save submitted content. Browser history stores short report summaries and finding labels locally and can be cleared in the History view. For optional text explanations, the server sends sanitized finding labels to the configured provider. Gemini media observations have a separate opt-in because they send the selected image or supported video to Gemini. Do not submit secrets or sensitive personal information. Vercel uploads are capped at 4 MB; other hosts use `MAX_UPLOAD_MB`.

This is a new standalone implementation. Pramanix AI was used only as a product-structure reference; this repository does not copy from or modify it. Before presenting, check the organizers' rules on AI-assisted code, pre-existing work, and outside libraries, and accurately describe your team's contributions.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 **Manthan Lonkar**.

