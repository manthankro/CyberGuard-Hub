"""Optional third-party reputation and media provenance integrations.

All external services are opt-in. Provider scores are signals, not proof.
"""
import io
import re
from urllib.parse import quote

import httpx

SIGHTENGINE_URL = "https://api.sightengine.com/1.0/video/check-sync.json"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"


def inspect_c2pa(data: bytes, mime: str) -> dict:
    """Read signed C2PA provenance when the optional SDK can parse the file."""
    try:
        from c2pa import Reader
        reader = Reader(mime, io.BytesIO(data))
        manifest = reader.json()
        active = manifest.get("active_manifest")
        manifests = manifest.get("manifests") or {}
        active_data = manifests.get(active, {}) if active else {}
        return {
            "status": "manifest_found",
            "active_manifest": active,
            "claim_generator": active_data.get("claim_generator"),
            "title": active_data.get("title"),
            "validation_status": manifest.get("validation_status", []),
            "note": "Signed content credentials describe provenance claims and validation; they do not prove that depicted events are true.",
        }
    except ImportError:
        return {"status": "unavailable", "note": "C2PA reader is not installed on this host."}
    except Exception:
        return {"status": "no_valid_manifest", "note": "No readable C2PA content credentials were found. Their absence does not prove a file is fake or authentic."}


def scan_video_authenticity(data: bytes, filename: str, mime: str, api_user: str, api_secret: str) -> dict:
    if not api_user or not api_secret:
        raise ValueError("Video authenticity scanning is not configured. Set SIGHTENGINE_API_USER and SIGHTENGINE_API_SECRET on the server.")
    try:
        response = httpx.post(
            SIGHTENGINE_URL,
            data={"api_user": api_user, "api_secret": api_secret, "models": "genai,deepfake"},
            files={"video": (filename, data, mime)},
            timeout=45.0,
        )
    except httpx.TimeoutException as exc:
        raise RuntimeError("The video provider timed out. Try a shorter clip or retry later.") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError("The video provider could not be reached. Try again later.") from exc
    if response.status_code >= 400:
        raise RuntimeError(f"The video provider returned HTTP {response.status_code}. Check provider limits and credentials.")
    payload = response.json()
    if payload.get("status") != "success":
        raise RuntimeError(payload.get("error", {}).get("message", "The video provider could not analyze this clip."))
    frames = (payload.get("data") or {}).get("frames") or []
    summaries = []
    for frame in frames[:30]:
        deepfake = frame.get("deepfake") or {}
        genai = frame.get("genai") or {}
        summaries.append({
            "time": frame.get("time"),
            "deepfake_probability": deepfake.get("score"),
            "ai_generated_probability": genai.get("score"),
            "generator_hypotheses": genai.get("matches", []),
        })
    return {
        "provider": "Sightengine",
        "status": "analyzed",
        "frames_analyzed": len(frames),
        "frames": summaries,
        "note": "Probabilistic model signals from sampled frames; not forensic proof. No original URL or creator identity is inferred by this scan.",
    }


def check_email_breaches(email: str, api_key: str) -> dict:
    value = email.strip()
    if not re.fullmatch(r"[^\s@]{1,64}@[^\s@.]+(?:\.[^\s@.]+)+", value):
        raise ValueError("Enter a valid email address.")
    if not api_key:
        raise RuntimeError("Email exposure lookup is not configured. Set HIBP_API_KEY on the server.")
    try:
        response = httpx.get(
            HIBP_URL.format(email=quote(value, safe="")),
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": api_key, "user-agent": "CyberGuard-Hub"},
            timeout=12.0,
        )
    except httpx.TimeoutException as exc:
        raise RuntimeError("The breach-data provider timed out. Try again later.") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError("The breach-data provider could not be reached. Try again later.") from exc
    if response.status_code == 404:
        return {"found": False, "breaches": [], "source": "Have I Been Pwned", "note": "No matching entries were returned from this provider's known breach dataset. This is not a complete dark-web search."}
    if response.status_code == 401:
        raise RuntimeError("The breach-data provider rejected its API key. Check HIBP_API_KEY.")
    if response.status_code == 429:
        raise RuntimeError("The breach-data provider rate-limited this request. Wait and retry.")
    if response.status_code >= 400:
        raise RuntimeError(f"The breach-data provider returned HTTP {response.status_code}.")
    payload = response.json()
    breaches = [{
        "name": item.get("Name"),
        "title": item.get("Title"),
        "domain": item.get("Domain"),
        "breach_date": item.get("BreachDate"),
        "data_classes": item.get("DataClasses", []),
        "is_verified": item.get("IsVerified"),
    } for item in payload if isinstance(item, dict)]
    return {"found": bool(breaches), "breaches": breaches, "source": "Have I Been Pwned", "note": "Matches are from this provider's known breach corpus and may not represent all exposures or current dark-web activity."}
