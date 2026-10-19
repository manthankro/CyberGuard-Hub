import os
import asyncio
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from app.config import settings
from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url, check_domain_status
from app.analyzers.code import analyze_code
from app.analyzers.media import inspect_media
from app.analyzers.triage import analyze_triage
from app.analyzers.external import inspect_c2pa, scan_video_authenticity, check_email_breaches
from app.analyzers.upi import analyze_upi
from app.analyzers.phone import analyze_phone
from app.llm import explain_findings, provider_status, review_media_observations

app=FastAPI(title=settings.app_name,version="1.3.0",description="Evidence-led digital safety workspace")
STATIC=Path(__file__).resolve().parent.parent/"static"
app.mount("/static",StaticFiles(directory=STATIC),name="static")

class TextRequest(BaseModel): text: str=Field(min_length=3,max_length=12000)
class URLRequest(BaseModel): url: str=Field(min_length=3,max_length=2048)
class CodeRequest(BaseModel): code: str=Field(min_length=3,max_length=30000)
class TriageRequest(BaseModel): content: str=Field(min_length=3,max_length=12000)
class UPIRequest(BaseModel): text: str=Field(min_length=3,max_length=4000)
class PhoneRequest(BaseModel): text: str=Field(min_length=3,max_length=4000)
class EmailExposureRequest(BaseModel):
    email: str=Field(min_length=6,max_length=254)
    consent: bool

@app.middleware("http")
async def security_headers(request, call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    return response

@app.get("/",include_in_schema=False)
def home(): return FileResponse(STATIC/"index.html")
def upload_limit_mb() -> int:
    configured = max(1, settings.max_upload_mb)
    # Vercel functions cap the full request body at 4.5 MB, including multipart overhead.
    return min(configured, 4) if os.getenv("VERCEL") else configured

@app.get("/health")
def health():
    return {"status":"ok","providers":provider_status(),"version":app.version,"max_upload_mb":upload_limit_mb(),"groq_model":settings.groq_model,"gemini_model":settings.gemini_model,"ai_provider_order":provider_status()["order"],"video_authenticity_configured":bool(settings.sightengine_api_user and settings.sightengine_api_secret),"email_exposure_configured":bool(settings.hibp_api_key)}
from app.analyzers.text import PATTERNS as TEXT_PATTERNS
from app.analyzers.code import RULES as CODE_RULES

@app.get("/api/rules")
def get_rules():
    rules = []
    for r_id, label, _, sev, why, rec in TEXT_PATTERNS:
        rules.append({"module": "text", "rule_id": r_id, "category": label, "severity": sev, "why_it_matters": why, "recommendation": rec})
    for r_id, title, _, sev, fix, why, sample in CODE_RULES:
        rules.append({"module": "code", "rule_id": r_id, "category": title, "severity": sev, "why_it_matters": why, "recommendation": fix, "sample_fix": sample})
    url_rules = [
        {"module": "url", "rule_id": "URL-IP", "category": "Raw IP address", "severity": "high", "why_it_matters": "A numeric destination can obscure the organisation behind a link.", "recommendation": "Do not sign in; verify destination officially."},
        {"module": "url", "rule_id": "URL-USERINFO", "category": "User-info syntax (@ symbol)", "severity": "high", "why_it_matters": "Text before @ can disguise the actual destination.", "recommendation": "Inspect actual host after @ symbol."},
        {"module": "url", "rule_id": "URL-PUNYCODE", "category": "Internationalized / Punycode (xn--)", "severity": "medium", "why_it_matters": "Visually deceptive homograph domain characters.", "recommendation": "Navigate from trusted bookmarks."},
        {"module": "url", "rule_id": "URL-SHORTENER", "category": "URL Shortener", "severity": "medium", "why_it_matters": "Hides true landing destination from preview.", "recommendation": "Expand short URL before opening."},
        {"module": "url", "rule_id": "URL-BRAND-SUBDOMAIN", "category": "Brand name in subdomain", "severity": "high", "why_it_matters": "Misleading subdomains mimicking major institutions.", "recommendation": "Verify registrable root domain."},
        {"module": "url", "rule_id": "URL-TYPOLOOKALIKE", "category": "Typo-squatting lookalike domain", "severity": "high", "why_it_matters": "Subtle character substitutions (e.g. paypa1).", "recommendation": "Inspect spelling of domain name."},
        {"module": "url", "rule_id": "URL-SUSPICIOUS-TLD", "category": "High-risk TLD", "severity": "medium", "why_it_matters": "TLDs disproportionately abused for transient spam.", "recommendation": "Exercise elevated caution with unfamiliar TLDs."},
        {"module": "url", "rule_id": "URL-DECEPTIVE-PATH", "category": "Deceptive authentication path", "severity": "medium", "why_it_matters": "Appendage of 'login'/'kyc' to unrelated hostnames.", "recommendation": "Check if primary domain matches service."},
    ]
    rules.extend(url_rules)
    media_rules = [
        {"module": "media", "rule_id": "MEDIA-MIME-MISMATCH", "category": "Declared MIME vs File Signature Mismatch", "severity": "low", "why_it_matters": "Header claims one type while binary magic bytes indicate another.", "recommendation": "Examine file structure in safe sandbox."},
        {"module": "media", "rule_id": "MEDIA-EXTENSION-MISMATCH", "category": "Extension vs Image Format Mismatch", "severity": "low", "why_it_matters": "Renamed extension can mask true executable or format.", "recommendation": "Verify true file format."},
        {"module": "media", "rule_id": "MEDIA-SOFTWARE-EDITED", "category": "Post-Processing/Editor Metadata Signature", "severity": "medium", "why_it_matters": "EXIF indicates editing or AI synthesis software was applied.", "recommendation": "Cross-reference with original source."},
    ]
    rules.extend(media_rules)
    return {"rules": rules, "total": len(rules)}

@app.get("/api/modules")
def modules():
    return {"modules":[
        {"id":"triage","name":"Message triage","description":"Correlate scam language with links embedded in a message."},
        {"id":"text","name":"Scam message","description":"Find urgency, credential, payment, and impersonation cues."},
        {"id":"url","name":"Link scanner","description":"Inspect URL text for suspicious destination patterns; never fetches the link."},
        {"id":"media","name":"Media verification","description":"Inspect image files and media fingerprints; optional Gemini image/video descriptions are not deepfake detection."},
        {"id":"code","name":"Code audit","description":"Find selected vulnerability patterns with line references and fixes."},{"id":"upi","name":"UPI & payment check","description":"Inspect UPI IDs and payment-request language without initiating a transfer."},{"id":"phone","name":"Phone heuristic check","description":"Offline pattern checks for Indian mobile numbers in messages."},
    ]}
async def with_domain_status(url: str) -> dict:
    try:
        return await asyncio.wait_for(asyncio.to_thread(check_domain_status, url), timeout=1.5)
    except asyncio.TimeoutError:
        return {"format_valid": True, "domain_status": "unknown", "domain_note": "DNS check timed out; URL pattern analysis is still available."}

@app.post("/api/analyze/triage")
async def triage_scan(request:TriageRequest):
    result=analyze_triage(request.content)
    statuses = await asyncio.gather(*(with_domain_status(item["url"]) for item in result["url_analyses"]))
    for item, status in zip(result["url_analyses"], statuses):
        item["url_validity"] = status
    result["ai_explanation"],result["ai_provider"]=explain_findings("message and embedded link triage",result)
    if result["ai_provider"]: result["analysis_mode"]=f"correlated local rules + {result['ai_provider']} explanation"
    return result
@app.post("/api/analyze/text")
def text_scan(request:TextRequest):
    result=analyze_text(request.text)
    result["ai_explanation"],result["ai_provider"]=explain_findings("scam text",result)
    result["analysis_mode"]=f"local rules + {result['ai_provider']} explanation" if result["ai_provider"] else "local rules"
    return result
@app.post("/api/analyze/url")
async def url_scan(request:URLRequest):
    result=analyze_url(request.url)
    result["url_validity"] = await with_domain_status(request.url)
    result["ai_explanation"],result["ai_provider"]=explain_findings("URL indicators",result)
    result["analysis_mode"]=f"URL heuristics + {result['ai_provider']} explanation" if result["ai_provider"] else "local URL heuristics"
    return result
@app.post("/api/analyze/code")
def code_scan(request:CodeRequest):
    result=analyze_code(request.code)
    result["ai_explanation"],result["ai_provider"]=explain_findings("source code findings",result)
    result["analysis_mode"]=f"static rules + {result['ai_provider']} explanation" if result["ai_provider"] else "local static rules"
    return result
@app.post("/api/analyze/media")
async def media_scan(file:UploadFile=File(...), ai_visual_review:bool=Form(False), ai_authenticity_scan:bool=Form(False)):
    limit=upload_limit_mb()*1024*1024
    data=await file.read(limit+1)
    if len(data)>limit: raise HTTPException(status_code=413,detail=f"File exceeds {upload_limit_mb()} MB limit")
    if not data: raise HTTPException(status_code=400,detail="Uploaded file is empty")
    mime=file.content_type or "application/octet-stream"
    if not (mime.startswith("image/") or mime.startswith("video/") or mime.startswith("audio/")):
        raise HTTPException(status_code=415,detail="Upload an image, audio, or video file")
    result=inspect_media(data,file.filename or "upload",mime)
    if mime.startswith("video/"):
        result["provenance"] = inspect_c2pa(data, mime)
    if ai_authenticity_scan:
        if not mime.startswith("video/"):
            raise HTTPException(status_code=422,detail="AI-generated/deepfake model scan supports video files only.")
        try:
            result["authenticity_scan"] = await run_in_threadpool(scan_video_authenticity,data,file.filename or "upload",mime,settings.sightengine_api_user,settings.sightengine_api_secret)
        except ValueError as exc:
            raise HTTPException(status_code=503,detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=502,detail=str(exc))
    if ai_visual_review:
        if not (mime.startswith("image/") or mime.startswith("video/")):
            raise HTTPException(status_code=422,detail="Optional Gemini observations support images and videos.")
        if not settings.gemini_api_key:
            raise HTTPException(status_code=503,detail="Add GEMINI_API_KEY on the server to enable optional media observations. Local file inspection is available without it.")
        if mime.startswith("image/"):
            actual_mime={"JPEG":"image/jpeg","PNG":"image/png","WEBP":"image/webp","GIF":"image/gif","BMP":"image/bmp","TIFF":"image/tiff"}.get(result.get("format"))
            if not actual_mime:
                raise HTTPException(status_code=415,detail="This image format is not supported for optional Gemini observations")
            mime=actual_mime
        elif mime not in {"video/mp4","video/webm","video/quicktime"}:
            raise HTTPException(status_code=415,detail="Optional Gemini observations support MP4, WebM, and QuickTime videos")
        observation,provider=await run_in_threadpool(review_media_observations,data,mime)
        if observation:
            result["visual_review"]={"provider":provider,"observations":observation,"label":"AI-assisted media observations · not a deepfake/authenticity verdict"}
        else:
            result["visual_review"]={"provider":None,"observations":"The optional Gemini review is temporarily unavailable. Local file inspection is still available.","label":"No AI media observations returned"}
    return result




@app.post("/api/analyze/upi")
def upi_scan(request: UPIRequest):
    result = analyze_upi(request.text)
    result["ai_explanation"], result["ai_provider"] = explain_findings("UPI payment indicators", result)
    result["analysis_mode"] = f"UPI heuristics + {result['ai_provider']} explanation" if result.get("ai_provider") else "local UPI heuristics"
    return result

@app.post("/api/analyze/phone")
def phone_scan(request: PhoneRequest):
    result = analyze_phone(request.text)
    result["ai_explanation"], result["ai_provider"] = explain_findings("phone number indicators", result)
    result["analysis_mode"] = f"phone heuristics + {result['ai_provider']} explanation" if result.get("ai_provider") else "local phone heuristics"
    return result

@app.post("/api/analyze/email-exposure")
async def email_exposure(request: EmailExposureRequest):
    if not request.consent:
        raise HTTPException(status_code=400, detail="Explicit consent is required before sending this email address to Have I Been Pwned.")
    try:
        return await run_in_threadpool(check_email_breaches, request.email, settings.hibp_api_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except RuntimeError as exc:
        status = 503 if "not configured" in str(exc) else 502
        raise HTTPException(status_code=status, detail=str(exc))
