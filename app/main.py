from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from app.config import settings
from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url
from app.analyzers.code import analyze_code
from app.analyzers.media import inspect_media
from app.analyzers.triage import analyze_triage
from app.llm import explain_findings, provider_status, review_image_visual_clues

app=FastAPI(title=settings.app_name,version="1.1.0",description="Evidence-led digital safety workspace")
STATIC=Path(__file__).resolve().parent.parent/"static"
app.mount("/static",StaticFiles(directory=STATIC),name="static")

class TextRequest(BaseModel): text: str=Field(min_length=3,max_length=12000)
class URLRequest(BaseModel): url: str=Field(min_length=3,max_length=2048)
class CodeRequest(BaseModel): code: str=Field(min_length=3,max_length=30000)
class TriageRequest(BaseModel): content: str=Field(min_length=3,max_length=12000)

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
@app.get("/health")
def health(): return {"status":"ok","providers":provider_status(),"version":app.version}
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
        {"id":"media","name":"Media verification","description":"Inspect image file signatures and metadata; optional Gemini visual observations are not a deepfake verdict."},
        {"id":"code","name":"Code audit","description":"Find selected vulnerability patterns with line references and fixes."},
    ]}
@app.post("/api/analyze/triage")
def triage_scan(request:TriageRequest):
    result=analyze_triage(request.content)
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
def url_scan(request:URLRequest):
    result=analyze_url(request.url)
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
async def media_scan(file:UploadFile=File(...), ai_visual_review:bool=Form(False)):
    limit=settings.max_upload_mb*1024*1024
    data=await file.read(limit+1)
    if len(data)>limit: raise HTTPException(status_code=413,detail=f"File exceeds {settings.max_upload_mb} MB limit")
    if not data: raise HTTPException(status_code=400,detail="Uploaded file is empty")
    mime=file.content_type or "application/octet-stream"
    if not (mime.startswith("image/") or mime.startswith("video/") or mime.startswith("audio/")):
        raise HTTPException(status_code=415,detail="Upload an image, audio, or video file")
    result=inspect_media(data,file.filename or "upload",mime)
    if ai_visual_review:
        if not mime.startswith("image/"):
            raise HTTPException(status_code=422,detail="Optional Gemini visual review is available for images only")
        if not settings.gemini_api_key:
            raise HTTPException(status_code=503,detail="Add GEMINI_API_KEY on the server to enable optional visual review. Local file inspection is available without it.")
        if result.get("format"):
            actual_mime={"JPEG":"image/jpeg","PNG":"image/png","WEBP":"image/webp","GIF":"image/gif","BMP":"image/bmp","TIFF":"image/tiff"}.get(result["format"])
            if not actual_mime:
                raise HTTPException(status_code=415,detail="This image format is not supported for optional visual review")
            observation,provider=await run_in_threadpool(review_image_visual_clues,data,actual_mime)
            if observation:
                result["visual_review"]={"provider":provider,"observations":observation,"label":"AI-assisted visual observations · not a deepfake/authenticity verdict"}
            else:
                result["visual_review"]={"provider":None,"observations":"The optional visual review is temporarily unavailable. The local file inspection is still available.","label":"No AI visual observations returned"}
    return result
