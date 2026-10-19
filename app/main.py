from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.config import settings
from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url
from app.analyzers.code import analyze_code
from app.analyzers.media import inspect_media
from app.analyzers.triage import analyze_triage
from app.llm import explain_findings, provider_status

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
@app.get("/api/modules")
def modules():
    return {"modules":[
        {"id":"triage","name":"Message triage","description":"Correlate scam language with links embedded in a message."},
        {"id":"text","name":"Scam message","description":"Find urgency, credential, payment, and impersonation cues."},
        {"id":"url","name":"Link scanner","description":"Inspect URL text for suspicious destination patterns; never fetches the link."},
        {"id":"media","name":"Media inspection","description":"Review file properties and image metadata; does not detect deepfakes."},
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
async def media_scan(file:UploadFile=File(...)):
    limit=settings.max_upload_mb*1024*1024
    data=await file.read(limit+1)
    if len(data)>limit: raise HTTPException(status_code=413,detail=f"File exceeds {settings.max_upload_mb} MB limit")
    if not data: raise HTTPException(status_code=400,detail="Uploaded file is empty")
    mime=file.content_type or "application/octet-stream"
    if not (mime.startswith("image/") or mime.startswith("video/") or mime.startswith("audio/")):
        raise HTTPException(status_code=415,detail="Upload an image, audio, or video file")
    return inspect_media(data,file.filename or "upload",mime)
