from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.config import settings
from app.analyzers.text import analyze_text
from app.analyzers.url import analyze_url
from app.analyzers.code import analyze_code
from app.analyzers.media import inspect_media
from app.llm import explain_with_gemini

app=FastAPI(title=settings.app_name,version="1.0.0",description="Evidence-led prototype digital safety analyzers")
STATIC=Path(__file__).resolve().parent.parent/"static"
app.mount("/static",StaticFiles(directory=STATIC),name="static")

class TextRequest(BaseModel): text: str=Field(min_length=3,max_length=12000)
class URLRequest(BaseModel): url: str=Field(min_length=3,max_length=2048)
class CodeRequest(BaseModel): code: str=Field(min_length=3,max_length=30000)

@app.get("/",include_in_schema=False)
def home(): return FileResponse(STATIC/"index.html")
@app.get("/health")
def health(): return {"status":"ok","gemini_configured":bool(settings.gemini_api_key),"version":app.version}
@app.post("/api/analyze/text")
def text_scan(request:TextRequest):
    result=analyze_text(request.text)
    result["ai_explanation"]=explain_with_gemini("scam text",result)
    result["analysis_mode"]="rules + Gemini explanation" if result["ai_explanation"] else "local rules"
    return result
@app.post("/api/analyze/url")
def url_scan(request:URLRequest):
    result=analyze_url(request.url)
    result["ai_explanation"]=explain_with_gemini("URL indicators",result)
    result["analysis_mode"]="URL heuristics + Gemini explanation" if result["ai_explanation"] else "local URL heuristics"
    return result
@app.post("/api/analyze/code")
def code_scan(request:CodeRequest):
    result=analyze_code(request.code)
    result["ai_explanation"]=explain_with_gemini("source code findings",result)
    result["analysis_mode"]="static rules + Gemini explanation" if result["ai_explanation"] else "local static rules"
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
