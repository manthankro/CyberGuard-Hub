from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "CyberGuard Hub"
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.8-flash"
    sightengine_api_user: str = ""
    sightengine_api_secret: str = ""
    hibp_api_key: str = ""
    ai_provider_order: str = "groq,gemini"
    max_upload_mb: int = 10
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
