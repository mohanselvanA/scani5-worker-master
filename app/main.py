from fastapi import FastAPI
from app.api.routes import router as api_router
from app.config.config import settings
from app.middleware.hmac_auth import verify_hmac_middleware

app = FastAPI(title="Agent Backend API")

app.middleware("http")(verify_hmac_middleware)
app.include_router(api_router, prefix="/api")