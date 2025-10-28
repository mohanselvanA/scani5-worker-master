import hashlib
import hmac

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.future import select
from starlette.middleware.base import BaseHTTPMiddleware


from app.models.models_worker import Agent
from app.core.database import AsyncWorkerSessionLocal


async def verify_hmac_middleware(request: Request, call_next):
    try:
        # Apply only to POSTs under /api
        if request.url.path.startswith("/api") and request.method != "GET":
            if request.url.path in ["/api/register"]:
                return await call_next(request)
            signature = request.headers.get("X-HMAC-Signature")
            if not signature:
                return JSONResponse(status_code=403, content={"detail": "Missing signature"})

            body = await request.body()
            db = AsyncWorkerSessionLocal()
            try:
                payload = await request.json()
                agent_id = payload.get("agent_id")
                if not agent_id:
                    return JSONResponse(status_code=403, content={"detail": "Missing agent ID"})

                result = await db.execute(select(Agent).filter_by(agent_id=agent_id))
                agent = result.scalar_one_or_none()
                if not agent:
                    return JSONResponse(status_code=403, content={"detail": "Invalid agent"})

                expected_signature = hmac.new(agent.secret.encode(), body, hashlib.sha256).hexdigest()
                print(expected_signature)
                if not hmac.compare_digest(expected_signature, signature):
                    return JSONResponse(status_code=403, content={"detail": "Signature mismatch"})
            finally:
                db.close()
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Middleware error: {str(e)}"})

    return await call_next(request)