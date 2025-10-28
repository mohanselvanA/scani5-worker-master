from fastapi import APIRouter, Request, status
from app.core.database import AsyncWorkerDBSession
from app.schemas.agent import AgentPayload,CollectPayload
from app.services.agent_service import (
    register_agent, ping_agent, collect_data, renew_secret
)


router = APIRouter()




@router.post("/register", status_code=status.HTTP_200_OK)
async def register(payload: AgentPayload, request: Request, db: AsyncWorkerDBSession):
    return await register_agent(payload, db)

@router.post("/ping", status_code=status.HTTP_200_OK)
async def ping(payload: AgentPayload, db: AsyncWorkerDBSession):
    return await ping_agent(payload, db)

@router.post("/collect", status_code=status.HTTP_200_OK)
async def collect(payload: CollectPayload,request: Request, db: AsyncWorkerDBSession):
    raw = await request.body()
    # print("🔍 Raw Request Body:", raw.decode())
    # print("🔍 Parsed Payload:", payload.dict())
    return await collect_data(payload, db)

@router.post("/renew_secret", status_code=status.HTTP_200_OK)
async def renew(payload: AgentPayload, db: AsyncWorkerDBSession):
    return await renew_secret(payload, db)