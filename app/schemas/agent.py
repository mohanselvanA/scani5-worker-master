from pydantic import BaseModel
from typing import Optional, List, Literal

class SoftwareInfo(BaseModel):
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    action: Literal["add", "remove", "upgraded", "upgraded_to", "downgraded", "downgraded_to"] = "add"

class PatchInfo(BaseModel):
    hotfix_id: str
    description: Optional[str] = None
    type: Optional[str] = None 
    installed_on: Optional[str] = None
    action: Literal["add", "remove", "upgraded", "upgraded_to", "downgraded", "downgraded_to"] = "add"

class CollectPayload(BaseModel):
    agent_id: str
    SoftwareInventory: List[SoftwareInfo] = []
    Patches: List[PatchInfo] = []

class AgentPayload(BaseModel):
    agent_id: str
    org_hash: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_info: Optional[str] = None
