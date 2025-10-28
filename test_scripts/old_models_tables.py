from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, func, Table, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    org_name = Column(String(255))
    org_hash = Column(String(255), unique=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    agents = relationship("Agent", back_populates="organization")

class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(255), unique=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"))
    secret = Column(Text)
    hostname = Column(String(255))
    ip_address = Column(String(255))
    os_info = Column(Text)
    agent_check_in = Column(DateTime)
    inventory_updated_at = Column(DateTime)
    key_rotated_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    organization = relationship("Organization", back_populates="agents")
    software_inventory = relationship("SoftwareInventory", back_populates="agent", cascade="all, delete")
    patch_info = relationship("OSUpdatesInventory", back_populates="agent", cascade="all, delete")
    vulnerability_status = relationship("AgentVulnerabilityStatus", back_populates="agent")

class SoftwareInventory(Base):
    __tablename__ = "software_inventory"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(Text)
    version = Column(Text)
    vendor = Column(Text)
    action = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    cpe = Column(Text)  
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    agent = relationship("Agent", back_populates="software_inventory")
    organization = relationship("Organization")
    cve_links = relationship("InventoryCVE", backref="software_inventory", cascade="all, delete")

class OSUpdatesInventory(Base):
    __tablename__ = "os_updates_inventory"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    hotfix_id = Column(Text)
    description = Column(Text)
    installed_on = Column(Text)
    type = Column(String(50))
    action = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    agent = relationship("Agent", back_populates="patch_info")
    organization = relationship("Organization")

class CPEData(Base):
    __tablename__ = "cpe_data"
    id = Column(Integer, primary_key=True)
    cpe_name = Column(Text, unique=True, nullable=False)
    cpe_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class CVEData(Base):
    __tablename__ = "cve_data"
    id = Column(Integer, primary_key=True)
    cve_id = Column(Text, unique=True, nullable=False)
    cve_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class CWEData(Base):
    __tablename__ = "cwe_data"
    id = Column(Integer, primary_key=True)
    cwe_id = Column(Text, unique=True, nullable=False)
    cwe_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())



class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    name = Column(Text)
    description = Column(Text)
    cvss = Column(Float)
    exploitscore = Column(Float)
    impactscore = Column(Float)
    car = Column(Float)
    exploit_risk = Column(Float)
    impact_risk = Column(Float)
    visibility_score = Column(Float)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    agent_links = relationship("AgentVulnerabilityStatus", back_populates="vulnerability")

class Exploit(Base):
    __tablename__ = "exploits"
    id = Column(Integer, primary_key=True)
    cve_id = Column(Integer, ForeignKey("cve_data.id"))
    title = Column(Text)
    description = Column(Text)
    published_on = Column(DateTime)
    source = Column(Text)
    exploit_type = Column(String(100))
    access_type = Column(String(100))
    severity = Column(String(50))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


    cve = relationship("CVEData")

class Solution(Base):
    __tablename__ = "solutions"
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    name = Column(Text)
    description = Column(Text)
    references = Column(JSONB)  # List of URLs
    release_date = Column(DateTime)
    type = Column(String(50))
    priority = Column(String(50))
    rollback_available = Column(String(10))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    vulnerability = relationship("Vulnerability")

class Mitigation(Base):
    __tablename__ = "mitigations"
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    name = Column(Text)
    description = Column(Text)
    references = Column(JSONB)  # List of URLs
    type = Column(String(50))
    effectiveness = Column(String(50))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    vulnerability = relationship("Vulnerability")

class AgentVulnerabilityStatus(Base):
    __tablename__ = "agent_vulnerability_status"
    id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)

    status = Column(String(50))  # open, patched, mitigated

    # CVSS/Exploit scores (for this specific agent-vuln link)
    cvssv2 = Column(Float)
    exploitscorev2 = Column(Float)
    impactscorev2 = Column(Float)
    cvssv3 = Column(Float)
    exploitscorev3 = Column(Float)
    impactscorev3 = Column(Float)
    car = Column(Float)
    exploit_risk = Column(Float)
    impact_risk = Column(Float)
    visibility_score = Column(Float)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


    agent = relationship("Agent")
    vulnerability = relationship("Vulnerability")

class InventoryCVE(Base):
    __tablename__ = "inventory_cves"
    id = Column(Integer, primary_key=True)
    software_inventory_id = Column(Integer, ForeignKey("software_inventory.id"), nullable=False)
    cve_id = Column(Integer, ForeignKey("cve_data.id"), nullable=False)
    created_at = Column(DateTime)

    cve = relationship("CVEData")  

    __table_args__ = (UniqueConstraint('software_inventory_id', 'cve_id', name='uq_inventory_cve'),)

class CVEGroup(Base):
    __tablename__ = "cve_groups"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    group_id = Column(String(100), nullable=False)  
    reason = Column(String(255), nullable=False)   
    cwe_id = Column(String(100), nullable=True)    
    created_on = Column(DateTime, default=func.now())

    __table_args__ = (UniqueConstraint("organization_id", "group_id", name="uq_org_group_id"),)

    organization = relationship("Organization", backref="cve_groups")
    vulnerabilities = relationship("VulnerabilityGroupLink", back_populates="group", cascade="all, delete")

class VulnerabilityGroupLink(Base):
    __tablename__ = "vulnerability_group_links"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("cve_groups.id"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)

    __table_args__ = (UniqueConstraint("group_id", "vulnerability_id", name="uq_group_vuln"),)

    group = relationship("CVEGroup", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability", backref="group_links")