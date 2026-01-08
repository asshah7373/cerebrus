"""
Entity Definitions for the Memory System
Inspired by Graphiti's temporal knowledge graph approach.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import uuid


class EntityType(str, Enum):
    """Types of entities in the knowledge graph."""
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    USER = "user"
    PORT = "port"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    FINDING = "finding"
    ATTACK = "attack"
    TOOL = "tool"


class RelationType(str, Enum):
    """Types of relationships between entities."""
    HOSTS = "hosts"              # Host -> Service
    EXPOSES = "exposes"          # Host -> Port
    RUNS_ON = "runs_on"          # Service -> Port
    HAS_VULNERABILITY = "has_vulnerability"  # Service/Host -> Vulnerability
    EXPLOITED_BY = "exploited_by"  # Vulnerability -> Attack
    DISCOVERED_BY = "discovered_by"  # Entity -> Tool
    LEADS_TO = "leads_to"        # Finding -> Finding (attack chain)
    AUTHENTICATES = "authenticates"  # Credential -> Service
    CONTAINS = "contains"        # Endpoint -> Parameter


class Entity(BaseModel):
    """
    Base entity in the knowledge graph.
    Represents any discoverable asset or concept.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType
    name: str
    attributes: Dict[str, Any] = Field(default_factory=dict)

    # Temporal information
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None

    # Provenance
    source: str = ""  # Where this entity was discovered
    confidence: float = 1.0  # Confidence in this entity's accuracy
    verified: bool = False

    # Session tracking
    session_id: Optional[str] = None
    episode_ids: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True

    def update(self, attributes: Dict[str, Any]):
        """Update entity attributes and timestamp."""
        self.attributes.update(attributes)
        self.updated_at = datetime.utcnow()


class Relationship(BaseModel):
    """
    Relationship between two entities in the knowledge graph.
    Edges are also temporal and can have attributes.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    relation_type: RelationType
    source_id: str
    target_id: str
    attributes: Dict[str, Any] = Field(default_factory=dict)

    # Temporal information
    created_at: datetime = Field(default_factory=datetime.utcnow)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None

    # Provenance
    confidence: float = 1.0
    episode_id: Optional[str] = None

    class Config:
        use_enum_values = True


class Episode(BaseModel):
    """
    An episode represents a discrete interaction or discovery event.
    Inspired by Graphiti's episodic memory approach.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Episode content
    name: str
    description: str
    episode_type: str  # "scan", "exploit", "discovery", "interaction"

    # Related entities and relationships
    entity_ids: List[str] = Field(default_factory=list)
    relationship_ids: List[str] = Field(default_factory=list)

    # Context
    tool_used: Optional[str] = None
    command: Optional[str] = None
    raw_output: Optional[str] = None

    # Results
    success: bool = True
    findings: List[str] = Field(default_factory=list)

    # Embedding for semantic search
    embedding: Optional[List[float]] = None


# Specialized entity classes for type safety

class HostEntity(Entity):
    """Represents a host (IP address or hostname)."""
    entity_type: EntityType = EntityType.HOST

    @property
    def ip_address(self) -> Optional[str]:
        return self.attributes.get("ip_address")

    @property
    def hostname(self) -> Optional[str]:
        return self.attributes.get("hostname")

    @property
    def os(self) -> Optional[str]:
        return self.attributes.get("os")


class ServiceEntity(Entity):
    """Represents a running service."""
    entity_type: EntityType = EntityType.SERVICE

    @property
    def service_name(self) -> Optional[str]:
        return self.attributes.get("service_name")

    @property
    def version(self) -> Optional[str]:
        return self.attributes.get("version")

    @property
    def port(self) -> Optional[int]:
        return self.attributes.get("port")


class VulnerabilityEntity(Entity):
    """Represents a discovered vulnerability."""
    entity_type: EntityType = EntityType.VULNERABILITY

    @property
    def cve_id(self) -> Optional[str]:
        return self.attributes.get("cve_id")

    @property
    def cvss_score(self) -> Optional[float]:
        return self.attributes.get("cvss_score")

    @property
    def severity(self) -> Optional[str]:
        return self.attributes.get("severity")

    @property
    def exploitable(self) -> bool:
        return self.attributes.get("exploitable", False)


class CredentialEntity(Entity):
    """Represents discovered credentials (stored securely)."""
    entity_type: EntityType = EntityType.CREDENTIAL

    @property
    def username(self) -> Optional[str]:
        return self.attributes.get("username")

    @property
    def credential_type(self) -> Optional[str]:
        return self.attributes.get("credential_type")  # password, hash, key, token

    # Note: Actual credential values should be encrypted


class EndpointEntity(Entity):
    """Represents a web endpoint."""
    entity_type: EntityType = EntityType.ENDPOINT

    @property
    def path(self) -> Optional[str]:
        return self.attributes.get("path")

    @property
    def method(self) -> Optional[str]:
        return self.attributes.get("method")

    @property
    def parameters(self) -> List[str]:
        return self.attributes.get("parameters", [])
