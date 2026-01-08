"""
SQLAlchemy Models for Cerebrus
Database schemas for storing pentesting data.
"""
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from .database import Base


class SessionStatus(enum.Enum):
    """Status of a pentesting session."""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskStatus(enum.Enum):
    """Status of a task."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(enum.Enum):
    """Severity level for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SessionModel(Base):
    """Database model for pentesting sessions."""
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    objective = Column(Text, nullable=False)
    status = Column(SQLEnum(SessionStatus), default=SessionStatus.CREATED)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Configuration
    automation_level = Column(String(50), default="semi_auto")
    constraints = Column(JSON, default=list)

    # Relationships
    targets = relationship("TargetModel", back_populates="session", cascade="all, delete-orphan")
    tasks = relationship("TaskModel", back_populates="session", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Session {self.id}: {self.name}>"


class TargetModel(Base):
    """Database model for pentesting targets."""
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)

    name = Column(String(255), nullable=False)
    target_type = Column(String(50), nullable=False)  # web, network, host, api
    address = Column(String(500), nullable=False)  # URL, IP, hostname

    # Authorization
    authorized = Column(Boolean, default=False)
    authorization_scope = Column(Text, default="")
    authorized_at = Column(DateTime, nullable=True)
    authorized_by = Column(String(255), nullable=True)

    # Discovery data
    ports = Column(JSON, default=list)
    services = Column(JSON, default=dict)

    # Metadata
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    session = relationship("SessionModel", back_populates="targets")
    tasks = relationship("TaskModel", back_populates="target")
    findings = relationship("FindingModel", back_populates="target")

    def __repr__(self):
        return f"<Target {self.id}: {self.address}>"


class TaskModel(Base):
    """Database model for pentesting tasks."""
    __tablename__ = "tasks"

    id = Column(String(36), primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=True)

    name = Column(String(255), nullable=False)
    task_type = Column(String(50), nullable=False)  # recon, scan, exploit, report
    status = Column(SQLEnum(TaskStatus), default=TaskStatus.PENDING)

    # Execution details
    tool = Column(String(100), nullable=True)
    parameters = Column(JSON, default=dict)
    risk_level = Column(String(20), default="low")

    # Results
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)

    # Approval
    requires_approval = Column(Boolean, default=False)
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    session = relationship("SessionModel", back_populates="tasks")
    target = relationship("TargetModel", back_populates="tasks")

    def __repr__(self):
        return f"<Task {self.id}: {self.name}>"


class FindingModel(Base):
    """Database model for security findings."""
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True)
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=True)

    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    category = Column(String(100), nullable=False)

    # Evidence
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")

    # CVE information
    cve_ids = Column(JSON, default=list)
    cvss_score = Column(Float, nullable=True)

    # Verification
    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    verified_by = Column(String(255), nullable=True)

    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    discovered_by = Column(String(100), default="")  # agent name

    # Relationships
    session = relationship("SessionModel", back_populates="findings")
    target = relationship("TargetModel", back_populates="findings")

    def __repr__(self):
        return f"<Finding {self.id}: {self.title}>"


class AuditLogModel(Base):
    """Database model for audit logging."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), nullable=True)

    # Event details
    event_type = Column(String(100), nullable=False)
    event_description = Column(Text, nullable=False)

    # Actor
    actor = Column(String(100), default="system")  # user, agent name, system

    # Context
    target = Column(String(500), nullable=True)
    tool = Column(String(100), nullable=True)
    risk_level = Column(String(20), nullable=True)

    # Data
    request_data = Column(JSON, nullable=True)
    response_data = Column(JSON, nullable=True)

    # Result
    success = Column(Boolean, default=True)
    error = Column(Text, nullable=True)

    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AuditLog {self.id}: {self.event_type}>"


class SettingsModel(Base):
    """Database model for user settings."""
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Setting {self.key}>"
