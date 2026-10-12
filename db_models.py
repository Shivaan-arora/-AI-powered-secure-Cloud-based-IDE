"""
Database models using SQLAlchemy ORM.
Supports PostgreSQL (production) and SQLite (local dev/fallback).
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Float, Integer, Boolean
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def generate_uuid() -> str:
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    executions = relationship("ExecutionRecord", back_populates="user", cascade="all, delete-orphan")
    security_events = relationship("SecurityEventRecord", back_populates="user", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="projects")
    files = relationship("ProjectFile", back_populates="project", cascade="all, delete-orphan")


class ProjectFile(Base):
    __tablename__ = "files"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    filename = Column(String(128), nullable=False)
    language = Column(String(32), default="python")
    content = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project = relationship("Project", back_populates="files")
    versions = relationship("FileVersion", back_populates="file", cascade="all, delete-orphan")


class FileVersion(Base):
    __tablename__ = "file_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    file_id = Column(String(36), ForeignKey("files.id"), nullable=False, index=True)
    version_num = Column(Integer, nullable=False, default=1)
    content = Column(Text, default="")
    content_hash = Column(String(64), nullable=False)
    commit_message = Column(String(255), default="Automated checkpoint")
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("ProjectFile", back_populates="versions")


class ExecutionRecord(Base):
    __tablename__ = "executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True, index=True)
    language = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)  # success, error, blocked, timeout
    stdout = Column(Text, default="")
    stderr = Column(Text, default="")
    execution_time = Column(Float, default=0.0)
    risk_level = Column(String(32), default="LOW")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="executions")


class SecurityEventRecord(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True, index=True)
    risk_level = Column(String(32), nullable=False)
    severity = Column(String(32), default="LOW")
    ip_address = Column(String(64), default="unknown")
    endpoint = Column(String(128), default="/execute")
    findings_json = Column(Text, default="[]")
    summary = Column(Text, default="")
    action_taken = Column(String(32), default="LOGGED")  # BLOCKED, ALLOWED, WARNED
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="security_events")
