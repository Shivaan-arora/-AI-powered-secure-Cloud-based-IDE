"""
Execution history, audit logs, and metrics dashboard endpoints.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database.session import get_db
from backend.models.db_models import User, ExecutionRecord, SecurityEventRecord, Project
from backend.auth.security import get_current_user_optional

router = APIRouter(tags=["monitoring"])

@router.get("/executions")
def get_executions(db: Session = Depends(get_db)):
    execs = db.query(ExecutionRecord).order_by(ExecutionRecord.created_at.desc()).limit(50).all()
    return [{
        "id": e.id,
        "language": e.language,
        "status": e.status,
        "execution_time": e.execution_time,
        "risk_level": e.risk_level,
        "created_at": e.created_at
    } for e in execs]

@router.get("/security/events")
def get_security_events(db: Session = Depends(get_db)):
    events = db.query(SecurityEventRecord).order_by(SecurityEventRecord.created_at.desc()).limit(50).all()
    return [{
        "id": ev.id,
        "risk_level": ev.risk_level,
        "severity": getattr(ev, "severity", "LOW") or "LOW",
        "ip_address": getattr(ev, "ip_address", "unknown") or "unknown",
        "endpoint": getattr(ev, "endpoint", "/execute") or "/execute",
        "action_taken": ev.action_taken,
        "summary": ev.summary,
        "created_at": ev.created_at
    } for ev in events]

@router.get("/security/threat-summary")
def get_threat_summary(db: Session = Depends(get_db)):
    """Threat intelligence: group blocked and high-risk events by client IP."""
    threat_events = db.query(
        SecurityEventRecord.ip_address,
        func.count(SecurityEventRecord.id).label("attack_count")
    ).filter(SecurityEventRecord.action_taken == "BLOCKED").group_by(SecurityEventRecord.ip_address).all()

    return {
        "flagged_ips": [{"ip": row[0], "blocked_attempts": row[1]} for row in threat_events],
        "threat_level": "ELEVATED" if len(threat_events) > 3 else "NORMAL"
    }

@router.get("/admin/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_projects = db.query(Project).count()
    total_executions = db.query(ExecutionRecord).count()
    blocked_executions = db.query(ExecutionRecord).filter(ExecutionRecord.status == "blocked").count()
    successful_executions = db.query(ExecutionRecord).filter(ExecutionRecord.status == "success").count()
    failed_executions = db.query(ExecutionRecord).filter(ExecutionRecord.status.in_(["error", "timeout"])).count()
    
    avg_time = db.query(func.avg(ExecutionRecord.execution_time)).scalar() or 0.0

    # Risk level distribution
    risks = db.query(ExecutionRecord.risk_level, func.count(ExecutionRecord.id)).group_by(ExecutionRecord.risk_level).all()
    risk_dist = {r[0]: r[1] for r in risks}

    return {
        "total_users": total_users,
        "total_projects": total_projects,
        "total_executions": total_executions,
        "successful_executions": successful_executions,
        "blocked_executions": blocked_executions,
        "failed_executions": failed_executions,
        "avg_execution_time": round(float(avg_time), 3),
        "risk_distribution": risk_dist
    }
