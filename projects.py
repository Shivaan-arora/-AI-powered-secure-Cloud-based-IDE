import hashlib
import difflib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database.session import get_db
from backend.models.db_models import Project, ProjectFile, FileVersion, User
from backend.auth.security import get_current_user

router = APIRouter(prefix="/projects", tags=["projects"])

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = ""

class FileCreate(BaseModel):
    filename: str
    language: Optional[str] = "python"
    content: Optional[str] = ""

class FileUpdate(BaseModel):
    content: str

@router.get("")
def list_projects(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.user_id == user.id).all()
    return [{"id": p.id, "name": p.name, "description": p.description, "created_at": p.created_at, "files_count": len(p.files)} for p in projects]

@router.post("")
def create_project(payload: ProjectCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = Project(user_id=user.id, name=payload.name, description=payload.description)
    db.add(project)
    db.commit()
    db.refresh(project)

    # Add default main.py
    default_file = ProjectFile(
        project_id=project.id,
        filename="main.py",
        language="python",
        content="print('Hello from ' + '" + payload.name + "')\n"
    )
    db.add(default_file)
    db.commit()

    return {"id": project.id, "name": project.name, "description": project.description}

@router.get("/{project_id}")
def get_project(project_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    files = [{"id": f.id, "filename": f.filename, "language": f.language, "content": f.content, "updated_at": f.updated_at} for f in project.files]
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "files": files
    }

@router.post("/{project_id}/files")
def create_file(project_id: str, payload: FileCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    existing = db.query(ProjectFile).filter(ProjectFile.project_id == project_id, ProjectFile.filename == payload.filename).first()
    if existing:
        raise HTTPException(status_code=400, detail="File already exists")

    file_obj = ProjectFile(
        project_id=project.id,
        filename=payload.filename,
        language=payload.language or "python",
        content=payload.content or ""
    )
    db.add(file_obj)
    db.commit()
    db.refresh(file_obj)
    return {"id": file_obj.id, "filename": file_obj.filename, "language": file_obj.language, "content": file_obj.content}

@router.put("/{project_id}/files/{file_id}")
def update_file(project_id: str, file_id: str, payload: FileUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    file_obj = db.query(ProjectFile).filter(ProjectFile.id == file_id, ProjectFile.project_id == project_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")

    # Create version snapshot if content changed
    new_hash = hashlib.sha256(payload.content.encode('utf-8')).hexdigest()
    last_version = db.query(FileVersion).filter(FileVersion.file_id == file_id).order_by(FileVersion.version_num.desc()).first()
    
    if not last_version or last_version.content_hash != new_hash:
        next_ver = (last_version.version_num + 1) if last_version else 1
        ver_obj = FileVersion(
            file_id=file_id,
            version_num=next_ver,
            content=payload.content,
            content_hash=new_hash,
            commit_message=f"Checkpoint v{next_ver}"
        )
        db.add(ver_obj)

    file_obj.content = payload.content
    db.commit()
    return {"status": "saved", "file_id": file_obj.id, "hash": new_hash}

@router.get("/{project_id}/files/{file_id}/versions")
def get_file_versions(project_id: str, file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieve version history list for a file."""
    versions = db.query(FileVersion).filter(FileVersion.file_id == file_id).order_by(FileVersion.version_num.desc()).all()
    return [{
        "id": v.id,
        "version_num": v.version_num,
        "content_hash": v.content_hash,
        "commit_message": v.commit_message,
        "created_at": v.created_at
    } for v in versions]

@router.get("/{project_id}/files/{file_id}/versions/{version_num}/diff")
def get_version_diff(project_id: str, file_id: str, version_num: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Compute line-by-line diff between current file and a previous version."""
    file_obj = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")

    target_ver = db.query(FileVersion).filter(FileVersion.file_id == file_id, FileVersion.version_num == version_num).first()
    if not target_ver:
        raise HTTPException(status_code=404, detail="Version not found")

    current_lines = file_obj.content.splitlines(keepends=True)
    target_lines = target_ver.content.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        target_lines, current_lines,
        fromfile=f"v{version_num}", tofile="current"
    ))
    return {
        "diff": "".join(diff),
        "target_version": version_num,
        "current_content": file_obj.content,
        "target_content": target_ver.content
    }

@router.post("/{project_id}/files/{file_id}/versions/{version_num}/restore")
def restore_version(project_id: str, file_id: str, version_num: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Roll back file to a previous version checkpoint."""
    file_obj = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")

    target_ver = db.query(FileVersion).filter(FileVersion.file_id == file_id, FileVersion.version_num == version_num).first()
    if not target_ver:
        raise HTTPException(status_code=404, detail="Version not found")

    file_obj.content = target_ver.content
    db.commit()
    return {"status": "restored", "version_restored": version_num, "content": file_obj.content}

@router.delete("/{project_id}/files/{file_id}")
def delete_file(project_id: str, file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    file_obj = db.query(ProjectFile).filter(ProjectFile.id == file_id, ProjectFile.project_id == project_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")

    db.delete(file_obj)
    db.commit()
    return {"status": "deleted"}
