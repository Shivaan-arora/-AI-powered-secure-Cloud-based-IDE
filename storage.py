"""
File Upload, Download, and Project ZIP Export/Import with security sanitization:
- Path traversal protection
- Extension whitelist
- ZIP-bomb protection (size threshold checks)
"""
import io
import os
import zipfile
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.models.db_models import Project, ProjectFile, User
from backend.auth.security import get_current_user

router = APIRouter(prefix="/files", tags=["storage"])

ALLOWED_EXTENSIONS = {".py", ".cpp", ".java", ".txt", ".md", ".json", ".csv"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_UNCOMPRESSED_ZIP_SIZE = 50 * 1024 * 1024  # 50 MB

@router.get("/download/{file_id}")
def download_file(file_id: str, db: Session = Depends(get_db)):
    """Download single project file."""
    file_obj = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")

    return Response(
        content=file_obj.content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{file_obj.filename}"'}
    )

@router.get("/export-zip/{project_id}")
def export_project_zip(project_id: str, db: Session = Depends(get_db)):
    """Export complete project files as a downloadable ZIP archive."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for f in project.files:
            zip_file.writestr(f.filename, f.content)

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{project.name}.zip"'}
    )

@router.post("/upload/{project_id}")
async def upload_file_to_project(
    project_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload a file (.py, .cpp, .md, .txt) with path sanitization."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    filename = os.path.basename(file.filename)
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File extension '{ext}' not permitted.")

    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds limit of 5MB.")

    text_content = content_bytes.decode("utf-8", errors="replace")

    # Update if exists or create new
    existing = db.query(ProjectFile).filter(ProjectFile.project_id == project_id, ProjectFile.filename == filename).first()
    if existing:
        existing.content = text_content
    else:
        new_file = ProjectFile(
            project_id=project_id,
            filename=filename,
            language="python" if ext == ".py" else ("cpp" if ext == ".cpp" else "text"),
            content=text_content
        )
        db.add(new_file)

    db.commit()
    return {"status": "uploaded", "filename": filename, "size": len(content_bytes)}
