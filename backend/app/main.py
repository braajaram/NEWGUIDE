from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import get_settings
from .db import Base, engine, get_db
from .models import AuditLog, Finding, Scan, Session as DbSession, User
from .scanners import analyze_email, analyze_file, analyze_url
from .schemas import CopilotInput, Credentials, EmailInput, UrlInput
from .security import create_session, csrf_guard, current_user, hash_password, require_admin, verify_password

settings = get_settings()
app = FastAPI(title="CyberGuard AI API", version="1.0.0", description="Evidence-based URL, file, and email security analysis.")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",")], allow_credentials=True, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"])

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)

@app.middleware("http")
async def secure_headers(request: Request, call_next):
    try:
        csrf_guard(request)
        response = await call_next(request)
    except Exception as exc:
        if hasattr(exc, "status_code"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        raise
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

def audit(db: Session, user_id: int | None, action: str, detail: dict | None = None):
    db.add(AuditLog(user_id=user_id, action=action, detail=detail or {}))

def save_scan(db: Session, user: User, kind: str, subject: str, result: dict) -> Scan:
    indicators = result.get("indicators", [])
    scan = Scan(user_id=user.id, kind=kind, subject=subject[:512], assessment="suspicious" if indicators else "insufficient_data", result=result, completed_at=datetime.now(timezone.utc))
    db.add(scan)
    db.flush()
    for item in indicators:
        db.add(Finding(scan_id=scan.id, severity=item.get("severity", "informational"), title=item["title"], description=item.get("evidence", ""), evidence=item.get("evidence", ""), recommendation=item.get("recommendation", "Review the evidence.")))
    audit(db, user.id, "scan.created", {"scan_id": scan.id, "kind": kind})
    db.commit()
    db.refresh(scan)
    return scan

def scan_json(scan: Scan):
    return {"id": scan.id, "kind": scan.kind, "status": scan.status, "subject": scan.subject, "assessment": scan.assessment, "created_at": scan.created_at, "completed_at": scan.completed_at, "result": scan.result, "findings": [{"severity": f.severity, "title": f.title, "description": f.description, "evidence": f.evidence, "confidence": f.confidence, "source": f.source, "recommendation": f.recommendation} for f in scan.findings]}

@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberguard-api"}

@app.post("/api/auth/register")
def register(payload: Credentials, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        return JSONResponse({"detail": "Email already registered"}, status_code=409)
    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_session(db, user)
    response = JSONResponse({"user": {"id": user.id, "email": user.email, "role": user.role}, "csrf_token": settings.secret_key[:16]})
    response.set_cookie("cyberguard_session", token, httponly=True, samesite="lax", secure=False, max_age=604800)
    return response

@app.post("/api/auth/login")
def login(payload: Credentials, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
    token = create_session(db, user)
    response = JSONResponse({"user": {"id": user.id, "email": user.email, "role": user.role}, "csrf_token": settings.secret_key[:16]})
    response.set_cookie("cyberguard_session", token, httponly=True, samesite="lax", secure=False, max_age=604800)
    return response

@app.post("/api/auth/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("cyberguard_session")
    session = db.get(DbSession, token) if token else None
    if session:
        db.delete(session)
        db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("cyberguard_session")
    return response

@app.get("/api/auth/me")
def me(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    return {"id": user.id, "email": user.email, "role": user.role, "verified": user.is_verified, "mfa_enabled": user.mfa_enabled, "csrf_token": settings.secret_key[:16]}

@app.post("/api/scans/url")
def url_scan(payload: UrlInput, request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    try:
        result = analyze_url(payload.url)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=422)
    return scan_json(save_scan(db, user, "url", payload.url, result))

@app.post("/api/scans/file")
def file_scan(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = current_user(request, db)
    try:
        result = analyze_file(file.filename or "upload", file.file.read())
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=413)
    return scan_json(save_scan(db, user, "file", file.filename or "upload", result))

@app.post("/api/scans/email")
def email_scan(payload: EmailInput, request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    return scan_json(save_scan(db, user, "email", "pasted email", analyze_email(payload.content.encode())))

@app.get("/api/scans")
def scans(request: Request, db: Session = Depends(get_db), kind: str | None = None):
    user = current_user(request, db)
    query = select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc())
    if kind:
        query = query.where(Scan.kind == kind)
    return [scan_json(scan) for scan in db.scalars(query.limit(100)).all()]

@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        return JSONResponse({"detail": "Scan not found"}, status_code=404)
    return scan_json(scan)

@app.get("/api/reports/{scan_id}.json")
def report_json(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        return JSONResponse({"detail": "Report not found"}, status_code=404)
    return {"report_type": "CyberGuard AI scan report", "limitations": scan.result.get("limitations", []), "scan": scan_json(scan)}

@app.get("/api/admin/system-health")
def system_health(request: Request, db: Session = Depends(get_db)):
    require_admin(current_user(request, db))
    return {"api": "ok", "database": "ok", "redis": "configured" if settings.redis_url else "Data unavailable", "external_integrations": {"virustotal": "configured" if settings.virustotal_api_key else "Data unavailable", "ai": "configured" if settings.ai_api_key else "Data unavailable"}}

@app.get("/api/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    records = db.scalars(select(Scan).where(Scan.user_id == user.id)).all()
    return {"total": len(records), "by_type": {kind: sum(s.kind == kind for s in records) for kind in ("url", "file", "email")}, "suspicious": sum(s.assessment == "suspicious" for s in records), "recent": [scan_json(s) for s in sorted(records, key=lambda x: x.created_at, reverse=True)[:5]]}

@app.post("/api/copilot/chat")
def copilot(payload: CopilotInput, request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    scan = db.scalar(select(Scan).where(Scan.id == payload.scan_id, Scan.user_id == user.id))
    if not scan:
        return JSONResponse({"detail": "Scan not found"}, status_code=404)
    findings = scan.result.get("indicators", [])
    if not findings:
        answer = "There are no locally detected indicators in this scan. External reputation data is Data unavailable, so this is not a guarantee of safety."
    else:
        answer = "Based only on this scan's evidence: " + "; ".join(f"{item['title']} ({item.get('severity', 'informational')}): {item.get('evidence', 'no evidence')}" for item in findings) + " Review the recommendations in the report."
    return {"answer": answer, "grounded_scan_id": scan.id, "data_sources": ["persisted scan evidence"]}

@app.get("/api/admin/users")
def admin_users(request: Request, db: Session = Depends(get_db)):
    require_admin(current_user(request, db))
    return [{"id": user.id, "email": user.email, "role": user.role, "active": user.is_active} for user in db.scalars(select(User)).all()]

@app.get("/api/admin/audit-logs")
def audit_logs(request: Request, db: Session = Depends(get_db)):
    require_admin(current_user(request, db))
    return [{"id": item.id, "action": item.action, "detail": item.detail, "created_at": item.created_at} for item in db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)).all()]
