import base64, hashlib, hmac, secrets
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session
from .config import get_settings
from .models import Session as DbSession, User

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return base64.urlsafe_b64encode(salt + digest).decode()

def verify_password(password: str, encoded: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(encoded.encode())
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 210_000), raw[16:])
    except (ValueError, TypeError): return False

def create_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(48)
    db.add(DbSession(id=token, user_id=user.id, expires_at=datetime.now(timezone.utc) + timedelta(days=7)))
    db.commit()
    return token

def current_user(request: Request, db: Session) -> User:
    token = request.cookies.get("cyberguard_session")
    if not token: raise HTTPException(401, "Authentication required")
    session = db.get(DbSession, token)
    if not session or session.expires_at < datetime.now(timezone.utc): raise HTTPException(401, "Session expired")
    user = db.get(User, session.user_id)
    if not user or not user.is_active: raise HTTPException(401, "Account unavailable")
    return user

def require_admin(user: User):
    if user.role != "admin": raise HTTPException(403, "Admin role required")

def csrf_guard(request: Request):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.cookies.get("cyberguard_session"):
        if request.headers.get("x-csrf-token") != get_settings().secret_key[:16]: raise HTTPException(403, "CSRF validation failed")
