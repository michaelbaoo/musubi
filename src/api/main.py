from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import jwt
from loguru import logger
import asyncio

from ..core import Config, QuarantineManager, SpamDetectionEngine
from ..database.mongodb_client import db_client
from ..database.models import (
    QuarantinedEmail, UserPreferences, EmailStatus,
    AllowedSender, BlockedSender, SpamPattern
)
from ..security.auth import AuthManager
from ..security.encryption import EncryptionManager

app = FastAPI(title="Email Spam Quarantine API", version="1.0.0")
security = HTTPBearer()
auth_manager = AuthManager()
encryption_manager = EncryptionManager()
quarantine_manager = QuarantineManager()
config = Config()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ReviewRequest(BaseModel):
    action: str
    reason: Optional[str] = None

class BulkReviewRequest(BaseModel):
    email_ids: List[str]
    action: str

class PreferencesUpdate(BaseModel):
    auto_delete_spam: Optional[bool] = None
    quarantine_days: Optional[int] = None
    spam_threshold: Optional[float] = None
    daily_digest: Optional[bool] = None
    digest_time: Optional[str] = None
    notify_high_risk: Optional[bool] = None

class AllowedSenderRequest(BaseModel):
    email: EmailStr
    reason: Optional[str] = None

class BlockedSenderRequest(BaseModel):
    email: Optional[EmailStr] = None
    domain: Optional[str] = None
    reason: str

# Dependency for authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.on_event("startup")
async def startup_event():
    await db_client.connect()
    await quarantine_manager.spam_engine.load_spam_patterns()
    logger.info("API server started")

@app.on_event("shutdown")
async def shutdown_event():
    await db_client.disconnect()
    logger.info("API server stopped")

# Static files and UI
app.mount("/static", StaticFiles(directory="src/ui/static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    with open("src/ui/templates/index.html", "r") as f:
        return HTMLResponse(content=f.read())

# Authentication endpoints
@app.post("/api/auth/login")
async def login(request: LoginRequest):
    user = await auth_manager.authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = auth_manager.create_access_token(user["id"])
    return {"access_token": token, "token_type": "bearer", "user": user}

@app.post("/api/auth/register")
async def register(request: LoginRequest):
    user = await auth_manager.register_user(request.email, request.password)
    if not user:
        raise HTTPException(status_code=400, detail="Registration failed")
    
    token = auth_manager.create_access_token(user["id"])
    return {"access_token": token, "token_type": "bearer", "user": user}

# Quarantine management endpoints
@app.get("/api/quarantine/emails", response_model=List[QuarantinedEmail])
async def get_quarantined_emails(
    user_id: str = Depends(get_current_user),
    status: Optional[str] = None,
    limit: int = 100,
    skip: int = 0
):
    emails = await db_client.get_quarantined_emails(user_id, status, limit, skip)
    return emails

@app.get("/api/quarantine/email/{email_id}")
async def get_email_details(
    email_id: str,
    user_id: str = Depends(get_current_user)
):
    emails = await db_client.get_quarantined_emails(user_id, limit=1)
    email = next((e for e in emails if e.id == email_id), None)
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    return email

@app.get("/api/quarantine/email/{email_id}/summary")
async def get_email_summary(
    email_id: str,
    user_id: str = Depends(get_current_user)
):
    summary = await db_client.get_email_summary(email_id)
    if not summary:
        # Generate summary on demand
        emails = await db_client.get_quarantined_emails(user_id, limit=1)
        email = next((e for e in emails if e.id == email_id), None)
        
        if not email:
            raise HTTPException(status_code=404, detail="Email not found")
        
        summary = await quarantine_manager.generate_email_summary(email)
        await db_client.save_email_summary(summary)
    
    return summary

@app.post("/api/quarantine/email/{email_id}/review")
async def review_email(
    email_id: str,
    request: ReviewRequest,
    user_id: str = Depends(get_current_user)
):
    success = await quarantine_manager.review_quarantined_email(
        email_id, user_id, request.action, request.reason
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Review action failed")
    
    return {"message": f"Email {request.action} successful"}

@app.post("/api/quarantine/bulk-review")
async def bulk_review_emails(
    request: BulkReviewRequest,
    user_id: str = Depends(get_current_user)
):
    results = await quarantine_manager.bulk_review(
        user_id, request.email_ids, request.action
    )
    
    return {"results": results}

@app.get("/api/quarantine/statistics")
async def get_statistics(
    user_id: str = Depends(get_current_user),
    days: int = 7
):
    stats = await quarantine_manager.get_quarantine_summary(user_id, days)
    return stats

# User preferences endpoints
@app.get("/api/preferences")
async def get_preferences(user_id: str = Depends(get_current_user)):
    preferences = await db_client.get_user_preferences(user_id)
    if not preferences:
        preferences = UserPreferences(user_id=user_id, email="")
    return preferences

@app.put("/api/preferences")
async def update_preferences(
    update: PreferencesUpdate,
    user_id: str = Depends(get_current_user)
):
    preferences = await db_client.get_user_preferences(user_id)
    if not preferences:
        preferences = UserPreferences(user_id=user_id, email="")
    
    for field, value in update.dict(exclude_unset=True).items():
        setattr(preferences, field, value)
    
    await db_client.save_user_preferences(preferences)
    return {"message": "Preferences updated"}

# Allowed/Blocked senders endpoints
@app.get("/api/senders/allowed")
async def get_allowed_senders(user_id: str = Depends(get_current_user)):
    # Implementation would fetch from database
    return []

@app.post("/api/senders/allowed")
async def add_allowed_sender(
    request: AllowedSenderRequest,
    user_id: str = Depends(get_current_user)
):
    sender = AllowedSender(
        email=request.email,
        domain=request.email.split("@")[1],
        user_id=user_id,
        reason=request.reason
    )
    
    sender_id = await db_client.add_allowed_sender(sender)
    return {"id": sender_id, "message": "Sender added to allowed list"}

@app.get("/api/senders/blocked")
async def get_blocked_senders(user_id: str = Depends(get_current_user)):
    # Implementation would fetch from database
    return []

@app.post("/api/senders/blocked")
async def add_blocked_sender(
    request: BlockedSenderRequest,
    user_id: str = Depends(get_current_user)
):
    if not request.email and not request.domain:
        raise HTTPException(status_code=400, detail="Either email or domain required")
    
    sender = BlockedSender(
        email=request.email,
        domain=request.domain,
        user_id=user_id,
        reason=request.reason
    )
    
    sender_id = await db_client.add_blocked_sender(sender)
    return {"id": sender_id, "message": "Sender added to blocked list"}

# Manual email scanning endpoint
@app.post("/api/scan")
async def manual_scan(
    background_tasks: BackgroundTasks,
    user_id: str = Depends(get_current_user)
):
    background_tasks.add_task(scan_user_inbox, user_id)
    return {"message": "Scan initiated"}

async def scan_user_inbox(user_id: str):
    try:
        emails = await quarantine_manager.gmail_client.fetch_emails(
            query="is:unread",
            max_results=50
        )
        
        for email_data in emails:
            await quarantine_manager.process_incoming_email(email_data, user_id)
        
        logger.info(f"Scanned {len(emails)} emails for user {user_id}")
    except Exception as e:
        logger.error(f"Scan failed for user {user_id}: {e}")

# Admin endpoints
@app.get("/api/admin/patterns", response_model=List[SpamPattern])
async def get_spam_patterns(user_id: str = Depends(get_current_user)):
    # Check if user is admin (implementation needed)
    patterns = await db_client.get_spam_patterns()
    return patterns

@app.post("/api/admin/patterns")
async def add_spam_pattern(
    pattern: SpamPattern,
    user_id: str = Depends(get_current_user)
):
    # Check if user is admin (implementation needed)
    # Save pattern to database
    return {"message": "Pattern added"}

# Health check
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": config.VERSION
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)