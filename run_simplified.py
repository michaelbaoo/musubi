#!/usr/bin/env python
"""
Simplified launcher for the Email Spam Quarantine API
This version runs without ML dependencies for initial testing
"""
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from loguru import logger

# Create simplified FastAPI app
app = FastAPI(title="Email Spam Quarantine API (Simplified)", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "Email Spam Quarantine System - Simplified Version",
        "status": "running",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "mode": "simplified"
    }

@app.get("/api/quarantine/emails")
async def get_quarantined_emails():
    """Mock endpoint for quarantined emails"""
    return [
        {
            "id": "1",
            "sender": "spam@example.com",
            "subject": "Win Free Money!",
            "spam_score": 0.95,
            "threat_level": "high",
            "quarantine_date": datetime.utcnow().isoformat(),
            "status": "quarantined"
        },
        {
            "id": "2",
            "sender": "phishing@fake.com",
            "subject": "Update Your Account",
            "spam_score": 0.88,
            "threat_level": "high",
            "quarantine_date": datetime.utcnow().isoformat(),
            "status": "quarantined"
        }
    ]

@app.get("/api/quarantine/statistics")
async def get_statistics():
    """Mock endpoint for statistics"""
    return {
        "total_quarantined": 42,
        "by_threat_level": {
            "critical": 5,
            "high": 12,
            "medium": 15,
            "low": 10
        },
        "average_spam_score": 0.72,
        "last_scan": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/login")
async def login(request: dict):
    """Mock login endpoint"""
    email = request.get("email")
    password = request.get("password")
    
    if email and password:
        return {
            "access_token": "mock_token_12345",
            "token_type": "bearer",
            "user": {
                "id": "user_1",
                "email": email
            }
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "message": str(exc)}
    )

if __name__ == "__main__":
    logger.info("Starting Email Spam Quarantine API (Simplified Version)")
    logger.info("Access the API at http://localhost:8000")
    logger.info("API Documentation at http://localhost:8000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)