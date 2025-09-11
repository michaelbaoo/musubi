from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from enum import Enum
import hashlib

class EmailStatus(str, Enum):
    QUARANTINED = "quarantined"
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    DELETED = "deleted"
    PENDING_REVIEW = "pending_review"

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class QuarantinedEmail(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    message_id: str
    user_id: str
    sender: EmailStr
    recipient: EmailStr
    subject: str
    body_preview: str
    body_hash: str
    attachments: List[Dict[str, Any]] = []
    headers: Dict[str, str] = {}
    
    spam_score: float
    threat_level: ThreatLevel
    detection_reasons: List[str] = []
    
    status: EmailStatus = EmailStatus.QUARANTINED
    quarantine_date: datetime = Field(default_factory=datetime.utcnow)
    expiry_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    action_taken: Optional[str] = None
    
    size_bytes: int
    has_attachments: bool = False
    attachment_types: List[str] = []
    
    spf_pass: bool = False
    dkim_pass: bool = False
    dmarc_pass: bool = False
    
    encrypted_content: Optional[str] = None
    
    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "message_id": "abc123@gmail.com",
                "sender": "spammer@malicious.com",
                "subject": "You've won $1,000,000!",
                "spam_score": 0.95,
                "threat_level": "high"
            }
        }

class AllowedSender(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    email: EmailStr
    domain: str
    user_id: str
    added_date: datetime = Field(default_factory=datetime.utcnow)
    reason: Optional[str] = None
    auto_added: bool = False
    
class BlockedSender(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    email: Optional[EmailStr] = None
    domain: Optional[str] = None
    user_id: str
    blocked_date: datetime = Field(default_factory=datetime.utcnow)
    reason: str
    auto_blocked: bool = False
    block_count: int = 1

class SpamPattern(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    pattern_type: str  # keyword, regex, header, url
    pattern_value: str
    weight: float = 1.0
    description: str
    active: bool = True
    created_date: datetime = Field(default_factory=datetime.utcnow)
    last_matched: Optional[datetime] = None
    match_count: int = 0
    
class UserPreferences(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    email: EmailStr
    
    auto_delete_spam: bool = False
    quarantine_days: int = 30
    spam_threshold: float = 0.7
    
    daily_digest: bool = True
    digest_time: str = "09:00"
    
    allowed_domains: List[str] = []
    blocked_domains: List[str] = []
    
    scan_attachments: bool = True
    scan_urls: bool = True
    check_spf: bool = True
    check_dkim: bool = True
    
    notification_email: Optional[EmailStr] = None
    notify_high_risk: bool = True
    
    created_date: datetime = Field(default_factory=datetime.utcnow)
    updated_date: datetime = Field(default_factory=datetime.utcnow)

class EmailSummary(BaseModel):
    email_id: str
    original_subject: str
    sender: EmailStr
    summary: str
    key_points: List[str]
    detected_threats: List[str]
    recommendation: str
    generated_date: datetime = Field(default_factory=datetime.utcnow)

class AuditLog(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    action: str
    email_id: Optional[str] = None
    details: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class MLModelMetadata(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    model_name: str
    version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_date: datetime
    training_samples: int
    active: bool = True
    model_path: str
    features_used: List[str] = []