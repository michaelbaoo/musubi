import os
from typing import Dict, List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings
from enum import Enum

class EmailProvider(str, Enum):
    GMAIL = "gmail"
    OUTLOOK = "outlook"
    IMAP = "imap"
    EXCHANGE = "exchange"

class SpamAction(str, Enum):
    QUARANTINE = "quarantine"
    DELETE = "delete"
    ALLOW = "allow"
    BLOCK_SENDER = "block_sender"
    MARK_SPAM = "mark_spam"

class Config(BaseSettings):
    APP_NAME: str = "Email Spam Quarantine System"
    VERSION: str = "1.0.0"
    
    API_HOST: str = Field(default="0.0.0.0", env="API_HOST")
    API_PORT: int = Field(default=8000, env="API_PORT")
    
    MONGODB_URL: str = Field(default="mongodb://localhost:27017", env="MONGODB_URL")
    MONGODB_DB_NAME: str = Field(default="spam_quarantine", env="MONGODB_DB_NAME")
    
    REDIS_URL: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    
    JWT_SECRET_KEY: str = Field(default="", env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = Field(default="HS256", env="JWT_ALGORITHM")
    JWT_EXPIRATION_HOURS: int = Field(default=24, env="JWT_EXPIRATION_HOURS")
    
    ENCRYPTION_KEY: str = Field(default="", env="ENCRYPTION_KEY")
    
    ML_MODEL_PATH: str = Field(default="models/spam_detector.pkl", env="ML_MODEL_PATH")
    TRANSFORMER_MODEL: str = Field(default="bert-base-uncased", env="TRANSFORMER_MODEL")
    
    SPAM_THRESHOLD: float = Field(default=0.7, env="SPAM_THRESHOLD")
    AUTO_LEARN: bool = Field(default=True, env="AUTO_LEARN")
    
    QUARANTINE_DAYS: int = Field(default=30, env="QUARANTINE_DAYS")
    MAX_EMAIL_SIZE_MB: int = Field(default=25, env="MAX_EMAIL_SIZE_MB")
    
    BATCH_SIZE: int = Field(default=100, env="BATCH_SIZE")
    SCAN_INTERVAL_MINUTES: int = Field(default=5, env="SCAN_INTERVAL_MINUTES")
    
    ALLOWED_DOMAINS: List[str] = Field(default_factory=list, env="ALLOWED_DOMAINS")
    BLOCKED_DOMAINS: List[str] = Field(default_factory=list, env="BLOCKED_DOMAINS")
    
    ENABLE_CONTENT_SCANNING: bool = Field(default=True, env="ENABLE_CONTENT_SCANNING")
    ENABLE_ATTACHMENT_SCANNING: bool = Field(default=True, env="ENABLE_ATTACHMENT_SCANNING")
    ENABLE_URL_CHECKING: bool = Field(default=True, env="ENABLE_URL_CHECKING")
    ENABLE_SPF_CHECKING: bool = Field(default=True, env="ENABLE_SPF_CHECKING")
    ENABLE_DKIM_CHECKING: bool = Field(default=True, env="ENABLE_DKIM_CHECKING")
    
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FILE: str = Field(default="logs/spam_quarantine.log", env="LOG_FILE")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

    def get_detection_criteria(self) -> Dict[str, bool]:
        return {
            "content_scanning": self.ENABLE_CONTENT_SCANNING,
            "attachment_scanning": self.ENABLE_ATTACHMENT_SCANNING,
            "url_checking": self.ENABLE_URL_CHECKING,
            "spf_checking": self.ENABLE_SPF_CHECKING,
            "dkim_checking": self.ENABLE_DKIM_CHECKING
        }

config = Config()