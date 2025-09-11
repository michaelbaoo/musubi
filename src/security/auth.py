import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from loguru import logger
import secrets
import hashlib
from ..core.config import config
from .encryption import EncryptionManager

class AuthManager:
    def __init__(self):
        self.encryption = EncryptionManager()
        self.secret_key = config.JWT_SECRET_KEY or self._generate_secret_key()
        self.algorithm = config.JWT_ALGORITHM
        self.expiration_hours = config.JWT_EXPIRATION_HOURS
        
        # In-memory user store (replace with database in production)
        self.users = {}
    
    def _generate_secret_key(self) -> str:
        key = secrets.token_urlsafe(32)
        logger.warning(f"Generated JWT secret key: {key}")
        logger.warning("Set JWT_SECRET_KEY environment variable in production")
        return key
    
    def create_access_token(self, user_id: str) -> str:
        payload = {
            "sub": user_id,
            "exp": datetime.utcnow() + timedelta(hours=self.expiration_hours),
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def create_refresh_token(self, user_id: str) -> str:
        payload = {
            "sub": user_id,
            "exp": datetime.utcnow() + timedelta(days=30),
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    async def register_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        # Check if user exists
        if email in self.users:
            logger.warning(f"User {email} already exists")
            return None
        
        # Hash password
        hashed_password = self.encryption.hash_password(password)
        
        # Create user
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        user = {
            "id": user_id,
            "email": email,
            "password": hashed_password,
            "created_at": datetime.utcnow().isoformat(),
            "is_active": True,
            "is_admin": False
        }
        
        self.users[email] = user
        logger.info(f"User {email} registered successfully")
        
        # Return user without password
        return {k: v for k, v in user.items() if k != "password"}
    
    async def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        # Get user
        user = self.users.get(email)
        if not user:
            logger.warning(f"User {email} not found")
            return None
        
        # Verify password
        if not self.encryption.verify_password(password, user["password"]):
            logger.warning(f"Invalid password for user {email}")
            return None
        
        # Return user without password
        return {k: v for k, v in user.items() if k != "password"}
    
    def generate_api_key(self, user_id: str) -> str:
        # Generate secure API key
        api_key = secrets.token_urlsafe(32)
        
        # Store API key (in production, store in database with user_id)
        # For now, we'll just return it
        
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[str]:
        # In production, look up API key in database
        # Return associated user_id if valid
        
        # Placeholder implementation
        return None
    
    def create_session_token(self, user_id: str) -> str:
        session_id = secrets.token_urlsafe(32)
        
        # Store session (in production, use Redis or database)
        # Include expiration, user_id, created_at, etc.
        
        return session_id
    
    def validate_session(self, session_token: str) -> Optional[str]:
        # In production, look up session in Redis/database
        # Check if expired, return user_id if valid
        
        # Placeholder implementation
        return None
    
    def revoke_token(self, token: str):
        # In production, add token to blacklist in Redis
        # Check blacklist when validating tokens
        pass
    
    def generate_2fa_code(self, user_id: str) -> str:
        # Generate 6-digit code
        code = str(secrets.randbelow(999999)).zfill(6)
        
        # Store code with expiration (in production, use Redis)
        # For now, just return it
        
        return code
    
    def verify_2fa_code(self, user_id: str, code: str) -> bool:
        # In production, check stored code in Redis
        # Verify not expired and matches
        
        # Placeholder implementation
        return False