from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import asyncio
from loguru import logger
from ..core.config import config
from .models import (
    QuarantinedEmail, AllowedSender, BlockedSender,
    SpamPattern, UserPreferences, EmailSummary, AuditLog
)

class MongoDBClient:
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        
    async def connect(self):
        try:
            self.client = AsyncIOMotorClient(config.MONGODB_URL)
            self.db = self.client[config.MONGODB_DB_NAME]
            
            await self._create_indexes()
            logger.info("Connected to MongoDB successfully")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    async def disconnect(self):
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
    
    async def _create_indexes(self):
        collections_indexes = {
            "quarantined_emails": [
                ("user_id", 1),
                ("message_id", 1),
                ("sender", 1),
                ("status", 1),
                ("quarantine_date", -1),
                ("spam_score", -1)
            ],
            "allowed_senders": [
                ("email", 1),
                ("domain", 1),
                ("user_id", 1)
            ],
            "blocked_senders": [
                ("email", 1),
                ("domain", 1),
                ("user_id", 1)
            ],
            "spam_patterns": [
                ("pattern_type", 1),
                ("active", 1)
            ],
            "user_preferences": [
                ("user_id", 1),
                ("email", 1)
            ],
            "audit_logs": [
                ("user_id", 1),
                ("timestamp", -1)
            ]
        }
        
        for collection_name, indexes in collections_indexes.items():
            collection = self.db[collection_name]
            for index in indexes:
                await collection.create_index([index])
    
    async def save_quarantined_email(self, email: QuarantinedEmail) -> str:
        collection = self.db.quarantined_emails
        email_dict = email.dict(by_alias=True, exclude_unset=True)
        
        if not email.expiry_date:
            email_dict["expiry_date"] = datetime.utcnow() + timedelta(days=config.QUARANTINE_DAYS)
        
        result = await collection.insert_one(email_dict)
        return str(result.inserted_id)
    
    async def get_quarantined_emails(
        self,
        user_id: str,
        status: Optional[str] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[QuarantinedEmail]:
        collection = self.db.quarantined_emails
        
        query = {"user_id": user_id}
        if status:
            query["status"] = status
        
        cursor = collection.find(query).sort("quarantine_date", -1).skip(skip).limit(limit)
        emails = []
        
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            emails.append(QuarantinedEmail(**doc))
        
        return emails
    
    async def update_email_status(
        self,
        email_id: str,
        status: str,
        action_taken: Optional[str] = None
    ) -> bool:
        collection = self.db.quarantined_emails
        
        update_data = {
            "status": status,
            "review_date": datetime.utcnow()
        }
        
        if action_taken:
            update_data["action_taken"] = action_taken
        
        result = await collection.update_one(
            {"_id": email_id},
            {"$set": update_data}
        )
        
        return result.modified_count > 0
    
    async def add_allowed_sender(self, sender: AllowedSender) -> str:
        collection = self.db.allowed_senders
        
        existing = await collection.find_one({
            "email": sender.email,
            "user_id": sender.user_id
        })
        
        if existing:
            return str(existing["_id"])
        
        result = await collection.insert_one(sender.dict(by_alias=True, exclude_unset=True))
        return str(result.inserted_id)
    
    async def add_blocked_sender(self, sender: BlockedSender) -> str:
        collection = self.db.blocked_senders
        
        query = {"user_id": sender.user_id}
        if sender.email:
            query["email"] = sender.email
        if sender.domain:
            query["domain"] = sender.domain
        
        existing = await collection.find_one(query)
        
        if existing:
            await collection.update_one(
                {"_id": existing["_id"]},
                {"$inc": {"block_count": 1}}
            )
            return str(existing["_id"])
        
        result = await collection.insert_one(sender.dict(by_alias=True, exclude_unset=True))
        return str(result.inserted_id)
    
    async def is_sender_allowed(self, email: str, user_id: str) -> bool:
        collection = self.db.allowed_senders
        domain = email.split("@")[1] if "@" in email else None
        
        query = {
            "user_id": user_id,
            "$or": [
                {"email": email},
                {"domain": domain}
            ]
        }
        
        result = await collection.find_one(query)
        return result is not None
    
    async def is_sender_blocked(self, email: str, user_id: str) -> bool:
        collection = self.db.blocked_senders
        domain = email.split("@")[1] if "@" in email else None
        
        query = {
            "user_id": user_id,
            "$or": [
                {"email": email},
                {"domain": domain}
            ]
        }
        
        result = await collection.find_one(query)
        return result is not None
    
    async def get_spam_patterns(self, active_only: bool = True) -> List[SpamPattern]:
        collection = self.db.spam_patterns
        
        query = {"active": True} if active_only else {}
        cursor = collection.find(query)
        
        patterns = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            patterns.append(SpamPattern(**doc))
        
        return patterns
    
    async def update_pattern_match(self, pattern_id: str):
        collection = self.db.spam_patterns
        
        await collection.update_one(
            {"_id": pattern_id},
            {
                "$set": {"last_matched": datetime.utcnow()},
                "$inc": {"match_count": 1}
            }
        )
    
    async def get_user_preferences(self, user_id: str) -> Optional[UserPreferences]:
        collection = self.db.user_preferences
        
        doc = await collection.find_one({"user_id": user_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            return UserPreferences(**doc)
        
        return None
    
    async def save_user_preferences(self, preferences: UserPreferences) -> str:
        collection = self.db.user_preferences
        
        preferences.updated_date = datetime.utcnow()
        prefs_dict = preferences.dict(by_alias=True, exclude_unset=True)
        
        result = await collection.replace_one(
            {"user_id": preferences.user_id},
            prefs_dict,
            upsert=True
        )
        
        return str(result.upserted_id) if result.upserted_id else preferences.user_id
    
    async def save_email_summary(self, summary: EmailSummary) -> str:
        collection = self.db.email_summaries
        result = await collection.insert_one(summary.dict(exclude_unset=True))
        return str(result.inserted_id)
    
    async def get_email_summary(self, email_id: str) -> Optional[EmailSummary]:
        collection = self.db.email_summaries
        
        doc = await collection.find_one({"email_id": email_id})
        if doc:
            return EmailSummary(**doc)
        
        return None
    
    async def log_audit(self, log: AuditLog) -> str:
        collection = self.db.audit_logs
        result = await collection.insert_one(log.dict(by_alias=True, exclude_unset=True))
        return str(result.inserted_id)
    
    async def cleanup_expired_emails(self) -> int:
        collection = self.db.quarantined_emails
        
        result = await collection.delete_many({
            "expiry_date": {"$lt": datetime.utcnow()},
            "status": "quarantined"
        })
        
        return result.deleted_count
    
    async def get_statistics(self, user_id: str) -> Dict[str, Any]:
        collection = self.db.quarantined_emails
        
        pipeline = [
            {"$match": {"user_id": user_id}},
            {
                "$group": {
                    "_id": "$status",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        cursor = collection.aggregate(pipeline)
        stats = {"total": 0}
        
        async for doc in cursor:
            stats[doc["_id"]] = doc["count"]
            stats["total"] += doc["count"]
        
        return stats

db_client = MongoDBClient()