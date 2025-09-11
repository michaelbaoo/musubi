import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import hashlib
# from transformers import pipeline  # Commented out for initial launch

from ..database.mongodb_client import db_client
from ..database.models import (
    QuarantinedEmail, EmailStatus, EmailSummary,
    AllowedSender, BlockedSender, AuditLog, UserPreferences
)
from ..integrations.gmail_integration import GmailIntegration
from .spam_engine import SpamDetectionEngine
from .config import config

class QuarantineManager:
    def __init__(self):
        self.spam_engine = SpamDetectionEngine()
        self.gmail_client = GmailIntegration()
        self.summarizer = None
        self._initialize_summarizer()
    
    def _initialize_summarizer(self):
        # Disabled for initial launch - transformers not installed
        self.summarizer = None
        logger.info("Email summarizer disabled (transformers not installed)")
    
    async def process_incoming_email(
        self,
        email_data: Dict[str, Any],
        user_id: str
    ) -> QuarantinedEmail:
        
        # Get user preferences
        preferences = await db_client.get_user_preferences(user_id)
        if not preferences:
            preferences = UserPreferences(user_id=user_id, email=email_data['recipient'])
            await db_client.save_user_preferences(preferences)
        
        # Check if sender is allowed/blocked
        if await db_client.is_sender_allowed(email_data['sender'], user_id):
            logger.info(f"Sender {email_data['sender']} is allowed for user {user_id}")
            email_data['spam_score'] = 0.0
        elif await db_client.is_sender_blocked(email_data['sender'], user_id):
            logger.info(f"Sender {email_data['sender']} is blocked for user {user_id}")
            email_data['spam_score'] = 1.0
        
        # Analyze email for spam
        quarantined_email = await self.spam_engine.analyze_email(
            message_id=email_data['message_id'],
            sender=email_data['sender'],
            recipient=email_data['recipient'],
            subject=email_data['subject'],
            body=email_data['body'],
            headers=email_data['headers'],
            attachments=email_data.get('attachments', []),
            user_id=user_id
        )
        
        # Apply user preferences
        if quarantined_email.spam_score >= preferences.spam_threshold:
            if preferences.auto_delete_spam and quarantined_email.spam_score >= 0.9:
                quarantined_email.status = EmailStatus.DELETED
                await self.gmail_client.delete_email(email_data['message_id'])
            else:
                quarantined_email.status = EmailStatus.QUARANTINED
                await self.gmail_client.move_to_quarantine(email_data['message_id'])
        
        # Save to database
        email_id = await db_client.save_quarantined_email(quarantined_email)
        quarantined_email.id = email_id
        
        # Generate summary if quarantined
        if quarantined_email.status == EmailStatus.QUARANTINED:
            summary = await self.generate_email_summary(quarantined_email)
            await db_client.save_email_summary(summary)
        
        # Log the action
        await self._log_action(
            user_id=user_id,
            action=f"Email {quarantined_email.status}",
            email_id=email_id,
            details={
                'sender': email_data['sender'],
                'spam_score': quarantined_email.spam_score,
                'threat_level': quarantined_email.threat_level
            }
        )
        
        # Send notification if high risk
        if preferences.notify_high_risk and quarantined_email.threat_level in ['high', 'critical']:
            await self._send_high_risk_notification(user_id, quarantined_email)
        
        return quarantined_email
    
    async def generate_email_summary(self, email: QuarantinedEmail) -> EmailSummary:
        summary_text = "Email flagged as potential spam"
        key_points = []
        
        if self.summarizer and len(email.body_preview) > 100:
            try:
                result = self.summarizer(
                    email.body_preview,
                    max_length=100,
                    min_length=30,
                    do_sample=False
                )
                summary_text = result[0]['summary_text']
            except:
                pass
        
        # Extract key points from detection reasons
        for reason in email.detection_reasons[:5]:
            key_points.append(reason)
        
        # Generate recommendation
        if email.spam_score >= 0.9:
            recommendation = "BLOCK: High confidence spam, recommend permanent blocking"
        elif email.spam_score >= 0.7:
            recommendation = "QUARANTINE: Likely spam, review before allowing"
        elif email.spam_score >= 0.5:
            recommendation = "REVIEW: Suspicious content, manual review recommended"
        else:
            recommendation = "ALLOW: Low spam probability, likely safe"
        
        return EmailSummary(
            email_id=email.id,
            original_subject=email.subject,
            sender=email.sender,
            summary=summary_text,
            key_points=key_points,
            detected_threats=email.detection_reasons,
            recommendation=recommendation
        )
    
    async def review_quarantined_email(
        self,
        email_id: str,
        user_id: str,
        action: str,
        reason: Optional[str] = None
    ) -> bool:
        
        # Validate action
        valid_actions = ['allow', 'block', 'delete', 'release']
        if action not in valid_actions:
            logger.error(f"Invalid action: {action}")
            return False
        
        # Get email from database
        emails = await db_client.get_quarantined_emails(user_id, limit=1)
        email = next((e for e in emails if e.id == email_id), None)
        
        if not email:
            logger.error(f"Email {email_id} not found")
            return False
        
        success = False
        
        if action == 'allow':
            # Add sender to allowed list
            allowed = AllowedSender(
                email=email.sender,
                domain=email.sender.split('@')[1],
                user_id=user_id,
                reason=reason or "Manual review"
            )
            await db_client.add_allowed_sender(allowed)
            
            # Release from quarantine
            success = await self.gmail_client.release_from_quarantine(email.message_id)
            await db_client.update_email_status(email_id, EmailStatus.ALLOWED, action)
            
        elif action == 'block':
            # Add sender to blocked list
            blocked = BlockedSender(
                email=email.sender,
                domain=email.sender.split('@')[1],
                user_id=user_id,
                reason=reason or "Manual review"
            )
            await db_client.add_blocked_sender(blocked)
            
            # Delete email
            success = await self.gmail_client.delete_email(email.message_id)
            await db_client.update_email_status(email_id, EmailStatus.BLOCKED, action)
            
        elif action == 'delete':
            # Permanently delete
            success = await self.gmail_client.delete_email(email.message_id)
            await db_client.update_email_status(email_id, EmailStatus.DELETED, action)
            
        elif action == 'release':
            # Just release without adding to allowed list
            success = await self.gmail_client.release_from_quarantine(email.message_id)
            await db_client.update_email_status(email_id, EmailStatus.ALLOWED, action)
        
        # Log the action
        await self._log_action(
            user_id=user_id,
            action=f"Manual review: {action}",
            email_id=email_id,
            details={'reason': reason}
        )
        
        # Update ML model if feedback provided
        if config.AUTO_LEARN and action in ['allow', 'block']:
            label = 0 if action == 'allow' else 1
            await self._update_training_data(email, label)
        
        return success
    
    async def bulk_review(
        self,
        user_id: str,
        email_ids: List[str],
        action: str
    ) -> Dict[str, bool]:
        
        results = {}
        
        for email_id in email_ids:
            try:
                success = await self.review_quarantined_email(
                    email_id, user_id, action, "Bulk action"
                )
                results[email_id] = success
            except Exception as e:
                logger.error(f"Error processing {email_id}: {e}")
                results[email_id] = False
        
        return results
    
    async def get_quarantine_summary(
        self,
        user_id: str,
        days: int = 7
    ) -> Dict[str, Any]:
        
        # Get recent emails
        emails = await db_client.get_quarantined_emails(
            user_id,
            status=EmailStatus.QUARANTINED,
            limit=1000
        )
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        recent_emails = [e for e in emails if e.quarantine_date >= cutoff_date]
        
        # Calculate statistics
        stats = {
            'total_quarantined': len(recent_emails),
            'by_threat_level': {},
            'top_senders': {},
            'by_day': {},
            'average_spam_score': 0,
            'detection_reasons': {}
        }
        
        if recent_emails:
            # By threat level
            for email in recent_emails:
                level = email.threat_level
                stats['by_threat_level'][level] = stats['by_threat_level'].get(level, 0) + 1
                
                # Top senders
                sender = email.sender
                stats['top_senders'][sender] = stats['top_senders'].get(sender, 0) + 1
                
                # By day
                day = email.quarantine_date.strftime('%Y-%m-%d')
                stats['by_day'][day] = stats['by_day'].get(day, 0) + 1
                
                # Detection reasons
                for reason in email.detection_reasons:
                    stats['detection_reasons'][reason] = stats['detection_reasons'].get(reason, 0) + 1
            
            # Average spam score
            stats['average_spam_score'] = sum(e.spam_score for e in recent_emails) / len(recent_emails)
            
            # Sort and limit top senders
            stats['top_senders'] = dict(
                sorted(stats['top_senders'].items(), key=lambda x: x[1], reverse=True)[:10]
            )
            
            # Sort detection reasons
            stats['detection_reasons'] = dict(
                sorted(stats['detection_reasons'].items(), key=lambda x: x[1], reverse=True)[:10]
            )
        
        return stats
    
    async def cleanup_expired_emails(self) -> int:
        count = await db_client.cleanup_expired_emails()
        logger.info(f"Cleaned up {count} expired emails")
        return count
    
    async def _log_action(
        self,
        user_id: str,
        action: str,
        email_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        log = AuditLog(
            user_id=user_id,
            action=action,
            email_id=email_id,
            details=details or {}
        )
        await db_client.log_audit(log)
    
    async def _send_high_risk_notification(
        self,
        user_id: str,
        email: QuarantinedEmail
    ):
        preferences = await db_client.get_user_preferences(user_id)
        if not preferences or not preferences.notification_email:
            return
        
        subject = f"High Risk Email Detected: {email.subject[:50]}"
        
        body = f"""
        <html>
        <body>
            <h2>High Risk Email Quarantined</h2>
            <p>A potentially dangerous email has been quarantined.</p>
            
            <h3>Email Details:</h3>
            <ul>
                <li><strong>From:</strong> {email.sender}</li>
                <li><strong>Subject:</strong> {email.subject}</li>
                <li><strong>Threat Level:</strong> {email.threat_level}</li>
                <li><strong>Spam Score:</strong> {email.spam_score:.2%}</li>
            </ul>
            
            <h3>Detection Reasons:</h3>
            <ul>
                {''.join(f'<li>{reason}</li>' for reason in email.detection_reasons[:5])}
            </ul>
            
            <p>Please review this email in your quarantine dashboard.</p>
        </body>
        </html>
        """
        
        await self.gmail_client.send_notification(
            preferences.notification_email,
            subject,
            body
        )
    
    async def _update_training_data(self, email: QuarantinedEmail, label: int):
        # This would be implemented to retrain the ML model
        # with user feedback for continuous improvement
        pass
    
    async def scan_inbox_periodically(self, user_id: str):
        while True:
            try:
                logger.info(f"Starting inbox scan for user {user_id}")
                
                # Fetch recent emails
                emails = await self.gmail_client.fetch_emails(
                    query="is:unread",
                    max_results=config.BATCH_SIZE
                )
                
                # Process each email
                for email_data in emails:
                    await self.process_incoming_email(email_data, user_id)
                
                logger.info(f"Processed {len(emails)} emails")
                
            except Exception as e:
                logger.error(f"Error in periodic scan: {e}")
            
            # Wait for next scan
            await asyncio.sleep(config.SCAN_INTERVAL_MINUTES * 60)