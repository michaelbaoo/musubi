from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
import hashlib
import re
from urllib.parse import urlparse
from loguru import logger
import asyncio
import aiohttp
from bs4 import BeautifulSoup

from ..detectors.ml_detector import MLSpamDetector
from ..database.models import (
    QuarantinedEmail, SpamPattern, ThreatLevel, EmailStatus
)
from ..database.mongodb_client import db_client
from .config import config

class SpamDetectionEngine:
    def __init__(self):
        self.ml_detector = MLSpamDetector(config.ML_MODEL_PATH)
        self.spam_patterns: List[SpamPattern] = []
        self.url_blacklist_cache = set()
        self.phishing_domains = set()
        self._load_threat_intelligence()
    
    def _load_threat_intelligence(self):
        self.phishing_domains = {
            'phishing-example.com', 'malware-site.org', 'scam-domain.net',
            'fake-bank.com', 'phishing-paypal.net', 'amazon-phishing.org'
        }
        
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review'}
        
        self.malicious_ip_ranges = [
            '192.0.2.0/24',  # Example ranges
            '198.51.100.0/24',
            '203.0.113.0/24'
        ]
    
    async def load_spam_patterns(self):
        self.spam_patterns = await db_client.get_spam_patterns(active_only=True)
        logger.info(f"Loaded {len(self.spam_patterns)} spam patterns")
    
    def calculate_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def check_url_reputation(self, urls: List[str]) -> Tuple[bool, List[str]]:
        threats_found = []
        
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if domain in self.phishing_domains:
                threats_found.append(f"Known phishing domain: {domain}")
            
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    threats_found.append(f"Suspicious TLD: {tld}")
            
            if domain in self.url_blacklist_cache:
                threats_found.append(f"Blacklisted URL: {url}")
        
        return len(threats_found) > 0, threats_found
    
    def check_spf_dkim(self, headers: Dict[str, str]) -> Dict[str, bool]:
        results = {
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False
        }
        
        if 'Authentication-Results' in headers:
            auth_results = headers['Authentication-Results'].lower()
            results['spf_pass'] = 'spf=pass' in auth_results
            results['dkim_pass'] = 'dkim=pass' in auth_results
            results['dmarc_pass'] = 'dmarc=pass' in auth_results
        
        if 'Received-SPF' in headers:
            results['spf_pass'] = 'pass' in headers['Received-SPF'].lower()
        
        return results
    
    def check_header_anomalies(self, headers: Dict[str, str]) -> List[str]:
        anomalies = []
        
        if 'From' in headers and 'Return-Path' in headers:
            from_domain = headers['From'].split('@')[-1].strip('>')
            return_domain = headers['Return-Path'].split('@')[-1].strip('>')
            if from_domain != return_domain:
                anomalies.append("From and Return-Path domains don't match")
        
        if 'Date' in headers:
            try:
                email_date = datetime.strptime(headers['Date'][:24], '%a, %d %b %Y %H:%M:%S')
                if abs((datetime.utcnow() - email_date).days) > 7:
                    anomalies.append("Email date is suspicious (too old or future dated)")
            except:
                anomalies.append("Invalid date format in headers")
        
        suspicious_headers = ['X-Spam-Flag', 'X-Spam-Score', 'X-Virus-Scanned']
        for header in suspicious_headers:
            if header in headers and 'yes' in headers[header].lower():
                anomalies.append(f"Suspicious header: {header}")
        
        return anomalies
    
    def check_attachment_threats(self, attachments: List[Dict[str, Any]]) -> List[str]:
        threats = []
        dangerous_extensions = [
            '.exe', '.scr', '.vbs', '.js', '.pif', '.cmd', '.bat',
            '.com', '.jar', '.zip', '.rar', '.iso', '.dmg'
        ]
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    threats.append(f"Dangerous attachment type: {ext}")
            
            if filename.count('.') > 2:
                threats.append(f"Suspicious filename with multiple extensions: {filename}")
            
            size = attachment.get('size', 0)
            if size > 50 * 1024 * 1024:  # 50MB
                threats.append(f"Large attachment: {size / (1024*1024):.1f}MB")
        
        return threats
    
    def apply_pattern_matching(self, content: str, subject: str) -> Tuple[float, List[str]]:
        score = 0.0
        matches = []
        
        full_text = f"{subject} {content}".lower()
        
        for pattern in self.spam_patterns:
            if pattern.pattern_type == 'keyword':
                if pattern.pattern_value.lower() in full_text:
                    score += pattern.weight
                    matches.append(f"Keyword match: {pattern.pattern_value}")
            
            elif pattern.pattern_type == 'regex':
                try:
                    if re.search(pattern.pattern_value, full_text, re.IGNORECASE):
                        score += pattern.weight
                        matches.append(f"Pattern match: {pattern.description}")
                except:
                    continue
        
        return min(score, 1.0), matches
    
    def determine_threat_level(self, spam_score: float, threats: List[str]) -> ThreatLevel:
        if spam_score >= 0.9 or len(threats) > 5:
            return ThreatLevel.CRITICAL
        elif spam_score >= 0.7 or len(threats) > 3:
            return ThreatLevel.HIGH
        elif spam_score >= 0.5 or len(threats) > 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    async def analyze_email(
        self,
        message_id: str,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        headers: Dict[str, str],
        attachments: List[Dict[str, Any]] = None,
        user_id: str = None
    ) -> QuarantinedEmail:
        
        logger.info(f"Analyzing email from {sender} to {recipient}")
        
        detection_reasons = []
        cumulative_score = 0.0
        
        # Check sender reputation
        if user_id:
            is_blocked = await db_client.is_sender_blocked(sender, user_id)
            if is_blocked:
                detection_reasons.append("Sender is blocked")
                cumulative_score = 1.0
            
            is_allowed = await db_client.is_sender_allowed(sender, user_id)
            if is_allowed:
                cumulative_score = max(0, cumulative_score - 0.5)
        
        # ML-based detection
        if config.ENABLE_CONTENT_SCANNING:
            ml_score, ml_reasons, ml_details = self.ml_detector.detect_spam(
                body, subject, headers, use_bert=True
            )
            cumulative_score = max(cumulative_score, ml_score)
            detection_reasons.extend(ml_reasons)
        
        # Pattern matching
        pattern_score, pattern_matches = self.apply_pattern_matching(body, subject)
        if pattern_score > 0:
            cumulative_score = max(cumulative_score, pattern_score)
            detection_reasons.extend(pattern_matches)
        
        # URL checking
        if config.ENABLE_URL_CHECKING:
            urls = re.findall(r'https?://\S+', body)
            if urls:
                has_threats, url_threats = await self.check_url_reputation(urls)
                if has_threats:
                    cumulative_score += 0.3
                    detection_reasons.extend(url_threats)
        
        # SPF/DKIM checking
        if config.ENABLE_SPF_CHECKING or config.ENABLE_DKIM_CHECKING:
            auth_results = self.check_spf_dkim(headers)
            if not auth_results['spf_pass']:
                detection_reasons.append("SPF check failed")
                cumulative_score += 0.2
            if not auth_results['dkim_pass']:
                detection_reasons.append("DKIM check failed")
                cumulative_score += 0.2
        else:
            auth_results = {'spf_pass': False, 'dkim_pass': False, 'dmarc_pass': False}
        
        # Header anomalies
        header_anomalies = self.check_header_anomalies(headers)
        if header_anomalies:
            detection_reasons.extend(header_anomalies)
            cumulative_score += 0.1 * len(header_anomalies)
        
        # Attachment scanning
        attachment_threats = []
        if attachments and config.ENABLE_ATTACHMENT_SCANNING:
            attachment_threats = self.check_attachment_threats(attachments)
            if attachment_threats:
                detection_reasons.extend(attachment_threats)
                cumulative_score += 0.3
        
        # Normalize score
        final_score = min(1.0, cumulative_score)
        
        # Determine threat level
        threat_level = self.determine_threat_level(final_score, detection_reasons)
        
        # Determine status
        if final_score >= config.SPAM_THRESHOLD:
            status = EmailStatus.QUARANTINED
        else:
            status = EmailStatus.ALLOWED
        
        # Create quarantined email object
        quarantined_email = QuarantinedEmail(
            message_id=message_id,
            user_id=user_id or recipient,
            sender=sender,
            recipient=recipient,
            subject=subject,
            body_preview=body[:500],
            body_hash=self.calculate_hash(body),
            attachments=attachments or [],
            headers=headers,
            spam_score=final_score,
            threat_level=threat_level,
            detection_reasons=detection_reasons,
            status=status,
            size_bytes=len(body.encode()),
            has_attachments=bool(attachments),
            attachment_types=[a.get('type', 'unknown') for a in (attachments or [])],
            spf_pass=auth_results['spf_pass'],
            dkim_pass=auth_results['dkim_pass'],
            dmarc_pass=auth_results['dmarc_pass']
        )
        
        logger.info(
            f"Email analysis complete: {sender} -> {recipient}, "
            f"Score: {final_score:.2f}, Status: {status}, Threat: {threat_level}"
        )
        
        return quarantined_email
    
    async def retrain_models(self, training_data: List[Tuple[str, int]]):
        logger.info(f"Retraining models with {len(training_data)} samples")
        
        # Prepare training data
        X_text = [text for text, _ in training_data]
        y = np.array([label for _, label in training_data])
        
        # Extract features
        X_features = []
        for text in X_text:
            features = self.ml_detector.extract_features(text, {})
            X_features.append(list(features.values()))
        
        X = np.array(X_features)
        
        # Train ensemble models
        self.ml_detector.train_ensemble(X, y)
        
        # Save updated models
        self.ml_detector.save_models(config.ML_MODEL_PATH)
        
        logger.info("Model retraining complete")