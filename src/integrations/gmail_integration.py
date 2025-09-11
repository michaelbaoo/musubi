import os
import base64
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger
import json

class GmailIntegration:
    def __init__(self, credentials_file: str = None):
        self.credentials_file = credentials_file or "config/gmail_credentials.json"
        self.token_file = "config/gmail_token.json"
        self.service = None
        self.creds = None
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.labels',
            'https://www.googleapis.com/auth/gmail.settings.basic'
        ]
    
    def authenticate(self) -> bool:
        try:
            if os.path.exists(self.token_file):
                with open(self.token_file, 'r') as token:
                    creds_data = json.load(token)
                    self.creds = Credentials.from_authorized_user_info(creds_data, self.scopes)
            
            if not self.creds or not self.creds.valid:
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    self.creds.refresh(Request())
                else:
                    flow = Flow.from_client_secrets_file(
                        self.credentials_file,
                        scopes=self.scopes,
                        redirect_uri='http://localhost:8080'
                    )
                    
                    auth_url, _ = flow.authorization_url(prompt='consent')
                    logger.info(f"Please visit this URL to authorize: {auth_url}")
                    
                    code = input("Enter the authorization code: ")
                    flow.fetch_token(code=code)
                    self.creds = flow.credentials
                
                with open(self.token_file, 'w') as token:
                    token.write(self.creds.to_json())
            
            self.service = build('gmail', 'v1', credentials=self.creds)
            logger.info("Gmail authentication successful")
            return True
            
        except Exception as e:
            logger.error(f"Gmail authentication failed: {e}")
            return False
    
    async def fetch_emails(
        self,
        query: str = "is:unread",
        max_results: int = 100,
        include_spam: bool = True
    ) -> List[Dict[str, Any]]:
        
        if not self.service:
            if not self.authenticate():
                return []
        
        emails = []
        
        try:
            if include_spam:
                query += " OR in:spam"
            
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            
            for message in messages:
                msg = self.service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='full'
                ).execute()
                
                email_data = self._parse_email(msg)
                emails.append(email_data)
            
            logger.info(f"Fetched {len(emails)} emails from Gmail")
            return emails
            
        except HttpError as error:
            logger.error(f"Error fetching emails: {error}")
            return []
    
    def _parse_email(self, message: Dict[str, Any]) -> Dict[str, Any]:
        headers = {}
        for header in message['payload'].get('headers', []):
            headers[header['name']] = header['value']
        
        email_data = {
            'message_id': message['id'],
            'thread_id': message.get('threadId'),
            'labels': message.get('labelIds', []),
            'snippet': message.get('snippet', ''),
            'headers': headers,
            'sender': headers.get('From', ''),
            'recipient': headers.get('To', ''),
            'subject': headers.get('Subject', ''),
            'date': headers.get('Date', ''),
            'body': self._get_body(message['payload']),
            'attachments': self._get_attachments(message['payload']),
            'size_estimate': message.get('sizeEstimate', 0)
        }
        
        return email_data
    
    def _get_body(self, payload: Dict[str, Any]) -> str:
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                elif part['mimeType'] == 'text/html' and not body:
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        elif payload['body'].get('data'):
            body = base64.urlsafe_b64decode(
                payload['body']['data']
            ).decode('utf-8', errors='ignore')
        
        return body
    
    def _get_attachments(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        attachments = []
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('filename'):
                    attachment = {
                        'filename': part['filename'],
                        'mime_type': part['mimeType'],
                        'size': part['body'].get('size', 0),
                        'attachment_id': part['body'].get('attachmentId')
                    }
                    attachments.append(attachment)
        
        return attachments
    
    async def move_to_quarantine(self, message_id: str) -> bool:
        try:
            quarantine_label = await self._get_or_create_label("Spam Quarantine")
            
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={
                    'addLabelIds': [quarantine_label],
                    'removeLabelIds': ['INBOX', 'UNREAD']
                }
            ).execute()
            
            logger.info(f"Email {message_id} moved to quarantine")
            return True
            
        except HttpError as error:
            logger.error(f"Error moving email to quarantine: {error}")
            return False
    
    async def release_from_quarantine(self, message_id: str) -> bool:
        try:
            quarantine_label = await self._get_or_create_label("Spam Quarantine")
            
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={
                    'addLabelIds': ['INBOX'],
                    'removeLabelIds': [quarantine_label]
                }
            ).execute()
            
            logger.info(f"Email {message_id} released from quarantine")
            return True
            
        except HttpError as error:
            logger.error(f"Error releasing email: {error}")
            return False
    
    async def delete_email(self, message_id: str) -> bool:
        try:
            self.service.users().messages().trash(
                userId='me',
                id=message_id
            ).execute()
            
            logger.info(f"Email {message_id} moved to trash")
            return True
            
        except HttpError as error:
            logger.error(f"Error deleting email: {error}")
            return False
    
    async def _get_or_create_label(self, label_name: str) -> str:
        try:
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            
            for label in labels:
                if label['name'] == label_name:
                    return label['id']
            
            label_object = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show',
                'color': {
                    'backgroundColor': '#fb4c2f',
                    'textColor': '#ffffff'
                }
            }
            
            created_label = self.service.users().labels().create(
                userId='me',
                body=label_object
            ).execute()
            
            logger.info(f"Created label: {label_name}")
            return created_label['id']
            
        except HttpError as error:
            logger.error(f"Error creating label: {error}")
            raise
    
    async def create_filter(
        self,
        criteria: Dict[str, Any],
        action: Dict[str, Any]
    ) -> bool:
        
        try:
            filter_object = {
                'criteria': criteria,
                'action': action
            }
            
            self.service.users().settings().filters().create(
                userId='me',
                body=filter_object
            ).execute()
            
            logger.info("Filter created successfully")
            return True
            
        except HttpError as error:
            logger.error(f"Error creating filter: {error}")
            return False
    
    async def get_user_info(self) -> Dict[str, str]:
        try:
            profile = self.service.users().getProfile(userId='me').execute()
            
            return {
                'email': profile['emailAddress'],
                'messages_total': profile.get('messagesTotal', 0),
                'threads_total': profile.get('threadsTotal', 0),
                'history_id': profile.get('historyId', '')
            }
            
        except HttpError as error:
            logger.error(f"Error getting user info: {error}")
            return {}
    
    async def watch_inbox(self, topic_name: str) -> Dict[str, Any]:
        try:
            request = {
                'labelIds': ['INBOX', 'SPAM'],
                'topicName': topic_name
            }
            
            response = self.service.users().watch(
                userId='me',
                body=request
            ).execute()
            
            logger.info(f"Watching inbox, expiration: {response['expiration']}")
            return response
            
        except HttpError as error:
            logger.error(f"Error setting up watch: {error}")
            return {}
    
    async def send_notification(
        self,
        recipient: str,
        subject: str,
        body: str
    ) -> bool:
        
        try:
            message = MIMEMultipart()
            message['to'] = recipient
            message['subject'] = subject
            
            msg = MIMEText(body, 'html')
            message.attach(msg)
            
            raw_message = base64.urlsafe_b64encode(
                message.as_bytes()
            ).decode('utf-8')
            
            self.service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            logger.info(f"Notification sent to {recipient}")
            return True
            
        except HttpError as error:
            logger.error(f"Error sending notification: {error}")
            return False