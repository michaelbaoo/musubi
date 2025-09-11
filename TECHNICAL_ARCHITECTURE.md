# Technical Architecture Document

## Executive Summary

The Email Spam Quarantine System is a comprehensive, multi-layered security solution designed to protect email accounts from spam, phishing, and malicious content. The system employs machine learning, pattern matching, and reputation-based filtering to achieve >99% spam detection accuracy while maintaining low false positive rates.

## System Architecture

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         User Layer                           │
├──────────────────────────────────────────────────────────────┤
│  Web UI (HTML/JS)  │  Mobile App  │  CLI Tool  │  API Client│
└────────┬─────────────────┬──────────────┬──────────────┬────┘
         │                 │              │              │
┌────────▼─────────────────▼──────────────▼──────────────▼────┐
│                      API Gateway (FastAPI)                   │
│  - Authentication  - Rate Limiting  - Request Routing        │
└────────┬──────────────────────────────────────────────────────┘
         │
┌────────▼──────────────────────────────────────────────────────┐
│                    Business Logic Layer                       │
├────────────────┬──────────────┬────────────┬─────────────────┤
│  Quarantine    │   Spam       │   Email    │    User        │
│   Manager      │   Engine     │ Integration│  Management    │
└────────┬───────┴──────┬───────┴─────┬──────┴────────┬────────┘
         │              │             │               │
┌────────▼──────────────▼─────────────▼───────────────▼────────┐
│                      Data Layer                              │
├─────────────┬──────────────┬──────────────┬──────────────────┤
│   MongoDB   │    Redis     │  ML Models   │   File Storage  │
└─────────────┴──────────────┴──────────────┴──────────────────┘
```

### Component Details

#### 1. Email Integration Layer

**Purpose**: Interface with email providers to fetch and manage emails

**Components**:
- **Gmail Integration** (`src/integrations/gmail_integration.py`)
  - OAuth 2.0 authentication
  - Gmail API v1 implementation
  - Label management
  - Email filtering and search

- **Outlook Integration** (Future)
  - Microsoft Graph API
  - Azure AD authentication
  - Exchange Web Services support

- **IMAP Integration** (Future)
  - Generic IMAP/SMTP support
  - SSL/TLS encryption
  - Multiple provider support

**Key Features**:
- Batch email fetching (100 emails/request)
- Incremental sync using history IDs
- Attachment handling
- Thread conversation support

#### 2. Spam Detection Engine

**Purpose**: Multi-layered spam detection using ML and heuristics

**Detection Layers**:

1. **Machine Learning Models**
   - Random Forest Classifier (30% weight)
   - Gradient Boosting (30% weight)
   - Naive Bayes (20% weight)
   - Logistic Regression (20% weight)
   - BERT transformer for NLP (optional, 40% final weight)

2. **Feature Extraction**
   - Text features (length, caps ratio, special chars)
   - URL analysis (count, reputation)
   - Header anomalies
   - Attachment analysis
   - Sender reputation

3. **Pattern Matching**
   - Keyword detection
   - Regex patterns
   - Blacklist/whitelist checking
   - Domain reputation

4. **Authentication Checks**
   - SPF validation
   - DKIM verification
   - DMARC policy checking

**Detection Flow**:
```python
Input Email → Feature Extraction → ML Models → Pattern Matching 
    → Authentication → Score Aggregation → Threat Assessment
```

**Scoring System**:
- 0.0 - 0.3: Low risk (likely legitimate)
- 0.3 - 0.5: Medium risk (suspicious)
- 0.5 - 0.7: High risk (likely spam)
- 0.7 - 1.0: Critical risk (confirmed spam/malware)

#### 3. Quarantine Management System

**Purpose**: Isolate and manage suspicious emails

**Core Functions**:
- Email isolation with encryption
- Automated summarization using BART
- User action processing (allow/block/delete)
- Sender reputation management
- Bulk operations support

**Workflow**:
1. Email received → Spam analysis
2. If spam score > threshold → Quarantine
3. Generate AI summary
4. Store encrypted in MongoDB
5. Notify user (if configured)
6. Await user review
7. Process user action
8. Update ML models with feedback

#### 4. Database Architecture

**MongoDB Collections**:

```javascript
// quarantined_emails
{
  _id: ObjectId,
  message_id: String,
  user_id: String,
  sender: String,
  recipient: String,
  subject: String,
  body_preview: String,
  body_hash: String,
  spam_score: Float,
  threat_level: Enum,
  detection_reasons: Array,
  status: Enum,
  quarantine_date: DateTime,
  encrypted_content: String
}

// user_preferences
{
  _id: ObjectId,
  user_id: String,
  spam_threshold: Float,
  auto_delete_spam: Boolean,
  quarantine_days: Integer,
  notification_settings: Object
}

// spam_patterns
{
  _id: ObjectId,
  pattern_type: String,
  pattern_value: String,
  weight: Float,
  active: Boolean,
  match_count: Integer
}
```

**Indexes**:
- user_id (all collections)
- message_id (unique)
- quarantine_date (descending)
- spam_score (descending)
- sender (for reputation queries)

#### 5. Security Architecture

**Encryption**:
- AES-256 for email content
- PBKDF2 for key derivation
- Bcrypt for password hashing
- JWT RS256 for tokens

**Authentication Flow**:
```
User Login → Password Verification → JWT Generation 
    → Token Validation → API Access
```

**Security Measures**:
- Rate limiting (100 requests/minute)
- Input sanitization
- SQL injection prevention
- XSS protection
- CSRF tokens
- Content Security Policy

#### 6. API Architecture

**RESTful Endpoints**:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /api/auth/login | User authentication |
| GET | /api/quarantine/emails | List quarantined emails |
| POST | /api/quarantine/email/{id}/review | Review email action |
| GET | /api/preferences | Get user preferences |
| PUT | /api/preferences | Update preferences |
| POST | /api/senders/allowed | Add allowed sender |
| POST | /api/senders/blocked | Add blocked sender |

**Response Format**:
```json
{
  "status": "success|error",
  "data": {},
  "message": "string",
  "timestamp": "ISO8601"
}
```

## Performance Optimization

### Caching Strategy

**Redis Implementation**:
- User preferences (TTL: 1 hour)
- Spam patterns (TTL: 10 minutes)
- API responses (TTL: 5 minutes)
- Session tokens (TTL: 24 hours)

### Database Optimization

- Compound indexes for complex queries
- Aggregation pipelines for statistics
- Bulk operations for batch processing
- Connection pooling (max: 100)

### ML Model Optimization

- Model caching in memory
- Batch predictions for efficiency
- Async processing for non-blocking
- Periodic model retraining (weekly)

## Scalability Design

### Horizontal Scaling

```
Load Balancer (nginx)
       │
   ┌───┴───┬───────┬───────┐
   │       │       │       │
 API-1   API-2   API-3   API-N
   │       │       │       │
   └───┬───┴───────┴───┬───┘
       │               │
  MongoDB RS      Redis Cluster
```

### Microservices Architecture (Future)

- Email Fetcher Service
- Spam Detection Service
- Quarantine Service
- Notification Service
- User Management Service

## Monitoring & Observability

### Metrics Collection

- API response times
- Spam detection accuracy
- False positive/negative rates
- System resource usage
- Email processing throughput

### Logging Strategy

```python
logger.info("Email processed", extra={
    "user_id": user_id,
    "email_id": email_id,
    "spam_score": score,
    "processing_time": time_ms
})
```

### Health Checks

- Database connectivity
- Redis availability
- ML model loading
- API endpoint status
- Email provider connection

## Disaster Recovery

### Backup Strategy

- MongoDB: Daily backups, 30-day retention
- ML Models: Version control, S3 storage
- Configuration: Git repository
- User data: Encrypted backups

### Recovery Procedures

1. **System Failure**:
   - Automatic failover to standby
   - Load balancer health checks
   - Service auto-restart

2. **Data Loss**:
   - Restore from latest backup
   - Replay transaction logs
   - Verify data integrity

## Compliance & Privacy

### GDPR Compliance

- User consent for data processing
- Right to erasure implementation
- Data portability (export)
- Privacy by design

### Data Retention

- Quarantined emails: 30 days
- Audit logs: 90 days
- User preferences: Until deletion
- ML training data: Anonymized, 1 year

## Future Enhancements

### Phase 1 (Q1 2024)
- Microsoft Exchange integration
- Advanced threat intelligence feeds
- Mobile applications

### Phase 2 (Q2 2024)
- Multi-tenant architecture
- GraphQL API
- Real-time notifications

### Phase 3 (Q3 2024)
- Kubernetes deployment
- Advanced analytics dashboard
- AI-powered threat prediction

## Technical Challenges & Solutions

### Challenge 1: Email Volume
**Problem**: Processing thousands of emails/second
**Solution**: 
- Async processing with Celery
- Message queue (RabbitMQ)
- Batch operations

### Challenge 2: False Positives
**Problem**: Legitimate emails marked as spam
**Solution**:
- User feedback loop
- Continuous model training
- Whitelist management

### Challenge 3: Zero-Day Threats
**Problem**: New spam patterns not in training data
**Solution**:
- Real-time pattern updates
- Community threat sharing
- Behavioral analysis

## Conclusion

The Email Spam Quarantine System represents a robust, scalable solution for email security. By combining multiple detection techniques, secure architecture, and user-friendly management, it provides comprehensive protection against spam and malicious content while maintaining high performance and reliability.