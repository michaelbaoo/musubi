#!/bin/bash

echo "========================================="
echo "musubi System Installer"
echo "========================================="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo "Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)"
    exit 1
fi

echo "✓ Python version check passed ($PYTHON_VERSION)"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Download NLTK data
echo "Downloading NLTK data..."
python3 -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"

# Download spaCy model
echo "Downloading spaCy language model..."
python3 -m spacy download en_core_web_sm

# Create necessary directories
echo "Creating directories..."
mkdir -p config logs models data

# Generate encryption key if not exists
if [ ! -f config/.env ]; then
    echo "Generating configuration..."
    cat > config/.env << EOF
# Email Spam Quarantine Configuration

# API Settings
API_HOST=0.0.0.0
API_PORT=8000

# Database
MONGODB_URL=mongodb://localhost:27017
MONGODB_DB_NAME=spam_quarantine

# Redis
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET_KEY=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 32)

# ML Settings
ML_MODEL_PATH=models/spam_detector.pkl
SPAM_THRESHOLD=0.7
AUTO_LEARN=true

# Quarantine Settings
QUARANTINE_DAYS=30
SCAN_INTERVAL_MINUTES=5

# Email Settings
MAX_EMAIL_SIZE_MB=25
BATCH_SIZE=100

# Feature Flags
ENABLE_CONTENT_SCANNING=true
ENABLE_ATTACHMENT_SCANNING=true
ENABLE_URL_CHECKING=true
ENABLE_SPF_CHECKING=true
ENABLE_DKIM_CHECKING=true

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/spam_quarantine.log
EOF
    echo "✓ Configuration file created"
else
    echo "✓ Configuration file already exists"
fi

# Check MongoDB
if command -v mongod &> /dev/null; then
    echo "✓ MongoDB detected"
else
    echo "⚠ MongoDB not found. Please install MongoDB:"
    echo "  macOS: brew install mongodb-community"
    echo "  Ubuntu: sudo apt-get install mongodb"
    echo "  CentOS: sudo yum install mongodb"
fi

# Check Redis
if command -v redis-server &> /dev/null; then
    echo "✓ Redis detected"
else
    echo "⚠ Redis not found. Please install Redis:"
    echo "  macOS: brew install redis"
    echo "  Ubuntu: sudo apt-get install redis-server"
    echo "  CentOS: sudo yum install redis"
fi

# Create Gmail credentials template
if [ ! -f config/gmail_credentials.json ]; then
    cat > config/gmail_credentials_template.json << EOF
{
  "installed": {
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "project_id": "your-project-id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_uris": ["http://localhost:8080"]
  }
}
EOF
    echo "✓ Gmail credentials template created"
    echo "⚠ Please update config/gmail_credentials.json with your OAuth credentials"
fi

# Create systemd service file
cat > email-quarantine.service << EOF
[Unit]
Description=Email Spam Quarantine Service
After=network.target mongodb.service redis.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "✓ Systemd service file created"

# Create start script
cat > start.sh << 'EOF'
#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Start MongoDB if not running
if ! pgrep -x "mongod" > /dev/null; then
    echo "Starting MongoDB..."
    mongod --dbpath data --logpath logs/mongodb.log --fork
fi

# Start Redis if not running
if ! pgrep -x "redis-server" > /dev/null; then
    echo "Starting Redis..."
    redis-server --daemonize yes
fi

# Start the application
echo "Starting Email Spam Quarantine System..."
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
EOF

chmod +x start.sh

# Create stop script
cat > stop.sh << 'EOF'
#!/bin/bash

echo "Stopping Email Spam Quarantine System..."

# Kill the application
pkill -f "uvicorn src.api.main:app"

# Optionally stop MongoDB and Redis
read -p "Stop MongoDB and Redis? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pkill mongod
    redis-cli shutdown
fi

echo "Services stopped"
EOF

chmod +x stop.sh

echo ""
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Configure Gmail OAuth:"
echo "   - Go to https://console.cloud.google.com"
echo "   - Create a new project or select existing"
echo "   - Enable Gmail API"
echo "   - Create OAuth 2.0 credentials"
echo "   - Download credentials and save as config/gmail_credentials.json"
echo ""
echo "2. Start MongoDB and Redis:"
echo "   mongod --dbpath data --logpath logs/mongodb.log --fork"
echo "   redis-server --daemonize yes"
echo ""
echo "3. Start the application:"
echo "   ./start.sh"
echo ""
echo "4. Access the dashboard:"
echo "   http://localhost:8000"
echo ""
echo "For production deployment:"
echo "   sudo cp email-quarantine.service /etc/systemd/system/"
echo "   sudo systemctl enable email-quarantine"
echo "   sudo systemctl start email-quarantine"
echo ""