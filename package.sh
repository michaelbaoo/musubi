#!/bin/bash

echo "Packaging Email Spam Quarantine System..."

# Create a timestamp for the package
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PACKAGE_NAME="email-spam-quarantine-${TIMESTAMP}.tar.gz"

# Create the package excluding unnecessary files
tar -czf "../${PACKAGE_NAME}" \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='data/*' \
    --exclude='logs/*' \
    --exclude='*.log' \
    --exclude='.env' \
    .

echo "Package created: ../${PACKAGE_NAME}"
echo "Size: $(du -h ../${PACKAGE_NAME} | cut -f1)"
echo ""
echo "To extract the package:"
echo "  tar -xzf ${PACKAGE_NAME}"