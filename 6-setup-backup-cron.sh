#!/bin/bash

# Script to set up daily Odoo database backup cron job
# This script will prompt for the backup script path and configure a cron job

set -e  # Exit on any error

echo "=== Odoo Daily Backup Cron Setup ==="
echo

# Get the backup script path
read -p "Enter the full path to your backup script [.devcontainer/scripts/backup-db.sh]: " SCRIPT_PATH
SCRIPT_PATH=${SCRIPT_PATH:-".devcontainer/scripts/backup-db.sh"}

# Validate the script exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "Error: Backup script not found at: $SCRIPT_PATH"
    exit 1
fi

# Make sure the script is executable
chmod +x "$SCRIPT_PATH"

# Get backup parameters
echo
echo "Configure backup parameters:"
read -p "Database name [odoo]: " DB_NAME
DB_NAME=${DB_NAME:-"odoo"}

read -p "Backup directory [.devcontainer/db/init]: " BACKUP_DIR
BACKUP_DIR=${BACKUP_DIR:-".devcontainer/db/init"}

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Get the full path to the script
FULL_SCRIPT_PATH=$(realpath "$SCRIPT_PATH")

# Get timing preference
echo
echo "When should the backup run daily?"
echo "1) 2:00 AM (recommended for minimal disruption)"
echo "2) 6:00 PM (end of business day)"
echo "3) Custom time"
read -p "Choose an option [1]: " TIME_OPTION
TIME_OPTION=${TIME_OPTION:-1}

case $TIME_OPTION in
    1)
        CRON_TIME="0 2 * * *"
        TIME_DESC="2:00 AM"
        ;;
    2)
        CRON_TIME="0 18 * * *"
        TIME_DESC="6:00 PM"
        ;;
    3)
        read -p "Enter hour (0-23): " HOUR
        read -p "Enter minute (0-59): " MINUTE
        CRON_TIME="$MINUTE $HOUR * * *"
        TIME_DESC="$HOUR:$(printf "%02d" $MINUTE)"
        ;;
    *)
        echo "Invalid option, using default 2:00 AM"
        CRON_TIME="0 2 * * *"
        TIME_DESC="2:00 AM"
        ;;
esac

# Create the cron job entry
CRON_JOB="$CRON_TIME $FULL_SCRIPT_PATH $DB_NAME $BACKUP_DIR"

# Create a temporary file with current crontab
TEMP_CRON=$(mktemp)
crontab -l 2>/dev/null > "$TEMP_CRON" || true

# Check if a similar backup job already exists
if grep -q "backup-db.sh" "$TEMP_CRON" 2>/dev/null; then
    echo
    echo "Warning: Found existing backup cron job(s):"
    grep "backup-db.sh" "$TEMP_CRON" || true
    echo
    read -p "Do you want to replace existing backup jobs? (y/N): " REPLACE
    if [[ $REPLACE =~ ^[Yy]$ ]]; then
        # Remove existing backup jobs
        grep -v "backup-db.sh" "$TEMP_CRON" > "${TEMP_CRON}.new" || true
        mv "${TEMP_CRON}.new" "$TEMP_CRON"
    else
        echo "Keeping existing jobs. Adding new job..."
    fi
fi

# Add the new cron job
echo "$CRON_JOB" >> "$TEMP_CRON"

# Install the new crontab
crontab "$TEMP_CRON"

# Clean up
rm "$TEMP_CRON"

# Show summary
echo
echo "=== Backup Cron Job Successfully Configured ==="
echo "Script: $FULL_SCRIPT_PATH"
echo "Database: $DB_NAME"
echo "Backup Directory: $BACKUP_DIR"
echo "Schedule: Daily at $TIME_DESC"
echo "Cron Expression: $CRON_TIME"
echo
echo "Current cron jobs:"
crontab -l | grep -E "(backup|odoo)" || echo "No backup-related cron jobs found"
echo
echo "The backup will create these files:"
echo "  - $BACKUP_DIR/03-restore-backup.sql.gz (database dump)"
echo "  - $BACKUP_DIR/04-restore-filestore.tar.gz (file attachments)"
echo
echo "To verify the backup script works, you can run it manually:"
echo "$FULL_SCRIPT_PATH $DB_NAME $BACKUP_DIR"
echo
echo "To remove this cron job later, run: crontab -e"
echo "Setup complete!"