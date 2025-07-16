#!/bin/bash

# Script 1: Initial Server Setup
# Creates a new sudo user and secures SSH access

set -e

echo "=== Initial Server Setup ==="
echo "This script will create a new sudo user and disable root SSH login."
echo

# Function to prompt for username with validation
get_username() {
    local username
    while true; do
        read -p "Enter username for new sudo user: " username
        if [ -z "$username" ]; then
            echo "Error: Username cannot be empty. Please try again."
            continue
        fi
        if id "$username" &>/dev/null; then
            echo "Error: User '$username' already exists. Please choose a different username."
            continue
        fi
        if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
            echo "Error: Username must start with a letter and contain only lowercase letters, numbers, hyphens, and underscores."
            continue
        fi
        echo "$username"
        break
    done
}

start_service() {
    local service_name=$1
    if [ -f /.dockerenv ]; then
        service "$service_name" start
    else
        systemctl start "$service_name"
    fi
}

# Get username from user
USERNAME=$(get_username)

echo "Creating user: $USERNAME"

# Create the user
useradd -m -s /bin/bash "$USERNAME"

# Set password for the user
echo "Please set a password for user $USERNAME:"
passwd "$USERNAME"

# Add user to sudo group
usermod -aG sudo "$USERNAME"

echo "User $USERNAME created and added to sudo group."

# Create .ssh directory for the new user
mkdir -p /home/$USERNAME/.ssh
chmod 700 /home/$USERNAME/.ssh
chown $USERNAME:$USERNAME /home/$USERNAME/.ssh

# Backup SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Disable root login via SSH
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Ensure the setting is added if it doesn't exist
if ! grep -q "PermitRootLogin" /etc/ssh/sshd_config; then
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

# Restart SSH service using /etc/init.d method
echo "Restarting SSH service..."
if [ -f /etc/init.d/ssh ]; then
    /etc/init.d/ssh restart
elif [ -f /etc/init.d/sshd ]; then
    /etc/init.d/sshd restart
else
    echo "Warning: Could not find SSH init script. You may need to restart SSH manually."
fi

echo
echo "=== Setup Complete ==="
echo "1. A new sudo user '$USERNAME' has been created"
echo "2. Root login via SSH has been disabled"
echo "3. SSH service has been restarted"
echo
echo "IMPORTANT: Before logging out, test the new user account:"
echo "   ssh $USERNAME@$(hostname -I | awk '{print $1}')"
echo
echo "Make sure you can log in and run 'sudo -l' to verify sudo access."
echo "Only log out of the root session after confirming the new user works!"
echo
read -p "Press Enter to continue..."