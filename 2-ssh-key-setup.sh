#!/bin/bash

# Script 2: SSH Key Setup and Password Authentication Disable
# Sets up SSH key authentication and disables password login

set -e

echo "=== SSH Key Setup ==="
echo "This script will set up SSH key authentication and disable password login."
echo

# Check if we're running as the correct user (not root)
if [ "$EUID" -eq 0 ]; then
    echo "Error: This script should NOT be run as root."
    echo "Please run this script as your regular sudo user."
    exit 1
fi

# Create .ssh directory if it doesn't exist
mkdir -p ~/.ssh
chmod 700 ~/.ssh

echo "You need to add your public key to the authorized_keys file."
echo "The file is located at: ~/.ssh/authorized_keys"
echo

# Check if authorized_keys exists
if [ -f ~/.ssh/authorized_keys ]; then
    echo "authorized_keys file already exists."
    echo "Current contents:"
    cat ~/.ssh/authorized_keys
    echo
    read -p "Do you want to replace it? (y/N): " replace
    if [[ $replace =~ ^[Yy]$ ]]; then
        > ~/.ssh/authorized_keys
    fi
else
    touch ~/.ssh/authorized_keys
fi

chmod 600 ~/.ssh/authorized_keys

echo "Please paste your public key (usually from ~/.ssh/id_rsa.pub on your local machine):"
echo "Tip: You can copy your public key using: cat ~/.ssh/id_rsa.pub"
echo "Then paste it below and press Enter, followed by Ctrl+D:"
echo

# Read the public key from user input
cat >> ~/.ssh/authorized_keys

echo
echo "Public key added to authorized_keys."

# Verify the key was added
echo "Current authorized_keys content:"
cat ~/.ssh/authorized_keys
echo

read -p "Does the key look correct? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Please edit ~/.ssh/authorized_keys manually and run this script again."
    exit 1
fi

echo "Now disabling password authentication in SSH..."

# Backup SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup-$(date +%Y%m%d-%H%M%S)

# Disable password authentication
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Ensure the setting is added if it doesn't exist
if ! sudo grep -q "PasswordAuthentication" /etc/ssh/sshd_config; then
    echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config
fi

# Also disable challenge response authentication
sudo sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

if ! sudo grep -q "ChallengeResponseAuthentication" /etc/ssh/sshd_config; then
    echo "ChallengeResponseAuthentication no" | sudo tee -a /etc/ssh/sshd_config
fi

# Restart SSH service using /etc/init.d method
echo "Restarting SSH service..."
if [ -f /etc/init.d/ssh ]; then
    sudo /etc/init.d/ssh restart
elif [ -f /etc/init.d/sshd ]; then
    sudo /etc/init.d/sshd restart
else
    echo "Warning: Could not find SSH init script. You may need to restart SSH manually."
fi

echo
echo "=== SSH Key Setup Complete ==="
echo "1. Public key has been added to ~/.ssh/authorized_keys"
echo "2. Password authentication has been disabled"
echo "3. SSH service has been restarted"
echo
echo "CRITICAL: Test SSH key authentication NOW in a new terminal:"
echo "   ssh $(whoami)@$(hostname -I | awk '{print $1}')"
echo
echo "Make sure you can log in without a password before closing this session!"
echo "If you can't connect, you may need to:"
echo "1. Check your local private key permissions (chmod 600 ~/.ssh/id_rsa)"
echo "2. Verify the public key was copied correctly"
echo "3. Check SSH client configuration"
echo
read -p "Press Enter after confirming SSH key login works..."