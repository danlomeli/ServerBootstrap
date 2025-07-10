#!/bin/bash

# SSH Security Lockdown Script
# This script implements comprehensive SSH hardening based on security review

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
NEW_SSH_PORT=2222
BACKUP_DIR="/etc/ssh/backup-$(date +%Y%m%d-%H%M%S)"
SSHD_CONFIG="/etc/ssh/sshd_config"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    SSH Security Lockdown Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to print status messages
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Create backup directory
print_status "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Backup current SSH configuration
print_status "Backing up current SSH configuration..."
cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.original"
cp -r /etc/ssh/ssh_host_* "$BACKUP_DIR/" 2>/dev/null || true

# Function to update SSH config
update_ssh_config() {
    local key="$1"
    local value="$2"
    local config_file="$3"

    if grep -q "^#\?$key" "$config_file"; then
        # Key exists (commented or not), replace it
        sed -i "s/^#\?$key.*/$key $value/" "$config_file"
        print_status "Updated: $key $value"
    else
        # Key doesn't exist, add it
        echo "$key $value" >> "$config_file"
        print_status "Added: $key $value"
    fi
}

# Function to add config if not present
add_config_if_missing() {
    local config_line="$1"
    local config_file="$2"

    if ! grep -q "^$config_line" "$config_file"; then
        echo "$config_line" >> "$config_file"
        print_status "Added: $config_line"
    else
        print_status "Already present: $config_line"
    fi
}

echo -e "${YELLOW}Starting SSH security hardening...${NC}"
echo ""

# 1. Change SSH port
print_status "Changing SSH port to $NEW_SSH_PORT"
update_ssh_config "Port" "$NEW_SSH_PORT" "$SSHD_CONFIG"

# 2. Disable X11 forwarding
print_status "Disabling X11 forwarding"
update_ssh_config "X11Forwarding" "no" "$SSHD_CONFIG"

# 3. Set connection limits
print_status "Setting connection limits"
update_ssh_config "MaxAuthTries" "3" "$SSHD_CONFIG"
update_ssh_config "MaxSessions" "5" "$SSHD_CONFIG"
update_ssh_config "MaxStartups" "10:30:60" "$SSHD_CONFIG"

# 4. Configure client timeouts
print_status "Configuring client timeouts"
update_ssh_config "ClientAliveInterval" "300" "$SSHD_CONFIG"
update_ssh_config "ClientAliveCountMax" "2" "$SSHD_CONFIG"

# 5. Enforce protocol version 2
print_status "Enforcing SSH protocol version 2"
add_config_if_missing "Protocol 2" "$SSHD_CONFIG"

# 6. Additional security settings
print_status "Adding additional security settings"
update_ssh_config "PermitEmptyPasswords" "no" "$SSHD_CONFIG"
update_ssh_config "StrictModes" "yes" "$SSHD_CONFIG"
update_ssh_config "LogLevel" "VERBOSE" "$SSHD_CONFIG"
update_ssh_config "LoginGraceTime" "30" "$SSHD_CONFIG"

# 7. Configure strong host keys
print_status "Configuring strong host keys"
# Comment out weak keys and enable strong ones
sed -i 's/^HostKey \/etc\/ssh\/ssh_host_dsa_key/#&/' "$SSHD_CONFIG"
sed -i 's/^HostKey \/etc\/ssh\/ssh_host_ecdsa_key/#&/' "$SSHD_CONFIG"

# Ensure strong keys are enabled
add_config_if_missing "HostKey /etc/ssh/ssh_host_ed25519_key" "$SSHD_CONFIG"
add_config_if_missing "HostKey /etc/ssh/ssh_host_rsa_key" "$SSHD_CONFIG"

# 8. Configure allowed ciphers and MACs (modern, secure algorithms)
print_status "Configuring secure ciphers and MACs"
add_config_if_missing "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONFIG"
add_config_if_missing "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" "$SSHD_CONFIG"
add_config_if_missing "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256" "$SSHD_CONFIG"

# 9. Disable unused features
print_status "Disabling unused features"
update_ssh_config "AllowAgentForwarding" "no" "$SSHD_CONFIG"
update_ssh_config "AllowTcpForwarding" "no" "$SSHD_CONFIG"
update_ssh_config "GatewayPorts" "no" "$SSHD_CONFIG"
update_ssh_config "PermitTunnel" "no" "$SSHD_CONFIG"

# 10. Update firewall rules
print_status "Updating firewall rules"
if command -v ufw &> /dev/null; then
    # UFW is available
    print_status "Configuring UFW firewall"
    ufw allow $NEW_SSH_PORT/tcp
    ufw delete allow 22/tcp 2>/dev/null || true
    print_status "UFW rules updated"
elif command -v firewall-cmd &> /dev/null; then
    # firewalld is available
    print_status "Configuring firewalld"
    firewall-cmd --permanent --add-port=$NEW_SSH_PORT/tcp
    firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true
    firewall-cmd --reload
    print_status "Firewalld rules updated"
else
    print_warning "No firewall detected. Please manually configure your firewall to allow port $NEW_SSH_PORT"
fi

# Test SSH configuration
print_status "Testing SSH configuration syntax"
if sshd -t; then
    print_status "SSH configuration syntax is valid"
else
    print_error "SSH configuration syntax error detected!"
    print_error "Restoring original configuration..."
    cp "$BACKUP_DIR/sshd_config.original" "$SSHD_CONFIG"
    exit 1
fi

# Display current user info for client config
CURRENT_USER=$(logname 2>/dev/null || echo $SUDO_USER)
if [[ -n "$CURRENT_USER" ]]; then
    USER_HOME=$(eval echo ~$CURRENT_USER)
    SSH_CONFIG_FILE="$USER_HOME/.ssh/config"
else
    print_warning "Could not determine current user. You'll need to manually update your SSH client config."
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}    SSH Lockdown Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT: Before restarting SSH service${NC}"
echo -e "${YELLOW}===========================================${NC}"
echo ""

if [[ -n "$CURRENT_USER" && -d "$USER_HOME" ]]; then
    echo -e "${BLUE}1. Update your SSH client configuration:${NC}"
    echo ""
    echo "   Edit or create: $SSH_CONFIG_FILE"
    echo ""
    echo -e "${GREEN}   Add the following configuration:${NC}"
    echo ""
    echo "   Host $(hostname)"
    echo "       HostName $(hostname -I | awk '{print $1}')"
    echo "       Port $NEW_SSH_PORT"
    echo "       User $CURRENT_USER"
    echo "       IdentityFile ~/.ssh/id_rsa"
    echo "       ServerAliveInterval 60"
    echo "       ServerAliveCountMax 3"
    echo ""

    # Create the SSH config automatically
    print_status "Creating SSH client configuration..."
    mkdir -p "$USER_HOME/.ssh"

    # Backup existing config
    if [[ -f "$SSH_CONFIG_FILE" ]]; then
        cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_FILE.backup.$(date +%Y%m%d-%H%M%S)"
        print_status "Backed up existing SSH config"
    fi

    # Add new host configuration
    cat >> "$SSH_CONFIG_FILE" << EOF

# Auto-generated SSH config for hardened server
Host $(hostname)
    HostName $(hostname -I | awk '{print $1}')
    Port $NEW_SSH_PORT
    User $CURRENT_USER
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking yes

# You can also create an alias for easier connection:
Host server
    HostName $(hostname -I | awk '{print $1}')
    Port $NEW_SSH_PORT
    User $CURRENT_USER
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

    chown $CURRENT_USER:$CURRENT_USER "$SSH_CONFIG_FILE"
    chmod 600 "$SSH_CONFIG_FILE"
    print_status "SSH client configuration created automatically"
    echo ""
fi

echo -e "${BLUE}2. Test the new configuration:${NC}"
echo ""
echo "   From another terminal (DON'T CLOSE THIS ONE YET):"
echo "   ssh -p $NEW_SSH_PORT $CURRENT_USER@$(hostname -I | awk '{print $1}')"
echo ""
echo "   Or if you updated your SSH config:"
echo "   ssh $(hostname)"
echo "   ssh server"
echo ""

echo -e "${BLUE}3. Restart SSH service:${NC}"
echo ""
if [[ -f "/etc/init.d/ssh" ]]; then
    echo "   sudo /etc/init.d/ssh restart"
elif [[ -f "/etc/init.d/sshd" ]]; then
    echo "   sudo /etc/init.d/sshd restart"
else
    echo "   sudo /etc/init.d/ssh restart  # or sshd"
fi
echo ""

echo -e "${BLUE}4. Verify service status:${NC}"
echo ""
echo "   ps aux | grep sshd"
echo "   sudo netstat -tlnp | grep :$NEW_SSH_PORT"
echo ""

echo -e "${RED}WARNING: Do NOT close this terminal until you've verified${NC}"
echo -e "${RED}you can connect using the new port and configuration!${NC}"
echo ""

echo -e "${GREEN}Backup location: $BACKUP_DIR${NC}"
echo ""
echo -e "${GREEN}Security improvements implemented:${NC}"
echo -e "${GREEN}✓ SSH port changed from 22 to $NEW_SSH_PORT${NC}"
echo -e "${GREEN}✓ X11 forwarding disabled${NC}"
echo -e "${GREEN}✓ Connection limits configured${NC}"
echo -e "${GREEN}✓ Client timeouts configured${NC}"
echo -e "${GREEN}✓ Strong host keys configured${NC}"
echo -e "${GREEN}✓ Secure ciphers and MACs configured${NC}"
echo -e "${GREEN}✓ Unused features disabled${NC}"
echo -e "${GREEN}✓ Firewall rules updated${NC}"
echo -e "${GREEN}✓ SSH client config created${NC}"
echo ""

# Function to restart SSH service (following same pattern as script 2)
restart_ssh_service() {
    print_status "Restarting SSH service..."
    if [[ -f "/etc/init.d/ssh" ]]; then
        /etc/init.d/ssh restart
        print_status "SSH service restarted successfully"
        return 0
    elif [[ -f "/etc/init.d/sshd" ]]; then
        /etc/init.d/sshd restart
        print_status "SSH service restarted successfully"
        return 0
    else
        print_warning "Could not find SSH init script. You may need to restart SSH manually."
        print_warning "Try one of these commands:"
        print_warning "  sudo /etc/init.d/ssh restart"
        print_warning "  sudo /etc/init.d/sshd restart"
        print_warning "  sudo systemctl restart sshd"
        return 1
    fi
}

# Ask user if they want to restart SSH immediately
read -p "Do you want to restart SSH service now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if restart_ssh_service; then
        print_status "SSH is now listening on port $NEW_SSH_PORT"
    else
        print_error "SSH service restart failed!"
    fi
else
    print_warning "SSH service NOT restarted. Remember to restart it manually:"
    if [[ -f "/etc/init.d/ssh" ]]; then
        print_warning "sudo /etc/init.d/ssh restart"
    elif [[ -f "/etc/init.d/sshd" ]]; then
        print_warning "sudo /etc/init.d/sshd restart"
    else
        print_warning "sudo /etc/init.d/ssh restart"
    fi
fi

echo ""
echo -e "${GREEN}SSH lockdown script completed successfully!${NC}"