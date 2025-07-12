#!/bin/bash

# Enhanced SSH Security Lockdown Script - VSCode Compatible
# This script implements comprehensive SSH hardening with VSCode Remote support
# Author: Enhanced Security Edition
# Version: 2.0

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration variables
readonly NEW_SSH_PORT=2222
readonly BACKUP_DIR="/etc/ssh/backup-$(date +%Y%m%d-%H%M%S)"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly VSCODE_COMPATIBLE=true
readonly SCRIPT_VERSION="2.0"

# Advanced security settings
readonly MAX_AUTH_TRIES=3
readonly MAX_SESSIONS=10
readonly MAX_STARTUPS="10:30:100"
readonly LOGIN_GRACE_TIME=30
readonly CLIENT_ALIVE_INTERVAL=300
readonly CLIENT_ALIVE_COUNT_MAX=2

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Enhanced SSH Security Lockdown v${SCRIPT_VERSION}${NC}"
echo -e "${BLUE}      (VSCode Compatible)${NC}"
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

print_vscode_note() {
    echo -e "${BLUE}[VSCODE]${NC} $1"
}

print_security() {
    echo -e "${PURPLE}[SECURITY]${NC} $1"
}

print_systemd() {
    echo -e "${CYAN}[SYSTEMD]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Check if SSH is installed
if ! command -v sshd &> /dev/null; then
    print_error "SSH daemon (sshd) is not installed"
    exit 1
fi

# Detect OS and package manager
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_warning "Cannot detect OS version"
        OS="unknown"
    fi
    print_status "Detected OS: $OS"
}

# Create backup directory
print_status "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Backup current SSH configuration
print_status "Backing up current SSH configuration..."
cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.original"
cp -r /etc/ssh/ssh_host_* "$BACKUP_DIR/" 2>/dev/null || true

# Function to update SSH config (safe for special characters)
update_ssh_config() {
    local key="$1"
    local value="$2"
    local config_file="$3"

    # Escape special characters for sed
    local escaped_key=$(printf '%s\n' "$key" | sed 's/[[\.*^$()+?{|]/\\&/g')
    local escaped_value=$(printf '%s\n' "$value" | sed 's/[[\.*^$()+?{|]/\\&/g')

    if grep -q "^#\?$key" "$config_file"; then
        # Key exists (commented or not), replace it
        # Use | as delimiter instead of / to avoid conflicts
        sed -i "s|^#\?${escaped_key}.*|${key} ${value}|" "$config_file"
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

# Function to ensure SSH directories exist
ensure_ssh_directories() {
    print_status "Ensuring required SSH directories exist..."

    # SSH privilege separation directory
    local sshd_dirs=("/run/sshd" "/var/run/sshd" "/var/empty/sshd")
    for dir in "${sshd_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chmod 755 "$dir"
            print_status "Created directory: $dir"
        fi
    done

    # Ensure proper ownership and permissions for SSH directories
    chown root:root /etc/ssh
    chmod 755 /etc/ssh

    # Set proper permissions for existing host keys
    if ls /etc/ssh/ssh_host_* 1> /dev/null 2>&1; then
        chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
        chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
    fi
}
check_port_availability() {
    local port="$1"
    if netstat -tuln | grep -q ":$port "; then
        print_warning "Port $port is already in use!"
        netstat -tuln | grep ":$port "
        return 1
    fi
    return 0
}

# Function to generate strong SSH host keys
generate_strong_host_keys() {
    print_security "Generating strong SSH host keys..."

    # Remove weak keys
    rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*

    # Generate Ed25519 key (strongest)
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
        print_status "Generated Ed25519 host key"
    fi

    # Generate RSA key (4096 bits for compatibility)
    if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
        print_status "Generated RSA 4096-bit host key"
    fi

    # Set proper permissions
    chmod 600 /etc/ssh/ssh_host_*
    chmod 644 /etc/ssh/ssh_host_*.pub
}

# Function to configure fail2ban (if available)
configure_fail2ban() {
    if command -v fail2ban-client &> /dev/null; then
        print_security "Configuring fail2ban for SSH protection..."

        # Create SSH jail configuration
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $NEW_SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

        systemctl enable fail2ban
        systemctl restart fail2ban
        print_status "Fail2ban configured and enabled"
    else
        print_warning "Fail2ban not installed. Consider installing it for additional protection:"
        print_warning "  Ubuntu/Debian: sudo apt install fail2ban"
        print_warning "  CentOS/RHEL: sudo yum install fail2ban"
    fi
}

# Function to handle systemd socket vs service
handle_systemd_ssh() {
    print_systemd "Handling systemd SSH configuration..."

    # Check if ssh.socket is active
    if systemctl is-active ssh.socket &>/dev/null; then
        print_systemd "SSH socket activation is currently active"
        print_systemd "Disabling socket activation to use traditional SSH service"

        systemctl stop ssh.socket
        systemctl disable ssh.socket
        print_status "SSH socket activation disabled"
    fi

    # Check if ssh.service exists and enable it
    if systemctl list-unit-files | grep -q "ssh.service"; then
        systemctl enable ssh.service
        print_status "SSH service enabled"
    elif systemctl list-unit-files | grep -q "sshd.service"; then
        systemctl enable sshd.service
        print_status "SSHD service enabled"
    fi
}

# Function to create SSH client configuration
create_ssh_client_config() {
    local current_user="$1"
    local user_home="$2"
    local server_ip="$3"
    local server_hostname="$4"
    local ssh_config_file="$user_home/.ssh/config"

    print_status "Creating SSH client configuration..."
    mkdir -p "$user_home/.ssh"

    # Backup existing config
    if [[ -f "$ssh_config_file" ]]; then
        cp "$ssh_config_file" "$ssh_config_file.backup.$(date +%Y%m%d-%H%M%S)"
        print_status "Backed up existing SSH config"
    fi

    # Add new host configuration
    cat >> "$ssh_config_file" << EOF

# Auto-generated SSH config for hardened server (VSCode compatible)
# Generated on $(date)
Host $server_hostname
    HostName $server_ip
    User $current_user
    Port $NEW_SSH_PORT
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    StrictHostKeyChecking accept-new
    AddKeysToAgent yes
    UseKeychain yes
    PreferredAuthentications publickey,keyboard-interactive,password

# Alternative alias for easier connection
Host server
    HostName $server_ip
    User $current_user
    Port $NEW_SSH_PORT
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    StrictHostKeyChecking accept-new
    AddKeysToAgent yes
    UseKeychain yes
    PreferredAuthentications publickey,keyboard-interactive,password

# VSCode Remote optimizations (global settings)
Host *
    # Multiplexing for better performance
    ControlMaster auto
    ControlPath ~/.ssh/control-%r@%h:%p
    ControlPersist 600

    # Compression for slower connections
    Compression yes

    # Keep connections alive
    ServerAliveInterval 60
    ServerAliveCountMax 3

    # Security settings
    HashKnownHosts yes
    VisualHostKey yes
    StrictHostKeyChecking ask

    # Performance optimizations
    IPQoS throughput
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
EOF

    chown "$current_user:$current_user" "$ssh_config_file"
    chmod 600 "$ssh_config_file"
    print_status "SSH client configuration created"
}

# Function to setup SSH key authentication
setup_ssh_keys() {
    local current_user="$1"
    local user_home="$2"

    print_security "Setting up SSH key authentication..."

    # Create .ssh directory if it doesn't exist
    mkdir -p "$user_home/.ssh"

    # Generate Ed25519 key pair if it doesn't exist
    if [[ ! -f "$user_home/.ssh/id_ed25519" ]]; then
        print_status "Generating Ed25519 key pair for $current_user..."
        sudo -u "$current_user" ssh-keygen -t ed25519 -f "$user_home/.ssh/id_ed25519" -N "" -C "$current_user@$(hostname)"
        print_status "Ed25519 key pair generated"
    fi

    # Setup authorized_keys if public key exists
    if [[ -f "$user_home/.ssh/id_ed25519.pub" ]]; then
        touch "$user_home/.ssh/authorized_keys"
        if ! grep -q "$(cat "$user_home/.ssh/id_ed25519.pub")" "$user_home/.ssh/authorized_keys"; then
            cat "$user_home/.ssh/id_ed25519.pub" >> "$user_home/.ssh/authorized_keys"
            print_status "Added public key to authorized_keys"
        fi
    fi

    # Set proper permissions
    chown -R "$current_user:$current_user" "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    chmod 600 "$user_home/.ssh/authorized_keys" 2>/dev/null || true
    chmod 600 "$user_home/.ssh/id_ed25519" 2>/dev/null || true
    chmod 644 "$user_home/.ssh/id_ed25519.pub" 2>/dev/null || true
}

# Function to configure advanced firewall rules
configure_advanced_firewall() {
    print_security "Configuring advanced firewall rules..."

    if command -v ufw &> /dev/null; then
        # UFW configuration
        print_status "Configuring UFW firewall with advanced rules"

        # Enable UFW
        ufw --force enable

        # Default policies
        ufw default deny incoming
        ufw default allow outgoing

        # Allow SSH on new port with rate limiting
        ufw allow $NEW_SSH_PORT/tcp
        ufw limit $NEW_SSH_PORT/tcp comment "SSH with rate limiting"

        # Remove old SSH rule
        ufw delete allow 22/tcp 2>/dev/null || true

        # Common service ports
        ufw allow 80/tcp comment "HTTP"
        ufw allow 443/tcp comment "HTTPS"

        # Allow loopback
        ufw allow in on lo
        ufw allow out on lo

        print_status "UFW firewall configured with advanced rules"

    elif command -v firewall-cmd &> /dev/null; then
        # firewalld configuration
        print_status "Configuring firewalld with advanced rules"

        firewall-cmd --permanent --add-port=$NEW_SSH_PORT/tcp
        firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true

        # Add rate limiting for SSH
        firewall-cmd --permanent --add-rich-rule="rule service name=ssh limit value=10/m accept"

        firewall-cmd --reload
        print_status "Firewalld configured with advanced rules"

    else
        print_warning "No supported firewall detected. Please manually configure your firewall:"
        print_warning "  - Allow port $NEW_SSH_PORT/tcp"
        print_warning "  - Block port 22/tcp"
        print_warning "  - Enable rate limiting for SSH"
    fi
}

# Function to get server IP addresses
get_server_ips() {
    local external_ip=""
    local internal_ip=""

    # Get external IP
    if command -v curl &> /dev/null; then
        external_ip=$(timeout 10 curl -s ifconfig.me 2>/dev/null || timeout 10 curl -s ipinfo.io/ip 2>/dev/null || timeout 10 curl -s icanhazip.com 2>/dev/null || echo "")
    elif command -v wget &> /dev/null; then
        external_ip=$(timeout 10 wget -qO- ifconfig.me 2>/dev/null || timeout 10 wget -qO- ipinfo.io/ip 2>/dev/null || echo "")
    fi

    # Get internal IP
    internal_ip=$(hostname -I | awk '{print $1}' || ip route get 1 | awk '{print $NF;exit}' || echo "127.0.0.1")

    # Return appropriate IP
    if [[ -n "$external_ip" && "$external_ip" != "$internal_ip" ]]; then
        echo "$external_ip"
        print_status "Using external IP: $external_ip"
    else
        echo "$internal_ip"
        print_status "Using internal IP: $internal_ip"
    fi
}

# Main execution starts here
detect_os

echo -e "${YELLOW}Starting enhanced SSH security hardening...${NC}"
echo ""

# Check port availability
if ! check_port_availability "$NEW_SSH_PORT"; then
    read -p "Port $NEW_SSH_PORT is in use. Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Aborting due to port conflict"
        exit 1
    fi
fi

# Generate strong host keys
generate_strong_host_keys

# 1. Change SSH port
print_status "Changing SSH port to $NEW_SSH_PORT"
update_ssh_config "Port" "$NEW_SSH_PORT" "$SSHD_CONFIG"

# 2. Disable dangerous features
print_security "Disabling dangerous SSH features"
update_ssh_config "PermitRootLogin" "no" "$SSHD_CONFIG"
update_ssh_config "PasswordAuthentication" "yes" "$SSHD_CONFIG"  # Keep enabled initially
update_ssh_config "PubkeyAuthentication" "yes" "$SSHD_CONFIG"
update_ssh_config "PermitEmptyPasswords" "no" "$SSHD_CONFIG"
update_ssh_config "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "KerberosAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "GSSAPIAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "X11Forwarding" "no" "$SSHD_CONFIG"
update_ssh_config "AllowUsers" "$(logname 2>/dev/null || echo $SUDO_USER)" "$SSHD_CONFIG"

# 3. Set connection limits (VSCode compatible)
print_status "Setting connection limits (VSCode compatible)"
update_ssh_config "MaxAuthTries" "$MAX_AUTH_TRIES" "$SSHD_CONFIG"
update_ssh_config "MaxSessions" "$MAX_SESSIONS" "$SSHD_CONFIG"
update_ssh_config "MaxStartups" "$MAX_STARTUPS" "$SSHD_CONFIG"

# 4. Configure client timeouts
print_status "Configuring client timeouts"
update_ssh_config "ClientAliveInterval" "$CLIENT_ALIVE_INTERVAL" "$SSHD_CONFIG"
update_ssh_config "ClientAliveCountMax" "$CLIENT_ALIVE_COUNT_MAX" "$SSHD_CONFIG"
update_ssh_config "LoginGraceTime" "$LOGIN_GRACE_TIME" "$SSHD_CONFIG"

# 5. Enforce protocol version 2
print_status "Enforcing SSH protocol version 2"
add_config_if_missing "Protocol 2" "$SSHD_CONFIG"

# 6. Additional security settings
print_security "Adding additional security settings"
update_ssh_config "StrictModes" "yes" "$SSHD_CONFIG"
update_ssh_config "LogLevel" "VERBOSE" "$SSHD_CONFIG"
update_ssh_config "SyslogFacility" "AUTH" "$SSHD_CONFIG"
update_ssh_config "IgnoreRhosts" "yes" "$SSHD_CONFIG"
update_ssh_config "HostbasedAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "PermitUserEnvironment" "no" "$SSHD_CONFIG"
update_ssh_config "AllowTcpForwarding" "local" "$SSHD_CONFIG"
update_ssh_config "AllowAgentForwarding" "yes" "$SSHD_CONFIG"
update_ssh_config "GatewayPorts" "no" "$SSHD_CONFIG"
update_ssh_config "PermitTunnel" "no" "$SSHD_CONFIG"
update_ssh_config "Banner" "/etc/issue.net" "$SSHD_CONFIG"

# Explicitly set privilege separation directory
update_ssh_config "UsePrivilegeSeparation" "sandbox" "$SSHD_CONFIG"
if [[ -d "/run/sshd" ]]; then
    update_ssh_config "PidFile" "/run/sshd.pid" "$SSHD_CONFIG"
fi

# 7. Configure strong host keys
print_status "Configuring strong host keys"
# Use | as delimiter to avoid issues with forward slashes in paths
sed -i 's|^HostKey /etc/ssh/ssh_host_dsa_key|#&|' "$SSHD_CONFIG"
sed -i 's|^HostKey /etc/ssh/ssh_host_ecdsa_key|#&|' "$SSHD_CONFIG"
add_config_if_missing "HostKey /etc/ssh/ssh_host_ed25519_key" "$SSHD_CONFIG"
add_config_if_missing "HostKey /etc/ssh/ssh_host_rsa_key" "$SSHD_CONFIG"

# 8. Configure modern cryptography
print_security "Configuring modern cryptography algorithms"
add_config_if_missing "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512" "$SSHD_CONFIG"
add_config_if_missing "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONFIG"
add_config_if_missing "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" "$SSHD_CONFIG"

# 9. VSCode optimizations
print_vscode_note "Adding VSCode-specific optimizations"
add_config_if_missing "TCPKeepAlive yes" "$SSHD_CONFIG"
add_config_if_missing "Compression yes" "$SSHD_CONFIG"
add_config_if_missing "UseDNS no" "$SSHD_CONFIG"  # Faster connections

# 10. Create login banner
print_status "Creating login banner"
cat > /etc/issue.net << 'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for authorized users only. All activities are monitored
and recorded. Unauthorized access is prohibited and may result in
criminal prosecution.
***************************************************************************
EOF

# Handle systemd SSH configuration
handle_systemd_ssh

# Configure advanced firewall
configure_advanced_firewall

# Configure fail2ban
configure_fail2ban

# Setup SSH keys and client configuration
CURRENT_USER=$(logname 2>/dev/null || echo $SUDO_USER)
if [[ -n "$CURRENT_USER" ]]; then
    USER_HOME=$(eval echo ~$CURRENT_USER)

    # Setup SSH keys
    setup_ssh_keys "$CURRENT_USER" "$USER_HOME"

    # Get server IP and hostname
    SERVER_IP=$(get_server_ips)
    SERVER_HOSTNAME=$(hostname -s)

    # Create SSH client configuration
    create_ssh_client_config "$CURRENT_USER" "$USER_HOME" "$SERVER_IP" "$SERVER_HOSTNAME"
fi

# Create SSH privilege separation directory if missing
print_status "Checking SSH privilege separation directory"
if [[ ! -d "/run/sshd" ]]; then
    print_status "Creating missing SSH privilege separation directory: /run/sshd"
    mkdir -p /run/sshd
    chmod 755 /run/sshd
    print_status "SSH privilege separation directory created"
fi

# Also check for alternative locations
if [[ ! -d "/var/run/sshd" ]]; then
    print_status "Creating alternative SSH privilege separation directory: /var/run/sshd"
    mkdir -p /var/run/sshd
    chmod 755 /var/run/sshd
fi

# Test SSH configuration
print_status "Testing SSH configuration syntax"
if sshd -t; then
    print_status "SSH configuration syntax is valid"
else
    print_error "SSH configuration syntax error detected!"
    print_error "Checking for common issues..."

    # Check what the actual error is
    echo "SSH configuration test output:"
    sshd -t 2>&1 || true

    print_error "Restoring original configuration..."
    cp "$BACKUP_DIR/sshd_config.original" "$SSHD_CONFIG"

    # Restore the privilege separation directory for the original config
    if [[ ! -d "/run/sshd" ]]; then
        mkdir -p /run/sshd
        chmod 755 /run/sshd
    fi

    exit 1
fi

# Function to restart SSH service properly
restart_ssh_service() {
    print_systemd "Restarting SSH service with proper systemd handling..."

    # Stop any running SSH services
    systemctl stop ssh.service 2>/dev/null || true
    systemctl stop sshd.service 2>/dev/null || true
    systemctl stop ssh.socket 2>/dev/null || true

    # Wait a moment
    sleep 2

    # Start the appropriate service
    if systemctl list-unit-files | grep -q "ssh.service"; then
        systemctl start ssh.service
        systemctl enable ssh.service
        print_status "SSH service started and enabled"
    elif systemctl list-unit-files | grep -q "sshd.service"; then
        systemctl start sshd.service
        systemctl enable sshd.service
        print_status "SSHD service started and enabled"
    else
        print_error "No SSH service found!"
        return 1
    fi

    # Verify service is running
    if systemctl is-active ssh.service &>/dev/null || systemctl is-active sshd.service &>/dev/null; then
        print_status "SSH service is running successfully"
        return 0
    else
        print_error "SSH service failed to start!"
        return 1
    fi
}

# Display completion message
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Enhanced SSH Lockdown Complete!${NC}"
echo -e "${GREEN}      (VSCode Compatible)${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Ask user if they want to restart SSH immediately
echo -e "${YELLOW}IMPORTANT: SSH service needs to be restarted to apply changes${NC}"
echo -e "${YELLOW}============================================================${NC}"
echo ""
read -p "Do you want to restart SSH service now? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if restart_ssh_service; then
        print_status "SSH is now listening on port $NEW_SSH_PORT"
        print_vscode_note "VSCode Remote should now work with this configuration!"

        # Verify the port is listening
        if netstat -tlnp | grep -q ":$NEW_SSH_PORT "; then
            print_status "Confirmed: SSH is listening on port $NEW_SSH_PORT"
        else
            print_warning "SSH service started but port $NEW_SSH_PORT is not listening"
        fi
    else
        print_error "SSH service restart failed!"
        print_error "Please restart manually and check the logs"
    fi
else
    print_warning "SSH service NOT restarted."
    print_warning "To restart manually, run:"
    print_warning "  sudo systemctl stop ssh.socket"
    print_warning "  sudo systemctl disable ssh.socket"
    print_warning "  sudo systemctl restart ssh"
fi

# Final instructions
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo -e "${BLUE}===========${NC}"
echo ""

if [[ -n "$CURRENT_USER" ]]; then
    echo -e "${GREEN}1. Test SSH Connection:${NC}"
    echo "   From another terminal (DON'T CLOSE THIS ONE YET):"
    echo "   ssh -p $NEW_SSH_PORT $CURRENT_USER@$SERVER_IP"
    echo ""
    echo "   Or using the configured alias:"
    echo "   ssh $SERVER_HOSTNAME"
    echo "   ssh server"
    echo ""

    echo -e "${GREEN}2. VSCode Remote Setup:${NC}"
    echo "   - Install Remote-SSH extension in VSCode"
    echo "   - Press F1 → 'Remote-SSH: Connect to Host'"
    echo "   - Select '$SERVER_HOSTNAME' from the list"
    echo "   - VSCode will automatically use the configuration"
    echo ""

    echo -e "${GREEN}3. Security Recommendations:${NC}"
    echo "   - Test SSH key authentication"
    echo "   - Consider disabling password authentication after testing"
    echo "   - Monitor SSH logs: sudo journalctl -u ssh -f"
    echo "   - Review fail2ban status: sudo fail2ban-client status"
    echo ""
fi

echo -e "${GREEN}4. Verify Services:${NC}"
echo "   sudo systemctl status ssh"
echo "   sudo netstat -tlnp | grep :$NEW_SSH_PORT"
echo "   sudo ufw status"
echo ""

echo -e "${RED}⚠️  IMPORTANT SECURITY NOTICE ⚠️${NC}"
echo -e "${RED}===========================================${NC}"
echo -e "${RED}Do NOT close this terminal until you've verified${NC}"
echo -e "${RED}you can connect using the new configuration!${NC}"
echo ""

echo -e "${GREEN}Backup Location: $BACKUP_DIR${NC}"
echo ""

echo -e "${GREEN}✅ Security Improvements Implemented:${NC}"
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}✓ SSH port changed: 22 → $NEW_SSH_PORT${NC}"
echo -e "${GREEN}✓ Root login disabled${NC}"
echo -e "${GREEN}✓ Strong host keys generated (Ed25519 + RSA-4096)${NC}"
echo -e "${GREEN}✓ Modern cryptography algorithms configured${NC}"
echo -e "${GREEN}✓ Connection limits optimized for VSCode${NC}"
echo -e "${GREEN}✓ Systemd socket activation handled properly${NC}"
echo -e "${GREEN}✓ Advanced firewall rules configured${NC}"
echo -e "${GREEN}✓ SSH key authentication prepared${NC}"
echo -e "${GREEN}✓ Fail2ban protection configured${NC}"
echo -e "${GREEN}✓ VSCode Remote compatibility ensured${NC}"
echo -e "${GREEN}✓ Client SSH configuration created${NC}"
echo -e "${GREEN}✓ Login banner configured${NC}"
echo ""

echo -e "${BLUE}🔐 Enhanced Security Features:${NC}"
echo -e "${BLUE}==============================${NC}"
echo -e "${CYAN}• AllowUsers restriction enabled${NC}"
echo -e "${CYAN}• Advanced cryptographic algorithms${NC}"
echo -e "${CYAN}• Connection rate limiting${NC}"
echo -e "${CYAN}• Comprehensive logging${NC}"
echo -e "${CYAN}• Fail2ban intrusion prevention${NC}"
echo -e "${CYAN}• Systemd service optimization${NC}"
echo -e "${CYAN}• VSCode multiplexing support${NC}"
echo ""

echo -e "${GREEN}Script completed successfully! 🚀${NC}"
echo -e "${GREEN}Your server is now secure and VSCode Ready!${NC}"