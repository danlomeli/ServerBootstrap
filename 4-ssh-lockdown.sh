#!/bin/bash

# SSH Hardening Script - Revised for RackNerd
# Focuses on reliability across Ubuntu versions with easy rollback

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/etc/ssh/backup-$(date +%Y%m%d-%H%M%S)"

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_notice() { echo -e "${BLUE}[NOTICE]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Detect environment and SSH service name
detect_environment() {
    local ssh_service=""
    
    if [ -f /.dockerenv ]; then
        echo "docker"
        return
    fi
    
    if systemctl list-unit-files 2>/dev/null | grep -q "^ssh.service"; then
        ssh_service="ssh.service"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^sshd.service"; then
        ssh_service="sshd.service"
    else
        echo "unknown"
        return
    fi
    
    echo "$ssh_service"
}

ENV_TYPE=$(detect_environment)

# Universal service restart
restart_ssh() {
    print_status "Restarting SSH service..."
    
    if [ "$ENV_TYPE" = "docker" ]; then
        service ssh restart || service sshd restart
        return $?
    fi
    
    if [ "$ENV_TYPE" = "unknown" ]; then
        print_error "Cannot determine SSH service type"
        return 1
    fi
    
    # Stop and mask socket to prevent conflicts
    if systemctl list-unit-files 2>/dev/null | grep -q "ssh.socket"; then
        systemctl stop ssh.socket 2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
        systemctl mask ssh.socket 2>/dev/null || true
    fi
    
    systemctl daemon-reload
    systemctl enable "$ENV_TYPE"
    systemctl restart "$ENV_TYPE"
    
    if systemctl is-active --quiet "$ENV_TYPE"; then
        print_status "✅ SSH service running on port 2222"
        ss -tlnp 2>/dev/null | grep :2222 || netstat -tlnp 2>/dev/null | grep :2222 || true
        return 0
    else
        print_error "❌ SSH service failed to start"
        systemctl status "$ENV_TYPE" --no-pager -l
        return 1
    fi
}

# Ensure privilege separation directory exists
ensure_privsep_dir() {
    local dir="/run/sshd"
    
    if [ ! -d "$dir" ]; then
        print_status "Creating privilege separation directory"
        mkdir -p "$dir"
        chown root:root "$dir"
        chmod 755 "$dir"
        
        # Add systemd-tmpfiles config for persistence
        if command -v systemd-tmpfiles >/dev/null 2>&1; then
            cat > /etc/tmpfiles.d/ssh.conf << 'EOF'
d /run/sshd 0755 root root -
EOF
        fi
    fi
}

# Safe config update - replaces or adds setting
update_config() {
    local key="$1"
    local value="$2"
    local file="$3"
    
    if grep -q "^#\?${key} " "$file" 2>/dev/null; then
        sed -i "s|^#\?${key} .*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
}

# Add line if not present
add_if_missing() {
    local line="$1"
    local file="$2"
    
    if ! grep -qF "$line" "$file" 2>/dev/null; then
        echo "$line" >> "$file"
    fi
}

echo "==================================================================="
echo "         SSH HARDENING SCRIPT - RACKNERD OPTIMIZED"
echo "==================================================================="
echo ""

# Determine current user
CURRENT_USER=$(logname 2>/dev/null || echo "$SUDO_USER" || whoami)
if [[ "$CURRENT_USER" == "root" ]]; then
    print_error "Cannot determine non-root user. Please run with sudo as your regular user."
    exit 1
fi

print_notice "Target user: $CURRENT_USER"
print_notice "SSH service: $ENV_TYPE"
print_notice "Backup location: $BACKUP_DIR"
echo ""

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.original"
print_status "Configuration backed up"

# Apply hardening settings (no conflicts)
print_status "Applying hardening configuration..."

# Port and access
update_config "Port" "2222" "$SSHD_CONFIG"
update_config "PermitRootLogin" "no" "$SSHD_CONFIG"
update_config "AllowUsers" "$CURRENT_USER" "$SSHD_CONFIG"

# Authentication
update_config "PubkeyAuthentication" "yes" "$SSHD_CONFIG"
update_config "PasswordAuthentication" "no" "$SSHD_CONFIG"
update_config "KbdInteractiveAuthentication" "no" "$SSHD_CONFIG"
update_config "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG"
update_config "PermitEmptyPasswords" "no" "$SSHD_CONFIG"
update_config "KerberosAuthentication" "no" "$SSHD_CONFIG"
update_config "GSSAPIAuthentication" "no" "$SSHD_CONFIG"

# Security limits
update_config "MaxAuthTries" "3" "$SSHD_CONFIG"
update_config "MaxSessions" "10" "$SSHD_CONFIG"
update_config "LoginGraceTime" "30" "$SSHD_CONFIG"
update_config "MaxStartups" "10:30:60" "$SSHD_CONFIG"

# Timeouts
update_config "ClientAliveInterval" "300" "$SSHD_CONFIG"
update_config "ClientAliveCountMax" "2" "$SSHD_CONFIG"

# Logging
update_config "LogLevel" "VERBOSE" "$SSHD_CONFIG"
update_config "SyslogFacility" "AUTH" "$SSHD_CONFIG"

# Additional security
update_config "StrictModes" "yes" "$SSHD_CONFIG"
update_config "IgnoreRhosts" "yes" "$SSHD_CONFIG"
update_config "HostbasedAuthentication" "no" "$SSHD_CONFIG"
update_config "PermitUserEnvironment" "no" "$SSHD_CONFIG"
update_config "X11Forwarding" "no" "$SSHD_CONFIG"
update_config "AllowTcpForwarding" "local" "$SSHD_CONFIG"
update_config "AllowAgentForwarding" "yes" "$SSHD_CONFIG"
update_config "GatewayPorts" "no" "$SSHD_CONFIG"
update_config "PermitTunnel" "no" "$SSHD_CONFIG"
update_config "UseDNS" "no" "$SSHD_CONFIG"
update_config "TCPKeepAlive" "yes" "$SSHD_CONFIG"
update_config "Compression" "yes" "$SSHD_CONFIG"

# Host keys (strong only)
add_if_missing "HostKey /etc/ssh/ssh_host_ed25519_key" "$SSHD_CONFIG"
add_if_missing "HostKey /etc/ssh/ssh_host_rsa_key" "$SSHD_CONFIG"

# Modern crypto
add_if_missing "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256" "$SSHD_CONFIG"
add_if_missing "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONFIG"
add_if_missing "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" "$SSHD_CONFIG"

# Banner
update_config "Banner" "/etc/issue.net" "$SSHD_CONFIG"
cat > /etc/issue.net << 'EOF'
***************************************************************************
                        AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for authorized users only. All activities are monitored.
Unauthorized access is prohibited and may result in prosecution.
***************************************************************************
EOF

print_status "Configuration updated"
echo ""

# Ensure privilege separation directory
ensure_privsep_dir

# Test configuration
print_status "Testing configuration..."
if ! sshd -t -f "$SSHD_CONFIG" 2>&1; then
    print_error "❌ Configuration test failed!"
    echo ""
    print_status "Restoring original configuration..."
    cp "$BACKUP_DIR/sshd_config.original" "$SSHD_CONFIG"
    
    if sshd -t -f "$SSHD_CONFIG" 2>&1; then
        print_status "✅ Original configuration restored and valid"
    else
        print_error "❌ Original configuration also invalid - manual intervention needed"
    fi
    exit 1
fi

print_status "✅ Configuration valid"
echo ""

# Display summary
echo "==================================================================="
echo "                  CONFIGURATION SUMMARY"
echo "==================================================================="
echo "  • SSH Port: 2222 (was 22)"
echo "  • Root Login: Completely disabled"
echo "  • Authentication: Keys only (passwords disabled)"
echo "  • Allowed User: $CURRENT_USER"
echo "  • Max Auth Tries: 3"
echo "  • Session Timeout: 10 minutes"
echo "  • Strong Cryptography: Enabled"
echo "  • Logging: VERBOSE"
echo ""

# Firewall warning
print_warning "⚠️  FIREWALL: Ensure port 2222 is open!"
echo "  RackNerd firewall: Check control panel"
echo "  UFW: sudo ufw allow 2222/tcp"
echo "  iptables: sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT"
echo ""

# Restart prompt
echo "==================================================================="
echo "                  READY TO APPLY CHANGES"
echo "==================================================================="
print_error "⚠️  CRITICAL NOTES:"
echo "  • Keep this terminal open"
echo "  • Test in a NEW terminal before closing this one"
echo "  • Have RackNerd console access ready"
echo "  • Verify firewall allows port 2222"
echo ""
echo "After restart, connect with:"
echo "  ssh -p 2222 $CURRENT_USER@YOUR_SERVER_IP"
echo ""

read -p "Restart SSH now? [y/N]: " -r restart_choice

if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
    echo ""
    if restart_ssh; then
        echo ""
        print_status "✅ SSH restarted successfully on port 2222"
        echo ""
        print_warning "TEST CONNECTION NOW in another terminal:"
        echo "  ssh -p 2222 $CURRENT_USER@\$(hostname -I | awk '{print \$1}')"
        echo ""
        print_error "DO NOT CLOSE THIS TERMINAL until connection verified!"
    else
        print_error "❌ SSH restart failed!"
        echo ""
        print_status "Attempting rollback..."
        cp "$BACKUP_DIR/sshd_config.original" "$SSHD_CONFIG"
        
        if [ "$ENV_TYPE" != "docker" ] && [ "$ENV_TYPE" != "unknown" ]; then
            systemctl restart "$ENV_TYPE" 2>/dev/null || service ssh restart 2>/dev/null || true
        fi
        
        print_status "Rolled back to original configuration"
        exit 1
    fi
else
    echo ""
    print_warning "Configuration applied but NOT active"
    echo ""
    echo "To apply manually:"
    if [ "$ENV_TYPE" != "docker" ] && [ "$ENV_TYPE" != "unknown" ]; then
        echo "  sudo systemctl stop ssh.socket"
        echo "  sudo systemctl restart $ENV_TYPE"
    else
        echo "  sudo service ssh restart"
    fi
    echo ""
    echo "To rollback:"
    echo "  sudo cp $BACKUP_DIR/sshd_config.original $SSHD_CONFIG"
    if [ "$ENV_TYPE" != "docker" ] && [ "$ENV_TYPE" != "unknown" ]; then
        echo "  sudo systemctl restart $ENV_TYPE"
    else
        echo "  sudo service ssh restart"
    fi
fi

echo ""
echo "==================================================================="
echo "Backup: $BACKUP_DIR"
echo "Completed: $(date)"
echo "==================================================================="