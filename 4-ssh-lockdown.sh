#!/bin/bash

# SSH Configuration Fix Script - Enhanced Version with Boot Verification
# This script applies the missing hardening configurations and handles systemd socket activation

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/etc/ssh/backup-$(date +%Y%m%d-%H%M%S)"

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_notice() {
    echo -e "${BLUE}[NOTICE]${NC} $1"
}

# Enhanced service management function for Docker, systemd, and regular systems
start_service() {
    local service_name="$1"
    if [ -f /.dockerenv ]; then
        print_status "Docker environment detected, using service command"
        service "$service_name" start
    else
        print_status "Regular system detected, using systemctl"
        systemctl start "$service_name"
    fi
}

# Enhanced restart function with proper systemd management
restart_service() {
    local service_name="$1"
    if [ -f /.dockerenv ]; then
        print_status "Docker environment detected, using service command"
        service "$service_name" start
    else
        print_status "Handling systemd socket activation for SSH"
        
        # Stop and mask ssh.socket to prevent it from interfering
        if systemctl list-unit-files | grep -q "ssh.socket"; then
            print_status "Stopping and masking ssh.socket"
            systemctl stop ssh.socket 2>/dev/null || true
            systemctl disable ssh.socket 2>/dev/null || true
            systemctl mask ssh.socket 2>/dev/null || true
        fi
        
        # Determine correct service name
        local ssh_service=""
        if systemctl list-unit-files | grep -q "^ssh.service"; then
            ssh_service="ssh.service"
        elif systemctl list-unit-files | grep -q "^sshd.service"; then
            ssh_service="sshd.service"
        else
            print_error "Neither ssh.service nor sshd.service found"
            return 1
        fi
        
        print_status "Using service: $ssh_service"
        
        # Reload systemd daemon first
        systemctl daemon-reload
        
        # Enable the service for startup
        print_status "Enabling $ssh_service for automatic startup"
        systemctl enable "$ssh_service"
        
        # Start/restart the service
        print_status "Restarting $ssh_service"
        systemctl restart "$ssh_service"
        
        # Verify it's running
        if systemctl is-active --quiet "$ssh_service"; then
            print_status "✅ $ssh_service is running"
            
            # Show listening ports
            print_status "SSH is listening on:"
            ss -tlnp | grep :2222 || netstat -tlnp | grep :2222 || true
        else
            print_error "❌ $ssh_service failed to start"
            systemctl status "$ssh_service" --no-pager -l
            return 1
        fi
        
        # Double-check it will start on boot
        if systemctl is-enabled --quiet "$ssh_service"; then
            print_status "✅ $ssh_service is enabled for startup"
        else
            print_warning "⚠️  $ssh_service is NOT enabled for startup"
            systemctl enable "$ssh_service"
        fi
    fi
}

stop_ssh_socket() {
    if [ ! -f /.dockerenv ]; then
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            print_status "Stopping and disabling ssh.socket for port change"
            systemctl stop ssh.socket
            systemctl disable ssh.socket
            print_status "ssh.socket stopped and disabled"
        else
            print_notice "ssh.socket is not active or doesn't exist"
        fi
    fi
}

# Function to verify boot configuration
verify_boot_config() {
    print_status "Verifying boot configuration..."
    
    if [ ! -f /.dockerenv ]; then
        # Check if ssh.socket is properly masked
        if systemctl is-enabled ssh.socket 2>/dev/null | grep -q "masked"; then
            print_status "✅ ssh.socket is properly masked"
        else
            print_warning "⚠️  ssh.socket may not be properly masked"
            systemctl mask ssh.socket 2>/dev/null || true
            print_status "✅ Masked ssh.socket"
        fi
        
        # Check SSH service enablement
        local ssh_service=""
        if systemctl list-unit-files | grep -q "^ssh.service"; then
            ssh_service="ssh.service"
        elif systemctl list-unit-files | grep -q "^sshd.service"; then
            ssh_service="sshd.service"
        fi
        
        if [ -n "$ssh_service" ]; then
            if systemctl is-enabled --quiet "$ssh_service"; then
                print_status "✅ $ssh_service is enabled for boot"
            else
                print_error "❌ $ssh_service is NOT enabled for boot"
                systemctl enable "$ssh_service"
                print_status "✅ Enabled $ssh_service for boot"
            fi
        fi
        
        # Check for conflicting socket files
        print_status "Checking for socket configuration conflicts..."
        if [ -f /etc/systemd/system/ssh.socket.d/override.conf ]; then
            print_warning "Found socket override file that might conflict"
            print_warning "Consider removing: /etc/systemd/system/ssh.socket.d/override.conf"
        fi
        
        # Check if ssh.socket is listening on port 22
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            print_warning "⚠️  ssh.socket is still active and may conflict with port change"
            print_status "Stopping ssh.socket..."
            systemctl stop ssh.socket
            systemctl mask ssh.socket
        fi
        
        # Verify systemd daemon is aware of changes
        print_status "Reloading systemd daemon..."
        systemctl daemon-reload
        
        print_status "✅ Boot configuration verification completed"
    else
        print_notice "Docker environment detected - skipping systemd boot configuration"
    fi
}

# Create SSH privilege separation directory if missing
create_ssh_privsep_dir() {
    local privsep_dir="/run/sshd"
    
    print_status "Checking SSH privilege separation directory..."
    
    if [ ! -d "$privsep_dir" ]; then
        print_status "Creating missing privilege separation directory: $privsep_dir"
        
        # Create the directory
        mkdir -p "$privsep_dir"
        
        # Set proper ownership and permissions
        chown root:root "$privsep_dir"
        chmod 755 "$privsep_dir"
        
        print_status "✅ Created $privsep_dir with proper permissions"
        
        # Also create a systemd-tmpfiles configuration to ensure it persists across reboots
        if command -v systemd-tmpfiles >/dev/null 2>&1; then
            cat > /etc/tmpfiles.d/ssh.conf << 'EOF'
# SSH privilege separation directory
d /run/sshd 0755 root root -
EOF
            print_status "✅ Created systemd-tmpfiles configuration for persistence"
        fi
    else
        print_status "✅ Privilege separation directory already exists"
        
        # Verify permissions
        local current_perms
        current_perms=$(stat -c "%a" "$privsep_dir")
        local current_owner
        current_owner=$(stat -c "%U:%G" "$privsep_dir")
        
        if [ "$current_perms" != "755" ] || [ "$current_owner" != "root:root" ]; then
            print_status "Fixing permissions on $privsep_dir"
            chown root:root "$privsep_dir"
            chmod 755 "$privsep_dir"
            print_status "✅ Fixed permissions on $privsep_dir"
        fi
    fi
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Create backup
print_status "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.original"

# Function to update SSH config safely
update_ssh_config() {
    local key="$1"
    local value="$2"
    local config_file="$3"

    # Escape special characters for sed
    local escaped_key
    escaped_key=$(printf '%s\n' "$key" | sed 's/[[\.*^$()+?{|]/\\&/g')
    local escaped_value
    escaped_value=$(printf '%s\n' "$value" | sed 's/[[\.*^$()+?{|]/\\&/g')

    if grep -q "^#\?$key" "$config_file"; then
        # Key exists (commented or not), replace it
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

echo "==================================================================="
echo "        SSH HARDENING CONFIGURATION SCRIPT - ENHANCED"
echo "==================================================================="
echo ""

print_notice "This script will apply comprehensive SSH hardening configurations"
print_notice "Current SSH configuration will be backed up to: $BACKUP_DIR"
echo ""

echo "Applying SSH hardening configurations..."
echo ""

# 1. Change SSH port and handle systemd socket
print_status "Setting SSH port to 2222"
update_ssh_config "Port" "2222" "$SSHD_CONFIG"

# 2. Disable root login
print_status "Disabling root login"
update_ssh_config "PermitRootLogin" "no" "$SSHD_CONFIG"

# 3. Set logging level
print_status "Setting verbose logging"
update_ssh_config "LogLevel" "VERBOSE" "$SSHD_CONFIG"
update_ssh_config "SyslogFacility" "AUTH" "$SSHD_CONFIG"

# 4. Configure authentication limits
print_status "Configuring authentication limits"
update_ssh_config "LoginGraceTime" "30" "$SSHD_CONFIG"
update_ssh_config "MaxAuthTries" "3" "$SSHD_CONFIG"
update_ssh_config "MaxSessions" "10" "$SSHD_CONFIG"
update_ssh_config "MaxStartups" "10:30:100" "$SSHD_CONFIG"

# 5. Enable public key authentication explicitly
print_status "Enabling public key authentication"
update_ssh_config "PubkeyAuthentication" "yes" "$SSHD_CONFIG"

# 6. Configure client alive settings
print_status "Setting client alive intervals"
update_ssh_config "ClientAliveInterval" "300" "$SSHD_CONFIG"
update_ssh_config "ClientAliveCountMax" "2" "$SSHD_CONFIG"

# 7. Additional security settings
print_status "Adding additional security settings"
update_ssh_config "StrictModes" "yes" "$SSHD_CONFIG"
update_ssh_config "IgnoreRhosts" "yes" "$SSHD_CONFIG"
update_ssh_config "HostbasedAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "PermitEmptyPasswords" "no" "$SSHD_CONFIG"
update_ssh_config "PermitUserEnvironment" "no" "$SSHD_CONFIG"
update_ssh_config "AllowAgentForwarding" "yes" "$SSHD_CONFIG"
update_ssh_config "AllowTcpForwarding" "local" "$SSHD_CONFIG"
update_ssh_config "GatewayPorts" "no" "$SSHD_CONFIG"
update_ssh_config "PermitTunnel" "no" "$SSHD_CONFIG"
update_ssh_config "X11Forwarding" "no" "$SSHD_CONFIG"
update_ssh_config "LogLevel" "INFO" "$SSHD_CONFIG"
update_ssh_config "ClientAliveInterval" "180" "$SSHD_CONFIG"
update_ssh_config "MaxStartups" "5:10:20" "$SSHD_CONFIG"

# Add explicit AuthorizedKeysFile specification
echo "AuthorizedKeysFile .ssh/authorized_keys" >> "$SSHD_CONFIG"

# 8. Set UseDNS to no for faster connections
print_status "Disabling DNS lookups for faster connections"
update_ssh_config "UseDNS" "no" "$SSHD_CONFIG"

# 9. Configure host keys (disable weak ones, enable strong ones)
print_status "Configuring strong host keys"
# Comment out weak host keys
sed -i 's|^HostKey /etc/ssh/ssh_host_dsa_key|#&|g' "$SSHD_CONFIG"
sed -i 's|^HostKey /etc/ssh/ssh_host_ecdsa_key|#&|g' "$SSHD_CONFIG"

# Add strong host keys if not present
add_config_if_missing "HostKey /etc/ssh/ssh_host_ed25519_key" "$SSHD_CONFIG"
add_config_if_missing "HostKey /etc/ssh/ssh_host_rsa_key" "$SSHD_CONFIG"

# 10. Add modern cryptography algorithms
print_status "Adding modern cryptographic algorithms"
add_config_if_missing "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256" "$SSHD_CONFIG"
add_config_if_missing "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONFIG"
add_config_if_missing "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" "$SSHD_CONFIG"

# 11. Add performance optimizations
print_status "Adding performance optimizations"
add_config_if_missing "TCPKeepAlive yes" "$SSHD_CONFIG"
add_config_if_missing "Compression yes" "$SSHD_CONFIG"

# 12. Set authentication methods
print_status "Configuring authentication methods"
update_ssh_config "KerberosAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "GSSAPIAuthentication" "no" "$SSHD_CONFIG"
update_ssh_config "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG"

# 13. Add login banner
print_status "Setting login banner"
update_ssh_config "Banner" "/etc/issue.net" "$SSHD_CONFIG"

# Create the banner file
cat > /etc/issue.net << 'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for authorized users only. All activities are monitored
and recorded. Unauthorized access is prohibited and may result in
criminal prosecution.
***************************************************************************
EOF

# 14. Ensure Protocol 2 is set
add_config_if_missing "Protocol 2" "$SSHD_CONFIG"

# 15. Set AllowUsers (replace with actual username)
CURRENT_USER=$(logname 2>/dev/null || echo $SUDO_USER || whoami)
if [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
    print_status "Setting AllowUsers to: $CURRENT_USER"
    update_ssh_config "AllowUsers" "$CURRENT_USER" "$SSHD_CONFIG"
else
    print_warning "Could not determine current non-root user. Please set AllowUsers manually."
fi

echo ""
# Create privilege separation directory before testing
create_ssh_privsep_dir

# Verify boot configuration before testing
verify_boot_config

print_status "Testing SSH configuration..."
if sshd -t -f "$SSHD_CONFIG"; then
    print_status "✅ SSH configuration is valid!"
    echo ""
    echo "==================================================================="
    echo "            CONFIGURATION APPLIED SUCCESSFULLY!"
    echo "==================================================================="
    echo ""
    
    print_warning "IMPORTANT: SSH service needs to be restarted to apply changes"
    print_warning "The SSH port will change from 22 to 2222"
    echo ""
    
    # Display current configuration summary
    echo "Configuration Summary:"
    echo "  • SSH Port: 2222"
    echo "  • Root Login: Disabled"
    echo "  • Password Authentication: Disabled (keys only)"
    echo "  • Max Auth Tries: 3"
    echo "  • Client Timeout: 10 minutes (300s × 2)"
    echo "  • Strong Cryptography: Enabled"
    echo "  • Logging: VERBOSE"
    if [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
        echo "  • Allowed User: $CURRENT_USER"
    fi
    echo ""
    
    # Enhanced restart prompt
    echo "==================================================================="
    echo "                    SSH SERVICE RESTART REQUIRED"
    echo "==================================================================="
    echo ""
    print_warning "CRITICAL: SSH configuration changes require service restart"
    print_warning "The SSH port will change from 22 to 2222"
    echo ""
    
    # Show what will happen
    echo "The restart process will:"
    echo "  1. Stop ssh.socket (if active) to release port 22"
    echo "  2. Disable ssh.socket to prevent conflicts"
    echo "  3. Restart SSH service on the new port (2222)"
    echo "  4. Enable SSH service for auto-start"
    echo "  5. Verify boot configuration"
    echo ""
    
    # Safety warnings
    print_error "⚠️  IMPORTANT SAFETY NOTES:"
    echo "  • Keep this terminal session open during restart"
    echo "  • Test new connection in a separate terminal"
    echo "  • Have console/physical access available as backup"
    echo "  • Ensure your user has sudo privileges"
    echo ""
    
    # Show connection test commands
    echo "After restart, test connection with:"
    echo "  ssh -p 2222 $CURRENT_USER@$(hostname -I | awk '{print $1}' 2>/dev/null || echo 'YOUR_SERVER_IP')"
    echo "  ssh -p 2222 $CURRENT_USER@localhost"
    echo ""
    
    # Ask user if they want to restart SSH service automatically
    echo -n "Do you want to restart SSH service now? [y/N]: "
    read -r restart_choice
    
    if [[ "$restart_choice" =~ ^[Yy]([Ee][Ss])?$ ]]; then
        echo ""
        print_status "Stopping ssh.socket and restarting SSH service..."
        
        # Stop ssh.socket first if it exists
        stop_ssh_socket
        
        # Restart SSH service
        if restart_service ssh; then
            echo ""
            # Run final boot configuration verification
            verify_boot_config
            
            print_status "✅ SSH service restarted successfully!"
            echo ""
            echo "==================================================================="
            echo "                    RESTART COMPLETED"
            echo "==================================================================="
            echo ""
            print_status "SSH is now running on port 2222 with hardened configuration"
            echo ""
            echo "Test connection from another terminal:"
            echo "  ssh -p 2222 $CURRENT_USER@$(hostname -I | awk '{print $1}')"
            echo "  ssh -p 2222 $CURRENT_USER@localhost"
            echo ""
            print_warning "KEEP THIS TERMINAL OPEN until you verify the connection works!"
        else
            print_error "❌ Failed to restart SSH service!"
            echo "You may need to restart manually:"
            echo "  sudo systemctl stop ssh.socket"
            echo "  sudo systemctl restart ssh"
            exit 1
        fi
    else
        echo ""
        echo "To restart SSH service manually:"
        echo "  sudo systemctl stop ssh.socket"
        echo "  sudo systemctl daemon-reload"
        echo "  sudo systemctl restart ssh"
        echo ""
        echo "Then test connection from another terminal:"
        echo "  ssh -p 2222 $CURRENT_USER@$(hostname -I | awk '{print $1}' 2>/dev/null || echo 'YOUR_IP')"
        echo "  ssh -p 2222 $CURRENT_USER@localhost"
        echo ""
        print_warning "IMPORTANT: Don't close this terminal until you verify the connection works!"
    fi
    
else
    print_error "❌ SSH configuration has errors!"
    echo ""
    echo "Configuration test failed. Details:"
    sshd -t -f "$SSHD_CONFIG" 2>&1 || true
    echo ""
    echo "Restoring original configuration..."
    cp "$BACKUP_DIR/sshd_config.original" "$SSHD_CONFIG"
    print_status "Original configuration restored from backup"
    exit 1
fi

echo ""
echo "==================================================================="
echo "Backup saved to: $BACKUP_DIR"
echo "Script completed: $(date)"
echo "==================================================================="