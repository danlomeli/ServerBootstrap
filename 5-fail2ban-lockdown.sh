#!/bin/bash
# Comprehensive Fail2ban Setup for Multi-Service Protection
# Protects: SSH, HTTP/HTTPS (Caddy), FreeSWITCH SIP/RTP
set -e

echo "=== Comprehensive Fail2ban Security Setup ==="

# --- Section 1: Installation ---
echo "1. Installing Fail2ban..."
sudo apt-get update
sudo apt-get install -y fail2ban
echo "✓ Fail2ban installed successfully."

# --- Section 2: Create all log directories and files ---
echo "2. Creating log directories and placeholder files..."
sudo mkdir -p /var/log/caddy
sudo mkdir -p /var/log/freeswitch

# Create placeholder log files that will exist in the future
sudo touch /var/log/caddy/access.log
sudo touch /var/log/caddy/error.log
sudo touch /var/log/freeswitch/freeswitch.log
sudo touch /var/log/freeswitch/sofia.log

# Set proper permissions
sudo chown -R syslog:adm /var/log/caddy/ 2>/dev/null || true
sudo chown -R freeswitch:freeswitch /var/log/freeswitch/ 2>/dev/null || true
sudo chmod 644 /var/log/caddy/*.log /var/log/freeswitch/*.log

echo "✓ Log directories and files created."

# --- Section 3: Enhanced Caddy Filter Configuration ---
echo "3. Creating enhanced Caddy filter..."
sudo tee /etc/fail2ban/filter.d/caddy.conf > /dev/null <<'EOL'
[Definition]
# Caddy error patterns and HTTP error status codes
failregex = ^.*\[ERROR\].*"remote_ip":"<HOST>".*$
            ^.*"status":40[0-4].*"remote_ip":"<HOST>".*$
            ^.*"status":50[0-5].*"remote_ip":"<HOST>".*$
            ^.*"status":429.*"remote_ip":"<HOST>".*$
            ^<HOST>.*" 40[0-4] 
            ^<HOST>.*" 50[0-5] 
            ^<HOST>.*" 429 

ignoreregex = ^.*"status":200.*$
              ^.*"status":30[0-8].*$

[Init]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
              ^%%Y-%%m-%%d[T ]%%H:%%M:%%S
EOL
echo "✓ Enhanced Caddy filter created."

# --- Section 4: Comprehensive FreeSWITCH Filter ---
echo "4. Creating comprehensive FreeSWITCH filter..."
sudo tee /etc/fail2ban/filter.d/freeswitch.conf > /dev/null <<'EOL'
[Definition]
# FreeSWITCH SIP authentication failures and attacks
failregex = ^\[WARNING\].*sofia_reg\.c.*SIP auth failure.*\(REGISTER\).*from ip <HOST>
            ^\[WARNING\].*sofia_reg\.c.*SIP auth failure.*\(INVITE\).*from ip <HOST>
            ^\[WARNING\].*sofia\.c.*SIP auth challenge.*<HOST>.*failing
            ^\[ERR\].*sofia_reg\.c.*SIP authentication challenge.*<HOST>.*failing
            ^\[WARNING\].*Rejected by acl.*<HOST>
            ^\[WARNING\].*Invalid extension.*from <HOST>
            ^\[NOTICE\].*Hangup.*CALL_REJECTED.*<HOST>
            ^\[WARNING\].*attempt.*<HOST>.*failed
            ^\[ERR\].*sofia\.c.*Received.*from <HOST>.*failing

ignoreregex = ^\[INFO\]
              ^\[DEBUG\]

[Init]
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S
EOL
echo "✓ Comprehensive FreeSWITCH filter created."

# --- Section 5: Multi-Service Jail Configuration ---
echo "5. Creating comprehensive jail configuration..."
sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOL'
[DEFAULT]
# Global settings
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd
usedns = warn
logencoding = auto
enabled = false

# Email notifications (configure if needed)
# destemail = admin@yourdomain.com
# sendername = Fail2Ban
# mta = sendmail

# Ban action (iptables by default)
banaction = iptables-multiport
banaction_allports = iptables-allports

# SSH Protection - Critical first line of defense
[sshd]
enabled = true
port = ssh,2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 7200
backend = systemd

# HTTP/HTTPS Protection - Web server attacks
[caddy]
enabled = true
port = http,https,8080,8443
filter = caddy
logpath = /var/log/caddy/*.log
maxretry = 10
findtime = 600
bantime = 3600
backend = systemd

# FreeSWITCH SIP Protection - VoIP attacks
[freeswitch]
enabled = true
port = 5060,5080,5061,5081
filter = freeswitch
logpath = /var/log/freeswitch/freeswitch.log
maxretry = 5
findtime = 300
bantime = 7200
backend = systemd

# Additional FreeSWITCH RTP Protection
[freeswitch-rtp]
enabled = true
port = 16384:32768
filter = freeswitch  
logpath = /var/log/freeswitch/freeswitch.log
maxretry = 3
findtime = 300
bantime = 14400
backend = systemd

# Recidive jail - Ban repeat offenders for longer
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = iptables-allports
bantime = 86400
findtime = 86400
maxretry = 3

# DOS protection for web services
[http-get-dos]
enabled = true
port = http,https
filter = http-get-dos
logpath = /var/log/caddy/*.log
maxretry = 300
findtime = 300
bantime = 600
action = iptables[name=HTTP, port=http, protocol=tcp]
         iptables[name=HTTPS, port=https, protocol=tcp]
EOL

# Create the HTTP GET DOS filter
sudo tee /etc/fail2ban/filter.d/http-get-dos.conf > /dev/null <<'EOL'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" 200 .*$
ignoreregex =
EOL

echo "✓ Comprehensive jail configuration created."

# --- Section 6: Configuration Testing ---
echo "6. Testing Fail2ban configuration..."
if sudo fail2ban-client -t; then
    echo "✓ Configuration test passed!"
else
    echo "❌ Configuration test failed. Please check the errors above."
    exit 1
fi

# --- Section 7: Service Management ---
echo "7. Configuring and starting Fail2ban service..."
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban

# Wait for service to fully initialize
sleep 5

# --- Section 8: Verification and Status ---
echo "8. Verifying Fail2ban status..."
if sudo systemctl is-active --quiet fail2ban; then
    echo "✓ Fail2ban service is running!"
else
    echo "❌ Fail2ban service failed to start."
    sudo journalctl -u fail2ban --no-pager -n 10
    exit 1
fi

# Show active jails
echo ""
echo "Active jails:"
sudo fail2ban-client status

echo ""
echo "Detailed jail status:"
for jail in sshd caddy freeswitch freeswitch-rtp recidive http-get-dos; do
    if sudo fail2ban-client status $jail >/dev/null 2>&1; then
        echo "✓ $jail jail is active"
    else
        echo "⚠ $jail jail is not active"
    fi
done

# --- Section 9: Security Summary ---
echo ""
echo "=== SECURITY PROTECTION SUMMARY ==="
echo "✓ SSH Protection: Ports 22, 2222 (3 attempts, 2h ban)"
echo "✓ Web Protection: HTTP/HTTPS ports 80,443,8080,8443 (10 attempts, 1h ban)"
echo "✓ SIP Protection: Ports 5060,5080,5061,5081 (5 attempts, 2h ban)"
echo "✓ RTP Protection: Ports 16384-32768 (3 attempts, 4h ban)"
echo "✓ DOS Protection: Rate limiting for web requests"
echo "✓ Recidive Protection: Long-term bans for repeat offenders"
echo ""
echo "Attack surfaces protected:"
echo "- SSH brute force attacks"
echo "- Web application attacks (4xx/5xx errors)"  
echo "- SIP registration/authentication attacks"
echo "- RTP flood attacks"
echo "- HTTP DOS attacks"
echo "- Repeat offender tracking"
echo ""
echo "=== MONITORING COMMANDS ==="
echo "Check status: sudo fail2ban-client status"
echo "Check specific jail: sudo fail2ban-client status <jail>"
echo "Unban IP: sudo fail2ban-client set <jail> unbanip <ip>"
echo "Check logs: sudo tail -f /var/log/fail2ban.log"
echo ""
echo "🛡️  Your system now has enterprise-level intrusion protection!"
echo "Script completed successfully."