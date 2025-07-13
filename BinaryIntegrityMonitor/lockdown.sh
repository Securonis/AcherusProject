#!/bin/bash
# Binary Integrity Monitor - Lockdown Script
# This script is executed when binary tampering is detected
# It implements emergency lockdown procedures to protect the system

set -e  # Exit on error

# Check if we have an incident report
if [ $# -ge 1 ]; then
  INCIDENT_REPORT="$1"
  echo "Incident report: $INCIDENT_REPORT"
else
  echo "No incident report provided"
  INCIDENT_REPORT=""
fi

# Get hostname for logs
HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
LOCKFILE="/var/run/system_lockdown"

# Log to syslog with high priority
logger -p auth.alert "SECURITY ALERT: Binary integrity violation detected! System entering lockdown mode."

# Create a lockfile to indicate the system is in lockdown mode
touch "$LOCKFILE"
echo "$TIMESTAMP - System locked down due to binary integrity violation" > "$LOCKFILE"

# Send alert to system console
wall <<EOF
!!! SECURITY ALERT !!!
Binary integrity violation detected at $TIMESTAMP
System is entering lockdown mode.
Contact system administrator immediately.
EOF

# Disable network interfaces except loopback
echo "Restricting network access..."
for iface in $(ip -o link show | grep -v 'lo' | awk -F': ' '{print $2}'); do
  if [ "$iface" != "lo" ]; then
    ip link set "$iface" down
    logger -p auth.alert "Lockdown: Disabled network interface $iface"
  fi
done

# Kill potentially compromised services
echo "Stopping non-essential services..."
for service in ssh nginx apache2 vsftpd httpd smbd; do
  if systemctl is-active --quiet "$service"; then
    systemctl stop "$service"
    logger -p auth.alert "Lockdown: Stopped service $service"
  fi
done

# Restrict new process creation
echo "Restricting process creation..."
if [ -f "/etc/security/limits.d/lockdown.conf" ]; then
  echo "lockdown.conf exists, not overwriting"
else
  echo "Creating process restrictions..."
  echo "* hard nproc 100" > /etc/security/limits.d/lockdown.conf
  echo "* hard maxlogins 2" >> /etc/security/limits.d/lockdown.conf
fi

# Save system state information for forensics
echo "Collecting system state information..."
FORENSICS_DIR="/var/log/binary_integrity/forensics-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$FORENSICS_DIR"

# Save process listing
ps auxww > "$FORENSICS_DIR/ps_output.txt"

# Save network connections
netstat -tupan > "$FORENSICS_DIR/netstat_output.txt"
ss -tupan > "$FORENSICS_DIR/ss_output.txt"

# Save logged in users
who > "$FORENSICS_DIR/who_output.txt"
last -20 > "$FORENSICS_DIR/last_output.txt"

# Save recent authentications
grep "authentication" /var/log/auth.log > "$FORENSICS_DIR/auth_log.txt" 2>/dev/null || true

# Save loaded kernel modules
lsmod > "$FORENSICS_DIR/lsmod_output.txt"

# Check for rootkits if rkhunter is available
if command -v rkhunter >/dev/null 2>&1; then
  echo "Running rootkit check..."
  rkhunter --check --skip-keypress > "$FORENSICS_DIR/rkhunter_output.txt" 2>&1 || true
fi

# Archive the forensics directory
tar -czf "$FORENSICS_DIR.tar.gz" -C "$(dirname "$FORENSICS_DIR")" "$(basename "$FORENSICS_DIR")"

# Email notification removed as requested

# Log completion
logger -p auth.alert "Lockdown procedures completed. System is now in restricted mode."
echo "System lockdown complete."

exit 0
