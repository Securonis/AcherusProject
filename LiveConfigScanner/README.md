# Live Configuration Integrity Scanner

## Overview

Live Configuration Integrity Scanner is an advanced Linux security tool that monitors critical system configuration files for unauthorized changes, helping detect silent privilege escalation attempts, backdoors, and other unauthorized modifications.

The service periodically takes snapshots of important configuration files and detects:

1. **Permission Changes**: Detects modifications to file permissions that could indicate security weakening
2. **Ownership Changes**: Identifies altered file ownership that may grant unauthorized access
3. **Content Changes**: Discovers modifications to file contents with detailed diffs
4. **File Creation/Deletion**: Monitors for unexpected addition or removal of tracked files

## Key Features

- **Real-time Detection**: Periodic scanning with configurable intervals
- **Comprehensive Monitoring**: Tracks key system files (/etc/passwd, /etc/shadow, /etc/sudoers, etc.)
- **Detailed Change Reporting**: Line-by-line diffs of file content changes
- **Admin Notifications**: Email alerts when changes are detected
- **Extensive Logging**: Detailed logs and reports for security forensics
- **Whitelist Support**: Ignore expected changes with regex pattern matching
- **Optional Automatic Restoration**: Can restore original files when unauthorized changes detected
- **Custom Response Scripts**: Execute custom scripts when changes are detected

## Installation

1. Install required Python dependencies (minimal requirements):
```bash
pip3 install pathlib
```

2. Copy files to appropriate locations:
```bash
# Copy main script
sudo cp live_config_scanner.py /usr/local/bin/
sudo chmod +x /usr/local/bin/live_config_scanner.py

# Copy configuration
sudo cp live_config_scanner.conf /etc/

# Install systemd service
sudo cp live-config-scanner.service /etc/systemd/system/
```

3. Create necessary directories:
```bash
sudo mkdir -p /var/log/live_config_scanner/reports
sudo mkdir -p /var/lib/live_config_scanner/snapshots
```

4. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable live-config-scanner.service
sudo systemctl start live-config-scanner.service
```

## Configuration

The service is configured via `/etc/live_config_scanner.conf`:

### Monitor Settings
- `interval`: Seconds between scans (default: 300 = 5 minutes)
- `snapshot_dir`: Directory for storing file snapshots
- `report_dir`: Directory for storing change reports
- `log_level`: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `pidfile`: Path to PID file

### Files Settings
- `track_passwd`: Enable tracking of /etc/passwd
- `track_shadow`: Enable tracking of /etc/shadow
- `track_sudoers`: Enable tracking of /etc/sudoers
- `track_hosts`: Enable tracking of /etc/hosts
- `track_sshd_config`: Enable tracking of /etc/ssh/sshd_config
- `additional_files`: Comma-separated list of additional files to track

### Detection Settings
- `track_permissions`: Enable detection of permission changes
- `track_ownership`: Enable detection of ownership changes
- `track_content`: Enable detection of content changes

### Action Settings

- `restore_backups`: Automatically restore files from snapshot (use with caution!)
- `exec_script`: Path to custom script to execute when changes detected

### Whitelist Settings
- `file_patterns`: Regex patterns to ignore file paths
- `content_patterns`: Regex patterns to ignore content changes

## Usage

### Basic Usage

After installation, the service will run automatically. You can check its status:

```bash
sudo systemctl status live-config-scanner
```

### Manual Operation

To run the service manually with default configuration:

```bash
sudo python3 /usr/local/bin/live_config_scanner.py
```

Or specify a custom configuration file:

```bash
sudo python3 /usr/local/bin/live_config_scanner.py /path/to/custom_config.conf
```

### Logs and Reports

- **Service logs**: `/var/log/syslog` or `journalctl -u live-config-scanner`
- **Dedicated logs**: `/var/log/live_config_scanner/live_config_scanner.log`
- **Detailed reports**: `/var/log/live_config_scanner/reports/report-YYYYMMDD-HHMMSS.json`
- **File snapshots**: `/var/lib/live_config_scanner/snapshots/snapshot-YYYYMMDD-HHMMSS.json`

## Report Format

Each detection generates a JSON report with:

- Timestamp and hostname
- Detailed changes by type (permission, ownership, content, created, deleted)
- File diffs when content changes are detected
- Summary statistics

## Detection Types

### 1. Permission Changes

Detects changes to file permissions that could indicate an attempt to:
- Make sensitive files world-readable
- Make configuration files writable by unauthorized users
- Enable execution of non-executable files

### 2. Ownership Changes

Identifies changes to file ownership that might indicate:
- Attempts to take ownership of system files
- Changes to group access rights
- Privilege escalation through ownership manipulation

### 3. Content Changes

The most important detection category, capturing:
- Addition of unauthorized users to /etc/passwd
- Changes to password hashes in /etc/shadow
- New sudo privileges in /etc/sudoers
- DNS hijacking through /etc/hosts modifications
- Security weakening in SSH configurations

### 4. File Creation/Deletion

Monitors for unexpected:
- Addition of new configuration files
- Removal of critical system files
- Replacement of configuration files

## Security Considerations

- The service must run as root to read sensitive files
- The systemd service is hardened with security protections
- Snapshot storage must be protected from unauthorized access
- Automatic file restoration should be enabled cautiously

## Troubleshooting

1. **Service fails to start**:
   - Check log files with `journalctl -u live-config-scanner`
   - Verify Python dependencies are installed
   - Ensure directories exist with proper permissions

2. **False positives**:
   - Add patterns to whitelist in configuration
   - Run with DEBUG log level for detailed information

3. **Email notifications not working**:
   - Verify mail command is installed and configured
   - Check admin_email is set correctly

## Integration with Other Security Systems

Live Configuration Integrity Scanner works well alongside other security tools:

- **Intrusion Detection Systems**: Complements host-based detection with configuration monitoring
- **Binary Integrity Monitor**: Together provide comprehensive coverage of both binaries and configuration
- **SIEM Systems**: Forward reports to centralized security monitoring

## Custom Response Scripts

The `exec_script` configuration option allows execution of custom scripts when changes are detected. The script is called with the report file path as an argument, enabling:

- Integration with other security systems
- Custom notifications or alerting
- Automatic system lockdown in case of critical changes
- Running additional security checks

Example script:

```bash
#!/bin/bash
# This script is called when changes are detected
# $1 = path to the JSON report file

REPORT_FILE="$1"
CRITICAL_CHANGES=$(jq '.summary.by_type.content' "$REPORT_FILE")

if [ "$CRITICAL_CHANGES" -gt 0 ]; then
  # Take action for critical changes
  echo "CRITICAL: Configuration changes detected" | wall
  # More actions...
fi
```

## Contributing

This service is part of the Securonis Linux userspace hardening projects. For contributions or bug reports, please contact the Securonis security team.

## License

Copyright © 2023 Securonis Linux Team. All rights reserved.
