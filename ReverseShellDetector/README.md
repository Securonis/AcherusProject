# Reverse Shell Detector

## Overview

Reverse Shell Detector is an advanced Linux userspace hardening service for Securonis Linux that monitors network connections to identify potential reverse shells and command-and-control (C2) channels. It detects suspicious network activity that may indicate system compromise.

The service continuously scans active network connections and detects:

1. **Long-lived Web Connections**: Persistent connections to ports 80/443 that exceed normal duration thresholds
2. **Suspicious Port Usage**: Connections to ports commonly associated with reverse shells (4444, 5555, etc.)
3. **Unexpected Process Activity**: Shell processes or scripting languages with unusual network connections
4. **Known Reverse Shell Patterns**: Command line patterns matching common reverse shell techniques

## Installation

1. Install required Python dependencies:
```bash
pip3 install psutil
```

2. Copy files to appropriate locations:
```bash
# Copy main script
sudo cp reverse_shell_detector.py /usr/local/bin/
sudo chmod +x /usr/local/bin/reverse_shell_detector.py

# Copy configuration
sudo cp reverse_shell_detector.conf /etc/

# Install systemd service
sudo cp reverse-shell-detector.service /etc/systemd/system/
```

3. Create necessary directories:
```bash
sudo mkdir -p /var/log/reverse_shell_detector/reports
```

4. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable reverse-shell-detector.service
sudo systemctl start reverse-shell-detector.service
```

## Configuration

The service is configured via `/etc/reverse_shell_detector.conf`:

### Monitor Settings
- `interval`: Seconds between connection scans (default: 60)
- `history_size`: Number of scans to retain for trend analysis (default: 5)
- `log_level`: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `report_dir`: Directory for JSON reports
- `pidfile`: Path to PID file

### Detection Settings
- `long_connection_threshold`: Time in seconds to consider a web connection as suspicious (default: 3600 = 1 hour)
- `check_standard_ports`: Enable detection of long-lived connections on standard web ports
- `check_nonstandard_ports`: Enable detection of connections to known suspicious ports
- `check_unexpected_processes`: Enable detection of shell/scripting processes with unexpected connections
- `check_known_patterns`: Enable detection of known reverse shell command patterns

### Action Settings
- `terminate_connections`: Automatically terminate suspicious connections (use with caution!)


### Whitelist Settings
- `ips`: IP addresses or CIDR networks to ignore (comma-separated)
- `processes`: Process names to ignore (comma-separated)
- `connections`: Specific connections to ignore in format "ip:port" (comma-separated)

## Usage

### Basic Usage

After installation, the service will run automatically. You can check its status:

```bash
sudo systemctl status reverse-shell-detector
```

### Manual Operation

To run the service manually with default configuration:

```bash
sudo python3 /usr/local/bin/reverse_shell_detector.py
```

Or specify a custom configuration file:

```bash
sudo python3 /usr/local/bin/reverse_shell_detector.py /path/to/custom_config.conf
```

### Logs and Reports

- **Service logs**: `/var/log/syslog` or `journalctl -u reverse-shell-detector`
- **Dedicated logs**: `/var/log/reverse_shell_detector/reverse_shell_detector.log`
- **Detailed reports**: `/var/log/reverse_shell_detector/reports/report-YYYYMMDD-HHMMSS.json`

## Report Format

Each detection generates a JSON report with:

- Timestamp and hostname
- Total connection count
- Suspicious connections by category
- Actions taken (process terminations)
- Summary statistics

## Detection Techniques

### 1. Long-lived Web Connections

Standard web connections are usually short-lived. Connections that remain open for extended periods (hours) to ports 80/443 may indicate C2 channels disguised as web traffic.

### 2. Suspicious Port Connections

Certain ports are commonly used in reverse shell attacks:
- 4444: Default Metasploit listener
- 5555: Common alternative
- 1337, 31337: "Leet" hacker ports
- 666, 6666: Other common choices

### 3. Unexpected Process Network Activity

Certain processes should generally not have external network connections:
- Shell processes (bash, sh, zsh)
- Scripting languages with suspicious args (python, perl, ruby)

### 4. Known Reverse Shell Patterns

Command lines containing patterns like:
- `nc -e` or `netcat -e` (executing shells)
- `bash -i` (interactive shells)
- Python/Perl socket connections
- Named pipes to shells (mkfifo)

## Security Considerations

- The service must run as root to inspect all network connections
- The systemd service is hardened with security protections
- Whitelisting is important to reduce false positives
- Automatic connection termination should be enabled cautiously

## Troubleshooting

1. **Service fails to start**:
   - Check log files with `journalctl -u reverse-shell-detector`
   - Verify Python and psutil are installed
   - Ensure directories exist with proper permissions

2. **False positives**:
   - Adjust whitelist settings in configuration
   - Run with DEBUG log level for detailed information

3. **Email notifications not working**:
   - Verify mail command is installed and configured
   - Check admin_email is set correctly

## Integration with Other Security Systems

Reverse Shell Detector works well alongside other security tools:

- **Intrusion Detection Systems**: Complements network-based detection with process-socket correlation
- **Binary Integrity Monitor**: Detect both modified binaries and their suspicious network activity
- **Zombie Process Monitor**: Together provide comprehensive view of process and network anomalies

## Contributing

This service is part of the Securonis Linux userspace hardening projects. For contributions or bug reports, please contact the Securonis security team.

## License

Copyright © 2023 Securonis Linux Team. All rights reserved.
