# Zombie Hunter - Suspicious Process Watchdog

## Overview

Zombie Hunter is an advanced Linux userspace hardening service for Securonis Linux that monitors for suspicious process activities. It's designed to detect potential post-exploitation persistence techniques and anomalous process behavior that may indicate system compromise.

The service continuously scans running processes and detects:

1. **Zombie Process Accumulation**: Abnormal increase in defunct (zombie) processes
2. **Root Directory Binaries**: Processes running executables directly from the root directory (/)
3. **Anomalous Parent PIDs**: Processes with parent PID 0 (except PID 1)
4. **Suspicious Command Lines**: Base64-encoded commands, shell pipes to bash/sh, and other common attack patterns

## Installation

1. Install required Python dependencies:
```bash
pip3 install psutil
```

2. Copy files to appropriate locations:
```bash
# Copy main script
sudo cp zombie_hunter.py /usr/local/bin/
sudo chmod +x /usr/local/bin/zombie_hunter.py

# Copy configuration
sudo cp zombie_hunter.conf /etc/

# Install systemd service
sudo cp zombie-hunter.service /etc/systemd/system/
```

3. Create necessary directories:
```bash
sudo mkdir -p /var/log/zombie_hunter/reports
```

4. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable zombie-hunter.service
sudo systemctl start zombie-hunter.service
```

## Configuration

The service is configured via `/etc/zombie_hunter.conf`:

### Monitor Settings
- `interval`: Seconds between process scans (default: 60)
- `history_size`: Number of scans to retain for trend analysis (default: 5)
- `log_level`: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `report_dir`: Directory for JSON reports
- `pidfile`: Path to PID file

### Detection Settings
- `max_zombies`: Maximum acceptable number of zombie processes
- `zombie_increase_threshold`: Alert when zombies increase by this amount
- `check_root_binaries`: Enable detection of root directory binaries
- `check_parent_pid`: Enable detection of processes with parent PID 0
- `check_suspicious_cmdline`: Enable detection of suspicious command lines
- `base64_cmdline_min_length`: Minimum length to consider for base64 detection

### Action Settings
- `kill_zombies`: Automatically terminate zombie processes
- `kill_root_binaries`: Automatically terminate root directory binaries
- `kill_suspicious`: Automatically terminate processes with suspicious command lines


### Whitelist Settings
- `processes`: Process names to ignore (comma-separated)
- `users`: Users whose processes to ignore (comma-separated)
- `paths`: Path prefixes to ignore (comma-separated)

## Usage

### Basic Usage

After installation, the service will run automatically. You can check its status:

```bash
sudo systemctl status zombie-hunter
```

### Manual Operation

To run the service manually with default configuration:

```bash
sudo python3 /usr/local/bin/zombie_hunter.py
```

Or specify a custom configuration file:

```bash
sudo python3 /usr/local/bin/zombie_hunter.py /path/to/custom_config.conf
```

### Logs and Reports

- **Service logs**: `/var/log/syslog` or `journalctl -u zombie-hunter`
- **Dedicated logs**: `/var/log/zombie_hunter/zombie_hunter.log`
- **Detailed reports**: `/var/log/zombie_hunter/reports/report-YYYYMMDD-HHMMSS.json`

## Report Format

Each detection generates a JSON report with:

- Timestamp and hostname
- Total process count
- Suspicious processes by category (zombie, root_binary, parent_pid_zero, suspicious_cmdline)
- Actions taken (process terminations)
- Summary statistics

## Security Considerations

- The service must run as root to inspect all processes
- The systemd service is hardened with security protections
- Whitelisting is important to reduce false positives
- Automatic process termination should be enabled cautiously

## Troubleshooting

1. **Service fails to start**:
   - Check log files with `journalctl -u zombie-hunter`
   - Verify Python and psutil are installed
   - Ensure directories exist with proper permissions

2. **False positives**:
   - Adjust whitelist settings in configuration
   - Increase thresholds if needed
   - Run with DEBUG log level for detailed information

3. **Email notifications not working**:
   - Verify mail command is installed and configured
   - Check admin_email is set correctly

## Contributing

This service is part of the Securonis Linux userspace hardening projects. For contributions or bug reports, please contact the Securonis security team.

## License

Copyright © 2023 Securonis Linux Team. All rights reserved.
