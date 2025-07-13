# Binary Integrity Monitor

Binary Integrity Monitor is a security service developed for Securonis Linux that monitors and protects the integrity of critical system files.

## What Does It Do?

This service:

- Records SHA-256 hash values of important binary files
- Checks these hash values at regular intervals
- When a change is detected:
  - Logs immediate alerts
  - Quarantines the suspicious file
  - Puts the system into "lockdown" mode

## Features

- **Comprehensive Monitoring**: Monitors critical system binaries and libraries
- **Fast Detection**: Can quickly check hundreds of files with multi-threaded architecture
- **Strong Response**: Automatically quarantines suspicious files and puts the system into protection mode
- **Forensic Analysis Support**: Collects detailed logs and forensic information for security incidents
- **Low System Load**: Uses system resources efficiently with adjustable check intervals
- **Flexible Configuration**: Customizable critical file list, check frequency, and response actions

## Installation

1. Copy the files to the following locations:
   ```bash
   sudo cp binary_integrity_monitor.py /usr/local/bin/
   sudo chmod +x /usr/local/bin/binary_integrity_monitor.py
   sudo cp binary-integrity-monitor.service /etc/systemd/system/
   sudo cp binary_integrity_monitor.conf /etc/
   sudo cp lockdown.sh /usr/local/bin/
   sudo chmod +x /usr/local/bin/lockdown.sh
   ```

2. Create necessary directories:
   ```bash
   sudo mkdir -p /var/log/binary_integrity
   sudo mkdir -p /var/quarantine/binaries
   sudo mkdir -p /var/lib/binary_integrity
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable binary-integrity-monitor.service
   sudo systemctl start binary-integrity-monitor.service
   ```

## Configuration

The configuration file (`/etc/binary_integrity_monitor.conf`) includes the following sections:

### [monitor]
- `interval`: Check interval (seconds)
- `quarantine_dir`: Quarantine directory
- `database_path`: Hash database path
- `log_level`: Log level
- `max_workers`: Number of parallel workers
- `lockdown_script`: Path to lockdown script

### [binaries]
- `critical_binaries`: Critical binary files to monitor
- `system_binaries`: System binary file patterns to monitor
- `include_libraries`: Monitor libraries (true/false)
- `critical_libraries`: Critical library file patterns to monitor

### [lockdown]
- `enable_lockdown`: Enable automatic lockdown (true/false)

- `auto_restore_backup`: Automatic restore from backup (true/false)

## Hash Database

The hash database is stored in JSON format at `/var/lib/binary_integrity/hashes.json`. Each entry contains:
- File path
- SHA-256 hash value
- File size
- Last modification time
- Last check time

## Lockdown Mode

When a suspicious file is detected, the system can automatically enter lockdown mode:

1. The suspicious file is quarantined
2. The incident is logged in detail
3. Network interfaces (except loopback) are disabled
4. Non-critical services are stopped
5. New process creation is restricted
6. System state information is collected for forensic analysis
7. Notification is sent to the administrator via email

## Logs and Reporting

- Standard log: `/var/log/binary_integrity/binary_integrity_monitor.log`
- Alert logs: `/var/log/binary_integrity/binary_integrity_alerts.log`
- Incident reports: `/var/log/binary_integrity/incident-*.json`
- Forensic analysis data: `/var/log/binary_integrity/forensics-*.tar.gz`

## Security Impact

This tool provides effective defense against attacks such as binary hooking and trojanized binaries. Malware often achieves persistence by modifying system files. When these changes are detected, the system is locked down and the attacker's access is restricted.

## Notes

- On first run, the service calculates and records hash values for all monitored files
- Designed to not affect Tor routing
- Should be temporarily disabled during system updates
- To prevent unwanted alarms, stop the service before system update processes that modify critical binary files

## Developer

This tool is specifically developed for Securonis Linux.
