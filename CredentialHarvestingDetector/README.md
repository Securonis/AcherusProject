# Credential Harvesting Detector

Credential Harvesting Detector is a security tool developed for Securonis Linux that monitors and detects potential credential theft attempts across the system.

## What Does It Do?

This service:

- Monitors system memory, processes, and file operations for patterns indicating credential harvesting
- Detects memory scraping attacks targeting credentials in RAM
- Identifies suspicious file reads from known credential storage locations
- Monitors network connections for potential credential exfiltration
- Alerts administrators immediately upon detection of suspicious activity

## Features

- **Memory Protection**: Monitors memory regions of sensitive processes for unauthorized access
- **Process Behavior Analysis**: Detects unusual process behavior related to credential access
- **File System Monitoring**: Tracks access to credential storage files and directories
- **Network Traffic Inspection**: Identifies suspicious patterns in network traffic that may indicate credential exfiltration
- **Real-time Alerting**: Provides immediate notifications via configurable alert methods
- **Comprehensive Logging**: Maintains detailed logs for forensic analysis
- **Low Overhead**: Designed for minimal impact on system performance
- **Whitelist Support**: Allows legitimate credential access patterns to be whitelisted

## Installation

1. Copy the files to the following locations:
   ```bash
   sudo cp credential_detector.py /usr/local/bin/
   sudo chmod +x /usr/local/bin/credential_detector.py
   sudo cp credential-detector.service /etc/systemd/system/
   sudo cp credential_detector.conf /etc/
   ```

2. Create necessary directories:
   ```bash
   sudo mkdir -p /var/log/credential_detector
   sudo mkdir -p /var/lib/credential_detector
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable credential-detector.service
   sudo systemctl start credential-detector.service
   ```

## Configuration

The configuration file (`/etc/credential_detector.conf`) includes the following sections:

### [monitor]
- `interval`: Monitoring interval in seconds
- `log_level`: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `pid_file`: Path to the PID file

### [protection]
- `monitor_memory`: Enable memory monitoring (true/false)
- `monitor_files`: Enable file monitoring (true/false)
- `monitor_network`: Enable network monitoring (true/false)
- `sensitive_processes`: List of processes to monitor closely (comma-separated)
- `detection_threshold`: Sensitivity threshold for detection algorithms

### [files]
- `protected_files`: Critical credential files to monitor
- `protected_directories`: Directories containing credential files to monitor
- `ignored_files`: Files to exclude from monitoring

### [network]
- `monitor_ports`: Network ports to monitor for credential exfiltration
- `suspicious_destinations`: Known suspicious network destinations
- `allowed_destinations`: Whitelisted network destinations

### [alerts]

- `alert_command`: External command to execute on detection

### [whitelist]
- `processes`: Processes allowed to access credentials (comma-separated)
- `users`: Users allowed to access credential files (comma-separated)
- `access_patterns`: Regular expression patterns for legitimate credential access

## How It Works

The Credential Harvesting Detector uses multiple detection methods:

1. **Memory Analysis**:
   - Monitors memory regions of processes handling credentials
   - Detects unusual memory access patterns or known memory scraping techniques
   - Identifies unauthorized code injection into credential-handling processes

2. **File System Monitoring**:
   - Monitors access to files containing credentials or authentication information
   - Tracks file operations (read, write, copy) on sensitive files
   - Alerts on unusual access patterns or unauthorized users accessing credential files

3. **Process Behavior Analysis**:
   - Analyzes process execution chains and parent-child relationships
   - Identifies processes attempting to access credentials outside their normal patterns
   - Monitors for known credential dumping tools and techniques

4. **Network Traffic Inspection**:
   - Examines outbound connections for patterns indicating credential exfiltration
   - Detects connections to suspicious destinations
   - Identifies unusual data transfer patterns that may contain credentials

## Logs and Reporting

- Standard log: `/var/log/credential_detector/credential_detector.log`
- Alert log: `/var/log/credential_detector/credential_alerts.log`
- Detection reports: `/var/log/credential_detector/incidents/`
- Status information: Available via `systemctl status credential-detector`

Log entries include:
- Timestamp of detection
- Detection method and confidence level
- Process information (PID, name, user)
- File path or memory region affected
- Network connection details (if applicable)
- Action taken

## Security Impact

This tool provides an additional layer of defense against credential theft attacks, which are often a critical step in privilege escalation and lateral movement during security breaches. By detecting credential harvesting attempts early, it can:

- Prevent unauthorized access to system and user credentials
- Identify compromised systems or user accounts
- Provide early warning of more sophisticated attacks in progress
- Create forensic evidence for post-incident analysis
- Reduce the attack surface for credential-based attacks

## Notes

- The detector is designed to complement, not replace, other security measures
- False positives may occur with certain legitimate administrative tools
- Use the whitelist feature to reduce false positives in your environment
- Regular updates to detection patterns are recommended as new credential theft techniques emerge
- Performance impact is minimal but can be adjusted through the monitoring interval setting

## Developer

This tool is specifically developed for Securonis Linux.