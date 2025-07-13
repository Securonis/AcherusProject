# Dynamic Cron & Timer Hunter

A security tool that monitors crontab files, `/etc/cron.*` directories, and systemd timer units for changes to detect potential persistence mechanisms and suspicious activities.

## Features

- **Real-time monitoring** of crontab files and systemd timer units for changes
- **Detection of suspicious patterns** in cron jobs and timer units (e.g., wget/curl downloads, base64 encoded commands)
- **User crontab monitoring** for all users on the system
- **Detailed change tracking** with diff logging for modified files
- **Persistence detection** to identify potential backdoors and malicious scheduled tasks
- **Configurable alerting** for suspicious activities

## Installation

### Prerequisites

- Python 3.6+
- Linux system with systemd
- Root privileges (for monitoring system cron files)

### Automatic Installation

1. Clone this repository or download the files
2. Run the installation script:

```bash
sudo ./install.sh
```

### Manual Installation

1. Copy the Python files to `/usr/local/bin/`:

```bash
sudo cp cron_hunter.py config.py /usr/local/bin/
sudo chmod +x /usr/local/bin/cron_hunter.py
```

2. Copy the systemd service file:

```bash
sudo cp cron_hunter.service /etc/systemd/system/
```

3. Create the log directory:

```bash
sudo mkdir -p /var/log
```

4. Start and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cron_hunter.service
sudo systemctl start cron_hunter.service
```

## Configuration

Edit the configuration in `/usr/local/bin/config.py` to customize:

- Directories and files to monitor
- Check interval
- Suspicious patterns to detect
- Logging settings
- Alert command

## Logs

Logs are written to `/var/log/cron_hunter.log` by default. View the logs with:

```bash
sudo tail -f /var/log/cron_hunter.log
```

## Alerts

Configure the `ALERT_COMMAND` in `config.py` to send alerts via email, Slack, or other notification methods. For example:

```python
# Send email alerts
ALERT_COMMAND = "echo '%MESSAGE%' | mail -s 'Cron Hunter Alert' admin@example.com"

# Send Slack webhook alerts
ALERT_COMMAND = "curl -X POST -H 'Content-type: application/json' --data '{\"text\":\"%MESSAGE%\"}' YOUR_SLACK_WEBHOOK_URL"
```

## Security Considerations

- The service runs as root to access all cron files and user crontabs
- Systemd hardening options are enabled in the service file
- Consider restricting access to the log file which may contain sensitive information

## Troubleshooting

If the service fails to start:

1. Check the service status:

```bash
sudo systemctl status cron_hunter.service
```

2. Verify permissions on Python files:

```bash
sudo chmod +x /usr/local/bin/cron_hunter.py
```

3. Check for Python dependencies:

```bash
sudo python3 -c "import sys, logging, subprocess, re, hashlib, json, tempfile"
```

## License

MIT
