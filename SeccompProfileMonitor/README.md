# Seccomp Profile Monitor

Seccomp Profile Monitor is a Python-based security tool developed for Securonis Linux that monitors the Seccomp protection status of all processes on the system.

## What Does It Do?

This service:

- Continuously monitors all processes on the system
- Checks Seccomp protection status from `/proc/$pid/status` files
- Detects and reports critical services running without Seccomp protection
- Runs as a systemd service in the background using minimal system resources
- Does not impact Tor routing or system performance

## Seccomp Values

- **0**: Disabled - No Seccomp protection
- **1**: Strict mode - Only allows read, write, exit, sigreturn system calls
- **2**: Filter mode - Allows system calls determined by BPF filter

## Installation

1. Copy the files to the following locations:
   ```bash
   sudo cp seccomp_monitor.py /usr/local/bin/
   sudo chmod +x /usr/local/bin/seccomp_monitor.py
   sudo cp seccomp-monitor.service /etc/systemd/system/
   sudo cp seccomp_monitor.conf /etc/
   ```

2. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable seccomp-monitor.service
   sudo systemctl start seccomp-monitor.service
   ```

## Configuration

The configuration file (`/etc/seccomp_monitor.conf`) includes the following settings:

- `interval`: Check interval (seconds)
- `critical_services`: Critical services to monitor (comma-separated list)
- `ignore_services`: Services to ignore (comma-separated list)
- `log_level`: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## Logs

Service logs can be viewed in the `/var/log/seccomp_monitor.log` file and in the systemd journal (`journalctl -u seccomp-monitor.service`).

## Security Impact

This tool provides system administrators with information about which critical services are running without sandbox protection to reduce the exploit surface. This allows you to:

- Detect services without Seccomp protection
- Identify missing configurations needed to enhance system security
- Detect potential security vulnerabilities in advance and take preventive measures

## Notes

- This service only monitors and does not automatically apply seccomp configurations
- Does not affect traffic and routing over the Tor network
- Uses minimal system resources and has minimal impact on performance

## Developer

This tool is specifically developed for Securonis Linux.
