# Anomaly CPU/Memory Hunter

Anomaly CPU/Mem Hunter is a Linux security component that monitors all processes in the system to detect those with excessive CPU or memory usage. This tool helps identify potential malicious activities such as exploits, cryptocurrency mining, and DoS attacks.

## Features

- **Continuous Monitoring:** Periodically monitors CPU and memory usage of all system processes
- **Threshold Detection:** Detects processes exceeding configurable thresholds
- **Memory Dumping:** Can automatically take memory dumps (using gcore) when anomalies are detected
- **Trend Analysis:** Detects sustained high usage patterns rather than short spikes
- **Additional Metrics:** Monitors additional metrics like I/O operations, thread counts, and open file descriptors
- **Whitelisting:** Ability to exclude specific processes, users, or directories from monitoring
- **Baseline Adjustment:** Can dynamically adjust thresholds based on system behavior
- **Alert System:** Configurable alerting mechanism (with email support)
- **Robust Architecture:** PID file management, signal handling, and graceful shutdown support

## Installation

```bash
# Install requirements
sudo apt install python3 python3-pip gcore
sudo pip3 install psutil

# Copy files
sudo cp anomaly_hunter.py /usr/local/bin/
sudo chmod +x /usr/local/bin/anomaly_hunter.py
sudo cp anomaly_hunter.conf /etc/
sudo mkdir -p /var/log/anomaly_hunter/dumps

# Install service file
sudo cp anomaly-hunter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable anomaly-hunter.service
sudo systemctl start anomaly-hunter.service
```

## Configuration

Configuration is stored in `/etc/anomaly_hunter.conf`. Example configuration:

```ini
[monitor]
interval = 30
log_level = INFO
log_file = /var/log/anomaly_hunter.log
pidfile = /var/run/anomaly_hunter.pid
history_size = 10
dump_dir = /var/log/anomaly_hunter/dumps

[thresholds]
cpu_threshold = 90
memory_threshold = 90
cpu_trend_count = 3
memory_trend_count = 3
io_threshold = 10000
max_threads = 500
max_file_descriptors = 1000

[actions]
enable_dump = true
dump_command = gcore -o %DUMP_DIR%/%TIMESTAMP%_%USER%_%PROCESS%_%PID%.core %PID%
max_dump_size = 500
enable_kill = false
enable_email = false
email_to = admin@securonis.local
email_from = anomaly_hunter@securonis.local
email_subject = [ALERT] High resource usage detected

[whitelist]
processes = systemd,init,chrome,firefox,brave,gnome-shell
users = root
paths = /usr/bin/X,/usr/lib/xorg/Xorg

[baselines]
enable_baselines = true
baseline_period = 24
baseline_margin = 20
```

### Configuration Options

#### [monitor]
- `interval`: Check interval (seconds)
- `log_level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `log_file`: Log file location
- `pidfile`: PID file location
- `history_size`: Number of historical measurements to store per process
- `dump_dir`: Directory to store memory dumps

#### [thresholds]
- `cpu_threshold`: CPU usage threshold (%)
- `memory_threshold`: Memory usage threshold (%)
- `cpu_trend_count`: Number of measurements exceeding threshold to trigger CPU anomaly
- `memory_trend_count`: Number of measurements exceeding threshold to trigger memory anomaly
- `io_threshold`: I/O operations threshold (operations/second)
- `max_threads`: Maximum allowed thread count
- `max_file_descriptors`: Maximum allowed open file descriptors

#### [actions]
- `enable_dump`: Enable memory dump creation
- `dump_command`: Command to create dumps
- `max_dump_size`: Maximum process size to dump (MB)
- `enable_kill`: Terminate processes with detected anomalies
- `enable_email`: Enable email alerts
- Related email settings

#### [whitelist]
- `processes`: Process names to ignore
- `users`: User names to ignore
- `paths`: Process paths to ignore

#### [baselines]
- `enable_baselines`: Enable dynamic baseline adjustment
- `baseline_period`: Baseline calculation period (hours)
- `baseline_margin`: Margin to add to baseline (%)

## Running

To start the service:
```bash
sudo systemctl start anomaly-hunter
```

To run manually:
```bash
sudo python3 /usr/local/bin/anomaly_hunter.py /etc/anomaly_hunter.conf
```

## Examining Logs

```bash
tail -f /var/log/anomaly_hunter.log
```

## Examining Memory Dumps

Memory dumps are stored by default in the `/var/log/anomaly_hunter/dumps` directory.

