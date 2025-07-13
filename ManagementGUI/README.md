# Acherus Project Management GUI

> **PROTOTYPE NOTICE**: This GUI is a prototype implementation and has not been extensively tested due to time constraints. Use at your own risk and expect potential issues.

**Author**: root0emir

**License**: GNU General Public License v3.0 (GPL-3.0)

A modern, comprehensive PyQt5-based graphical interface for managing all Acherus Project security tools.

## Features

- **Centralized Dashboard**: View status of all security tools in one place
- **Service Management**: Start, stop, restart, enable, and disable systemd services
- **Log Viewing**: Browse and monitor log files with real-time updates
- **Configuration Editing**: Edit configuration files with syntax highlighting
- **Documentation Access**: Quickly access documentation for each tool
- **Resource Monitoring**: Track CPU and memory usage of security tools

## Requirements

- Python 3.6 or higher
- PyQt5
- PyQtWebEngine (for documentation viewing)
- psutil (for process monitoring)
- Linux system with systemd (for service management)

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Ensure the tool is run with appropriate permissions to manage systemd services:

```bash
# For service management functionality
sudo apt install policykit-1
```

## Usage

Start the management GUI:

```bash
python launch.py
```

For service management functionality, you may need elevated privileges:

```bash
sudo python launch.py
```

## Dashboard

The dashboard provides an overview of all Acherus Project security tools:

- View active/inactive status of each tool
- Quick access to detailed information for each tool
- Start/stop all services with a single click

## Individual Tool Tabs

Each security tool has its own dedicated tab with:

- Service control (start, stop, restart, enable/disable)
- Configuration file editing
- Log file viewing with real-time updates
- Documentation access

## Configuration Editing

The configuration editor provides:

- Syntax highlighting for better readability
- Automatic backup creation before saving changes
- Error prevention and validation

## Log Viewing

The log viewer allows you to:

- View real-time log updates
- Browse historical log files
- Export logs for further analysis

## Troubleshooting

If you encounter issues with service management:

1. Ensure you have appropriate permissions (sudo or membership in appropriate groups)
2. Verify that systemd is running on your system
3. Check that the service files are properly installed at /etc/systemd/system/

## Security Notes

This tool requires elevated privileges to manage systemd services. Always review configuration changes carefully before saving them, as they affect system security tools.

## License

This tool is part of the Acherus Project security suite and is governed by the same license terms as the main project.
