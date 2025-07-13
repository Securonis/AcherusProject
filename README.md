# Acherus Hardening Project

> **PROTOTYPE NOTICE**: This is a prototype implementation of the Acherus Hardening Project. Due to time constraints, comprehensive testing has not been completed. Use at your own risk and expect potential issues during deployment.

A comprehensive suite of advanced security monitoring and hardening tools for Linux environments, specifically designed for Securonis Linux. These integrated tools provide in-depth security monitoring, intrusion detection, system hardening, and automated response capabilities through a modular framework.

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

**Author**: root0emir

## Overview

The Acherus Project implements a defense-in-depth strategy through a collection of specialized security tools that monitor different aspects of system security. Each tool is designed with focused detection capabilities for specific attack vectors, combined with appropriate response mechanisms including alerts, logging, and automated protective measures.

The project follows a modular design philosophy with five core utility components that have been integrated across all tools:

- **Privilege Management**: Secure privilege separation and dropping using Linux capabilities
- **Process Isolation**: Namespace and cgroup-based isolation mechanisms
- **Performance Optimization**: Adaptive resource management and scan intervals
- **Monitoring Scope**: Fine-grained process filtering and scope control
- **Service Activation**: On-demand service activation policies

This architecture ensures that each security tool operates with minimal performance impact while maintaining maximum security coverage.

## Security Tools Suite

### 1. Zombie Hunter

**Purpose**: Detects and terminates zombie processes that may indicate compromised applications.

**Key Features**:
- Monitors process states to identify zombie processes
- Detects abnormal parent-child process relationships
- Automatically terminates suspicious processes
- Supports whitelisting of known-good processes

**Use Case**: Identifies process-based attacks where the attacker may have spawned orphaned or zombie processes, which could indicate a compromised application or privilege escalation attempt.

[View ZombieHunter Documentation](./ZombieHunter/README.md)

### 2. Dynamic Cron & Timer Hunter

**Purpose**: Monitors crontab, /etc/cron.*, and systemd timer units for suspicious changes.

**Key Features**:
- Real-time detection of new or modified cron jobs and timer units
- Analysis for suspicious patterns (wget, curl, base64, etc.)
- Identification of persistence mechanisms
- Configurable alert thresholds and monitoring intervals

**Use Case**: Prevents attackers from establishing persistence via scheduled tasks, which is a common technique used after initial compromise.

[View Dynamic Cron Hunter Documentation](./DynamicCronHunter/README.md)

### 3. Anomaly CPU/Mem Hunter

**Purpose**: Monitors system processes for CPU and memory usage anomalies.

**Key Features**:
- Continuous monitoring of all processes' resource usage
- Detection of unusual spikes in CPU or memory consumption
- Optional process memory dumping for forensic analysis
- Configurable thresholds and baseline analysis

**Use Case**: Identifies resource-intensive malware such as cryptominers, or denial-of-service attacks that consume excessive system resources.

[View Anomaly CPU/Mem Hunter Documentation](./AnomalyCPUMemHunter/README.md)

### 4. Binary Integrity Monitor

**Purpose**: Monitors and protects critical system files from unauthorized modifications.

**Key Features**:
- Records SHA-256 hash values of important binary files
- Regular integrity verification of system files
- Automatic quarantine of modified files
- System lockdown mode upon detection of compromised binaries

**Use Case**: Protects against attacks that modify system binaries to establish persistence or create backdoors, such as rootkits and trojans.

[View Binary Integrity Monitor Documentation](./BinaryIntegrityMonitor/README.md)

### 5. Seccomp Profile Monitor

**Purpose**: Monitors processes' Seccomp protection status to ensure proper sandboxing.

**Key Features**:
- Checks Seccomp protection status for all running processes
- Detects critical services running without proper Seccomp protection
- Detailed logging and reporting for security auditing
- Minimal performance impact on the system

**Use Case**: Ensures that processes are properly sandboxed using Seccomp to limit the potential damage from exploitation by restricting available system calls.

[View Seccomp Profile Monitor Documentation](./SeccompProfileMonitor/README.md)

### 6. Credential Harvesting Detector

**Purpose**: Detects attempts to steal credentials from memory, files, or network traffic.

**Key Features**:
- Monitors memory regions of sensitive processes
- Tracks access to credential storage files and directories
- Detects unusual process behavior related to credential access
- Identifies suspicious network traffic patterns indicating credential exfiltration

**Use Case**: Prevents credential theft attacks which are often critical steps in privilege escalation and lateral movement during security breaches.

[View Credential Harvesting Detector Documentation](./CredentialHarvestingDetector/README.md)

## Integrated Security Architecture

These tools work together to provide comprehensive security coverage across different aspects of the system:

1. **Process Security**: ZombieHunter and Anomaly CPU/Mem Hunter monitor process behavior for signs of compromise.

2. **Persistence Prevention**: Dynamic Cron & Timer Hunter prevents attackers from establishing persistence mechanisms.

3. **System Integrity**: Binary Integrity Monitor ensures critical system files remain unmodified.

4. **Sandbox Enforcement**: Seccomp Profile Monitor ensures proper process isolation via sandboxing.

5. **Credential Protection**: Credential Harvesting Detector prevents theft of authentication credentials.

By deploying these tools together, the system gains multiple layers of security that cover different attack vectors and techniques commonly used by adversaries.

## Common Features Across Tools

All tools in this suite share these advanced security features and design patterns:

### Core Security Features

- **Privilege Separation**: Operates with least privilege using Linux capabilities for secure privilege dropping
- **Process Isolation**: Utilizes Linux namespaces (PID, network, mount) and cgroups for secure isolation
- **Resource Control**: Implements adaptive resource management to prevent DoS conditions
- **Fine-grained Scope Control**: Configurable monitoring targets with support for inclusion/exclusion patterns
- **On-demand Activation**: Energy and resource efficient activation policies based on system state

### Operational Features

- **Systemd Service Integration**: Runs as hardened background services with proper systemd security controls
- **Configurable Monitoring**: Highly adjustable settings via standardized `.conf` configuration files
- **Low Resource Usage**: Adaptive scanning intervals based on system load and threat level
- **Comprehensive Logging**: Structured JSON and text logging with rate limiting to prevent log flooding
- **Metrics Collection**: Performance and security metrics collection for analysis and tuning
- **Self-protection**: Mechanisms to prevent tool manipulation or termination
- **Whitelist Support**: Sophisticated pattern matching for excluding known-good processes or patterns
- **Tor Compatible**: Designed to work with Tor routing without interference or privacy leaks

## Installation

Each tool has its own installation instructions in its respective README file. The deployment on Securonis Linux follows these standardized steps:

1. Copy the Python scripts to `/usr/local/sbin/` (for primary tools) and `/usr/local/lib/acherus/` (for utility modules)
2. Copy service files to `/etc/systemd/system/`
3. Copy configuration files to `/etc/acherus/`
4. Create necessary log directories under `/var/log/acherus/`
5. Set appropriate permissions (owned by root:root, mode 0750 for scripts, 0640 for configs)
6. Enable and start the systemd service

See `developer.txt` for detailed deployment paths and instructions for Securonis Linux.

### Dependencies

The tools rely on these core dependencies:

- Python 3.8+ with standard library
- psutil (process utilities)
- pyinotify (file monitoring)
- python-prctl (process control)
- libcap-dev and python-cap (Linux capabilities)
- cgroup-tools (for resource control)
- libseccomp-dev (for seccomp filtering)

All dependencies are pre-installed on Securonis Linux.

## Technical Architecture

### Utility Modules

The project employs five core utility modules that are shared across all tools:

1. **privilege_manager.py**: Handles secure privilege dropping and restoration using Linux capabilities
   - Implements fine-grained capability management (CAP_DAC_OVERRIDE, CAP_SYS_PTRACE, etc.)
   - Supports temporary privilege elevation for specific operations
   - Uses secure privilege boundaries and capability inheritance control

2. **isolation_manager.py**: Creates secure process isolation boundaries
   - Implements PID, network, mount, and user namespace isolation
   - Sets up cgroup restrictions for CPU, memory, and I/O limits
   - Provides escape prevention mechanisms

3. **performance_optimizer.py**: Manages resource usage and scanning intervals
   - Implements adaptive scan scheduling based on system load
   - Provides resource usage throttling during high load periods
   - Collects performance metrics for analysis and tuning

4. **monitoring_scope.py**: Controls what processes and resources are monitored
   - Implements pattern-based inclusion and exclusion rules
   - Supports user, group, path, and command line filtering
   - Provides dynamic scope adjustment based on system state

5. **service_activator.py**: Manages service activation policies
   - Supports scheduled, on-demand, and event-triggered activation
   - Implements minimal monitoring mode during inactive periods
   - Provides activation state tracking and metrics

## Security Considerations

### Defense-in-Depth Strategy
- These tools implement a layered defense approach covering different attack vectors
- They should be deployed as part of a broader security strategy including network controls and access management
- The modular design ensures that compromise of one component doesn't affect the entire security posture

### Operational Security
- Regular updates to detection patterns and configurations are essential
- Schedule periodic security audits to validate tool effectiveness
- During system updates or maintenance, use the minimal monitoring mode to prevent false positives
- Configure whitelisting features based on your environment's baseline behavior
- Implement a security monitoring policy for regular log review and alert handling

### Hardening Recommendations
- Enable seccomp profiles for all services whenever possible
- Implement AppArmor/SELinux profiles for the security tools themselves
- Use file integrity monitoring for all security tool binaries and configurations
- Deploy the tools with read-only root filesystem where possible
- Use the isolated mode for maximum security at the cost of slightly higher resource usage

## Management GUI

The Acherus Project includes a centralized management interface for controlling and monitoring all security tools:

- **Service Management**: Enable/disable tools with real-time status monitoring
- **Configuration Editor**: Safely modify security tool configurations with validation
- **Log Viewer**: Centralized log viewing and analysis across all tools
- **Security Dashboard**: Overview of system security status and recent alerts
- **Report Generation**: Create comprehensive security reports for audit purposes

## Development

All tools in this suite are developed specifically for Securonis Linux and follow these design principles:

### Architecture Principles
- **Modular Design**: Each tool focuses on a specific security domain with clear boundaries
- **Core Utilities**: Common functionality extracted into shared libraries to ensure consistency
- **Zero Trust**: No assumptions about the security of the underlying environment
- **Fail Secure**: Default to most restrictive security posture when errors occur
- **Resource Efficiency**: Adaptive resource usage based on threat levels and system load

### Implementation Details
- Python 3.8+ with robust exception handling and secure coding practices
- Standardized YAML/JSON configuration file formats with schema validation
- Structured logging with proper sanitization and rate limiting
- Automated tests for both functionality and security properties
- Comprehensive documentation including threat models and example configurations

## License

These tools are licensed under the GNU General Public License v3.0 (GPL-3.0) and specifically developed for Securonis Linux. See individual tool documentation for any tool-specific licensing information. 