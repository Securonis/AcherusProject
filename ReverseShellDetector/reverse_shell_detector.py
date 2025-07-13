#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reverse Shell Detector
--------------------
Monitors the system for suspicious network connections that may indicate
reverse shell activity:

- Long-lived outbound connections on ports 80/443
- Connections on non-standard ports
- Unexpected processes with network connections
- Known reverse shell patterns

On detection, reports and optionally terminates suspicious connections.

License: GNU General Public License v3.0
Author: Root0Emir - Securonis Linux
"""

import os
import sys
import time
import signal
import logging
import socket
import json
import psutil
import re
import subprocess
import configparser
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict

# Import utility modules
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ''))
from utils.privilege_manager import PrivilegeManager
from utils.isolation_manager import IsolationManager
from utils.performance_optimizer import PerformanceOptimizer
from utils.monitoring_scope import MonitoringScope
from utils.service_activator import ServiceActivator

# Configure logging
log_directory = Path("/var/log/reverse_shell_detector")
log_directory.mkdir(exist_ok=True, parents=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_directory / "reverse_shell_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('reverse_shell_detector')

# Default configuration
DEFAULT_CONFIG = {
    'monitor': {
        'interval': '300',  # 5 minutes between scans
        'log_level': 'INFO',
        'pidfile': '/var/run/reverse_shell_detector.pid',
    },
    'detection': {
        'max_history_size': '1000',
        'web_port_duration_threshold': '3600',  # 1 hour in seconds
        'suspicious_ports': '4444,5555,1337,31337,666,6666',
        'allowed_outbound_users': 'root,www-data',
        'unexpected_outbound_blacklist': 'apache2,nginx,mysql,postgres',
        'enable_shell_pattern_matching': 'true',
    },
    'action': {
        'terminate_connections': 'false',
        'block_ips': 'false',
        'report_dir': '/var/log/reverse_shell_detector/reports',
        'notify_admin': 'false',
    },
    'privilege': {
        'enabled': 'true',
        'drop_privileges': 'true',
        'restore_privileges_for_actions': 'true'
    },
    'isolation': {
        'enabled': 'true',
        'enable_namespaces': 'true',
        'enable_cgroups': 'true',
        'cpu_limit': '20',  # Percentage
        'memory_limit_mb': '512'
    },
    'performance': {
        'enabled': 'true',
        'adaptive_interval': 'true',
        'min_interval': '30',  # Seconds
        'max_interval': '300',  # Seconds
        'cpu_threshold': '80',  # Percentage
        'memory_threshold': '80',  # Percentage
        'sample_window': '5'  # Number of samples to average
    },
    'monitoring_scope': {
        'enabled': 'true',
        'include_processes': 'bash,sh,ksh,zsh,python,perl,ruby,nc,netcat,ncat,telnet,socat',
        'exclude_processes': 'systemd,systemd-*,dbus-daemon,cron,crond',
        'include_users': 'root',
        'exclude_users': 'nobody,www-data',
        'include_connections': '*:*',  # All connections by default
        'exclude_connections': '127.0.0.1:*,*:22,*:53'  # Exclude localhost, SSH, DNS
    },
    'activation': {
        'enabled': 'true',
        'mode': 'adaptive',  # 'always', 'adaptive', 'scheduled', 'trigger'
        'schedule': '0 */2 * * *',  # Every 2 hours in cron format
        'active_duration': '600',  # 10 minutes to stay active when triggered
        'triggers': 'new_connection,connection_spike,system_event',
        'threshold_connections': '3',  # Number of suspicious connections to trigger activation
        'inactivity_timeout': '3600'  # 1 hour of inactivity before deactivation
    }
}

# Define a class to represent a network connection
class Connection:
    """Represents a network connection with process information"""
    
    def __init__(self, 
                 pid: int, 
                 process_name: str,
                 local_addr: str,
                 local_port: int,
                 remote_addr: str,
                 remote_port: int,
                 status: str,
                 create_time: float,
                 cmdline: str = "",
                 username: str = ""):
        """Initialize a Connection object"""
        self.pid = pid
        self.process_name = process_name
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.status = status
        self.create_time = create_time
        self.cmdline = cmdline
        self.username = username
        
        # Additional fields
        self.duration = time.time() - create_time
        self.reason = ""  # Reason for flagging as suspicious
    
    @classmethod
    def from_psutil_connection(cls, conn, process: Optional[psutil.Process] = None) -> Optional['Connection']:
        """Create a Connection object from psutil connection and process"""
        if not process:
            try:
                process = psutil.Process(conn.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None
                
        try:
            create_time = process.create_time()
            process_name = process.name()
            cmdline = " ".join(process.cmdline()) if process.cmdline() else ""
            
            try:
                username = process.username()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                username = ""
                
            # Handle connection data
            laddr = conn.laddr
            raddr = conn.raddr if conn.raddr else ("0.0.0.0", 0)
            
            return cls(
                pid=process.pid,
                process_name=process_name,
                local_addr=laddr.ip,
                local_port=laddr.port,
                remote_addr=raddr[0],
                remote_port=raddr[1],
                status=conn.status,
                create_time=create_time,
                cmdline=cmdline,
                username=username
            )
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'pid': self.pid,
            'process_name': self.process_name,
            'local_addr': self.local_addr,
            'local_port': self.local_port,
            'remote_addr': self.remote_addr,
            'remote_port': self.remote_port,
            'status': self.status,
            'create_time': self.create_time,
            'cmdline': self.cmdline,
            'username': self.username,
            'duration': self.duration,
            'reason': self.reason
        }


class ReverseShellDetector:
    """Detects potential reverse shell connections"""
    
    def __init__(self, config: Optional[Dict[str, Dict[str, str]]] = None):
        """Initialize the detector with configuration"""
        # Load default config
        self.config = config or DEFAULT_CONFIG
        
        # Detection settings
        self.long_connection_threshold = int(self.config['detection'].get('long_connection_threshold', 3600))
        self.check_standard_ports = self.config['detection'].get('check_standard_ports', 'true').lower() == 'true'
        self.check_nonstandard_ports = self.config['detection'].get('check_nonstandard_ports', 'true').lower() == 'true'
        self.check_unexpected_processes = self.config['detection'].get('check_unexpected_processes', 'true').lower() == 'true'
        self.check_known_patterns = self.config['detection'].get('check_known_patterns', 'true').lower() == 'true'
        
        # Action settings
        self.terminate_connections = self.config['action'].get('terminate_connections', 'false').lower() == 'true'
        
        # Whitelist settings
        self._load_whitelist()
        
        # Connection history
        self.history_size = int(self.config['monitor'].get('history_size', 5))
        self.connection_history = []
        
        # Create report directory
        self.report_dir = Path(self.config['monitor'].get('report_dir', '/var/log/reverse_shell_detector/reports'))
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Standard ports and suspicious ports
        self.standard_web_ports = {80, 443, 8080, 8443}
        self.known_suspicious_ports = {4444, 5555, 1337, 31337, 666, 6666}
        
    def _load_whitelist(self):
        """Load whitelisted items from configuration"""
        self.whitelisted_ips = set()
        self.whitelisted_processes = set()
        self.whitelisted_connections = set()
        
        # Parse IPs
        ips = self.config['whitelist'].get('ips', '')
        for ip in ips.split(','):
            ip = ip.strip()
            if ip:
                self.whitelisted_ips.add(ip)
                
        # Parse processes
        processes = self.config['whitelist'].get('processes', '')
        for proc in processes.split(','):
            proc = proc.strip()
            if proc:
                self.whitelisted_processes.add(proc)
                
        # Parse connections
        connections = self.config['whitelist'].get('connections', '')
        for conn in connections.split(','):
            conn = conn.strip()
            if conn:
                self.whitelisted_connections.add(conn)
                
        logger.debug(f"Loaded whitelist: {len(self.whitelisted_ips)} IPs, "
                    f"{len(self.whitelisted_processes)} processes, "
                    f"{len(self.whitelisted_connections)} connections")
                    
    def is_whitelisted_ip(self, ip: str) -> bool:
        """Check if an IP is whitelisted"""
        # Check direct match
        if ip in self.whitelisted_ips:
            return True
            
        # Check if IP is in any whitelisted networks
        try:
            addr = ipaddress.ip_address(ip)
            for network_str in self.whitelisted_ips:
                if '/' in network_str:  # CIDR notation
                    try:
                        network = ipaddress.ip_network(network_str, strict=False)
                        if addr in network:
                            return True
                    except ValueError:
                        pass
        except ValueError:
            pass
            
        return False
        
    def is_whitelisted_process(self, process_name: str) -> bool:
        """Check if a process name is whitelisted"""
        return process_name in self.whitelisted_processes
        
    def is_whitelisted_connection(self, conn: Connection) -> bool:
        """Check if a connection is whitelisted"""
        # Check process
        if self.is_whitelisted_process(conn.process_name):
            return True
            
        # Check IP
        if self.is_whitelisted_ip(conn.remote_addr):
            return True
            
        # Check specific connection
        conn_str = f"{conn.remote_addr}:{conn.remote_port}"
        if conn_str in self.whitelisted_connections:
            return True
            
        local_conn_str = f"{conn.local_addr}:{conn.local_port}"
        if local_conn_str in self.whitelisted_connections:
            return True
            
        return False
        
    def collect_connections(self) -> List[Connection]:
        """Collect all network connections from the system"""
        connections = []
        
        # Try primary method: psutil
        try:
            # Get connections with associated processes
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    # Get all connections for this process
                    for conn in proc.connections(kind='inet'):
                        # Only consider established or listening connections
                        if conn.status in ('ESTABLISHED', 'LISTEN'):
                            connection = Connection.from_psutil_connection(conn, proc)
                            if connection:
                                connections.append(connection)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception as e:
            logger.error(f"Error collecting connections with psutil: {e}")
            
        # If primary method fails or returns no results, try secondary methods
        if not connections:
            logger.warning("Primary connection collection method failed, trying alternatives")
            connections = self._collect_connections_alternative()
            
        logger.info(f"Collected {len(connections)} active connections")
        return connections
        
    def _collect_connections_alternative(self) -> List[Connection]:
        """Alternative methods to collect connections when psutil fails"""
        connections = []
        
        # Try using ss command
        try:
            output = subprocess.check_output(['ss', '-tunp'], text=True)
            # Parse ss output (implementation details omitted for brevity)
            # This would parse the output and create Connection objects
            
        except Exception as e:
            logger.error(f"Error collecting connections with ss: {e}")
            
        # Try using /proc/net files as last resort
        if not connections:
            try:
                self._parse_proc_net_files(connections)
            except Exception as e:
                logger.error(f"Error parsing /proc/net files: {e}")
                
        return connections
        
    def _parse_proc_net_files(self, connections: List[Connection]):
        """Parse /proc/net/tcp and /proc/net/udp files to extract connection information"""
        # Implementation would read and parse these files
        # This is complex and would require mapping inode numbers to processes
        # by examining /proc/{pid}/fd/
        pass
        
    def detect_suspicious_connections(self, connections: List[Connection]) -> Dict[str, List[Connection]]:
        """Detect suspicious connections that may indicate reverse shells"""
        suspicious = {
            'long_lived_web': [],
            'suspicious_ports': [],
            'unexpected_process': [],
            'known_pattern': []
        }
        
        for conn in connections:
            # Skip localhost connections
            if conn.remote_addr in ('127.0.0.1', '::1', '0.0.0.0') or not conn.remote_addr:
                continue
                
            # Skip whitelisted connections
            if self.is_whitelisted_connection(conn):
                continue
                
            # Check for long-lived web port connections (potential C2)
            if self.check_standard_ports and conn.remote_port in self.standard_web_ports:
                if conn.duration > self.long_connection_threshold:
                    conn.reason = f"Long-lived connection to web port {conn.remote_port} ({conn.duration:.1f}s)"
                    suspicious['long_lived_web'].append(conn)
                    
            # Check for connections to known suspicious ports
            if self.check_nonstandard_ports and conn.remote_port in self.known_suspicious_ports:
                conn.reason = f"Connection to suspicious port {conn.remote_port}"
                suspicious['suspicious_ports'].append(conn)
                
            # Check for unexpected processes with network connections
            if self.check_unexpected_processes:
                # Shell processes should generally not have remote connections
                if conn.process_name in ('bash', 'sh', 'zsh', 'dash'):
                    conn.reason = f"Shell process with network connection: {conn.process_name}"
                    suspicious['unexpected_process'].append(conn)
                    
                # Check for Python/Perl/Ruby with direct network connections (often used for shells)
                if conn.process_name in ('python', 'python3', 'perl', 'ruby') and conn.remote_addr != '0.0.0.0':
                    # Look at the command line for network-related args
                    if any(x in conn.cmdline for x in ['-c', '-e', 'socket', 'connect']):
                        conn.reason = f"Scripting language with suspicious args: {conn.cmdline[:50]}..."
                        suspicious['unexpected_process'].append(conn)
                        
            # Check for known reverse shell patterns in command line
            if self.check_known_patterns and conn.cmdline:
                patterns = [
                    r'nc\s+-e',              # netcat with -e
                    r'bash\s+-i',            # interactive bash shell
                    r'python.*socket\..*connect', # Python socket connection
                    r'perl.*\$sock\s*=\s*IO::Socket', # Perl socket
                    r'sh\s+>&',             # Shell redirection
                    r'socat.*exec',          # socat with exec
                    r'mkfifo.*\|\s*sh'      # Named pipe to shell
                ]
                
                for pattern in patterns:
                    if re.search(pattern, conn.cmdline, re.IGNORECASE):
                        conn.reason = f"Known reverse shell pattern detected: {pattern}"
                        suspicious['known_pattern'].append(conn)
                        break
                        
        return suspicious
        
    def update_history(self, connections: List[Connection]):
        """Update the connection history list"""
        self.connection_history.append(connections)
        if len(self.connection_history) > self.history_size:
            self.connection_history.pop(0)
            
    def terminate_suspicious_connection(self, conn: Connection) -> bool:
        """Terminate a suspicious connection"""
        if not self.terminate_connections:
            return False
            
        try:
            # Attempt to kill the process
            process = psutil.Process(conn.pid)
            process.terminate()
            
            # Wait a moment to see if it terminates
            time.sleep(0.2)
            
            # If still running, force kill
            if process.is_running():
                process.kill()
                
            logger.warning(f"Terminated suspicious connection: PID {conn.pid} ({conn.process_name}) "
                          f"connected to {conn.remote_addr}:{conn.remote_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to terminate connection {conn.pid}: {e}")
            return False
            
    def generate_report(self, connections: List[Connection], suspicious: Dict[str, List[Connection]],
                       actions_taken: int) -> str:
        """Generate a detailed report of findings"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'total_connections': len(connections),
            'suspicious': {
                category: [conn.to_dict() for conn in conns]
                for category, conns in suspicious.items()
            },
            'actions_taken': actions_taken,
            'summary': {
                'long_lived_web_count': len(suspicious['long_lived_web']),
                'suspicious_ports_count': len(suspicious['suspicious_ports']),
                'unexpected_process_count': len(suspicious['unexpected_process']),
                'known_pattern_count': len(suspicious['known_pattern'])
            }
        }
        
        # Generate filename with timestamp
        report_file = self.report_dir / f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        
        # Write report to file
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Generated report: {report_file}")
        return str(report_file)
        
    def notify_admin(self, report_file: str, suspicious: Dict[str, List[Connection]]):
        """Send notification to admin about suspicious connections"""
        if not self.config['action']['notify_admin'].lower() == 'true':
            return
            
        admin_email = self.config['action']['admin_email']
        if not admin_email:
            logger.warning("Admin email not configured, skipping notification")
            return
            
        # Count suspicious connections
        counts = {category: len(conns) for category, conns in suspicious.items()}
        total = sum(counts.values())
        
        if total == 0:
            return  # No need to notify if nothing found
            
        # Prepare email content
        subject = f"[SECURITY] Suspicious network connections detected on {socket.gethostname()}"
        
        body = f"""Reverse Shell Detector has detected {total} suspicious connections:
        
- Long-lived connections to web ports: {counts['long_lived_web']}
- Connections to suspicious ports: {counts['suspicious_ports']}
- Unexpected processes with connections: {counts['unexpected_process']}
- Known reverse shell patterns: {counts['known_pattern']}

See the full report at: {report_file}
        """
        
        # Add some examples of suspicious connections
        categories = ['known_pattern', 'unexpected_process', 'suspicious_ports', 'long_lived_web']
        
        for category in categories:
            if suspicious[category]:
                body += f"\n{category.replace('_', ' ').title()}:\n"
                for i, conn in enumerate(suspicious[category][:3]):
                    body += f"- PID {conn.pid} ({conn.process_name}) connected to {conn.remote_addr}:{conn.remote_port} - {conn.reason}\n"
                
        # Try to send email using the mail command
        try:
            p = subprocess.Popen(
                ['mail', '-s', subject, admin_email],
                stdin=subprocess.PIPE
            )
            p.communicate(body.encode())
            logger.info(f"Notification sent to {admin_email}")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            
    def take_action(self, suspicious: Dict[str, List[Connection]]) -> int:
        """Take action on suspicious connections based on configuration"""
        if not self.terminate_connections:
            return 0
            
        terminated_count = 0
        
        # Process highest risk categories first
        for category in ['known_pattern', 'unexpected_process', 'suspicious_ports', 'long_lived_web']:
            for conn in suspicious[category]:
                if self.terminate_suspicious_connection(conn):
                    terminated_count += 1
                    
        return terminated_count


class ReverseShellDetectorService:
    """Main service class for Reverse Shell Detector"""
    
    def __init__(self, config_file: str = None):
        """Initialize the service with optional config file path"""
        self.running = True
        self.config = self._load_config(config_file)
        
        # Configure logging level based on config
        log_level = getattr(logging, self.config['monitor']['log_level'].upper(), logging.INFO)
        logger.setLevel(log_level)
        
        # Initialize security and performance modules
        self._setup_security_and_performance()
        
        # Create detector
        self.detector = ReverseShellDetector(self.config)
        
        # Write PID file
        pid_file = self.config['monitor']['pidfile']
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        logger.info(f"PID written to {pid_file}")
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
    
    def _setup_security_and_performance(self):
        """Setup security and performance modules"""
        service_name = "reverse_shell_detector"
        
        # Initialize isolation manager
        if self.config['isolation']['enabled'].lower() == 'true':
            self.isolation_mgr = IsolationManager(service_name)
            
            if self.config['isolation']['enable_namespaces'].lower() == 'true':
                try:
                    self.isolation_mgr.enable_namespace_isolation()
                    logger.info("Namespace isolation enabled")
                except Exception as e:
                    logger.error(f"Failed to enable namespace isolation: {str(e)}")
                    
            if self.config['isolation']['enable_cgroups'].lower() == 'true':
                try:
                    cpu_limit = int(self.config['isolation']['cpu_limit'])
                    memory_limit = int(self.config['isolation']['memory_limit_mb'])
                    self.isolation_mgr.setup_cgroup(cpu_limit=cpu_limit, memory_limit_mb=memory_limit)
                    logger.info(f"Cgroup resource limits set: CPU {cpu_limit}%, Memory {memory_limit}MB")
                except Exception as e:
                    logger.error(f"Failed to set up cgroup limits: {str(e)}")
        else:
            self.isolation_mgr = None
            logger.info("Isolation features disabled in configuration")
        
        # Initialize privilege manager
        if self.config['privilege']['enabled'].lower() == 'true':
            self.priv_mgr = PrivilegeManager()
            logger.info("Privilege manager initialized")
        else:
            self.priv_mgr = None
            logger.info("Privilege management disabled in configuration")
        
        # Initialize performance optimizer
        if self.config['performance']['enabled'].lower() == 'true':
            self.perf_optimizer = PerformanceOptimizer(service_name)
            self.perf_optimizer.configure(self.config['performance'])
            logger.info("Performance optimizer initialized")
        else:
            self.perf_optimizer = None
            logger.info("Performance optimization disabled in configuration")
        
        # Initialize monitoring scope
        if self.config['monitoring_scope']['enabled'].lower() == 'true':
            self.monitoring_scope = MonitoringScope(service_name)
            self.monitoring_scope.configure(self.config['monitoring_scope'])
            logger.info("Monitoring scope initialized")
        else:
            self.monitoring_scope = None
            logger.info("Monitoring scope filtering disabled in configuration")
        
        # Initialize service activator
        if self.config['activation']['enabled'].lower() == 'true':
            self.service_activator = ServiceActivator(service_name)
            self.service_activator.configure(self.config['activation'])
            
            # Register activation/deactivation handlers
            self.service_activator.register_active_function(self._on_service_activated)
            self.service_activator.register_inactive_function(self._on_service_deactivated)
            
            logger.info(f"Service activator configured in {self.config['activation']['mode']} mode")
            
            # Activate service immediately for first run
            self.service_activator.activate("initial startup")
        else:
            self.service_activator = None
            logger.info("On-demand service activation disabled in configuration")
    
    def _on_service_activated(self):
        """Called when service becomes active"""
        logger.info("Service activated - running with full scanning capabilities")
    
    def _on_service_deactivated(self):
        """Called when service becomes inactive"""
        logger.info("Service deactivated - running with reduced scanning capabilities")
        
    def _load_config(self, config_file: str) -> Dict[str, Dict[str, str]]:
        """Load configuration from file or use defaults"""
        config = configparser.ConfigParser()
        
        # Set default configuration
        for section, options in DEFAULT_CONFIG.items():
            if not config.has_section(section):
                config.add_section(section)
            for key, value in options.items():
                config.set(section, key, value)
                
        # Override with file configuration if provided
        if config_file and os.path.exists(config_file):
            logger.info(f"Loading configuration from {config_file}")
            config.read(config_file)
            
        # Convert to dictionary
        return {section: dict(config.items(section)) for section in config.sections()}
        
    def _handle_signal(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        
    def run(self):
        """Main service loop"""
        logger.info("Reverse Shell Detector service started")
        
        # Apply isolation if configured (must be done early in startup)
        if self.isolation_mgr and self.config['isolation']['enabled'].lower() == 'true':
            try:
                self.isolation_mgr.apply_isolation()
                logger.info("Process isolation applied successfully")
            except Exception as e:
                logger.error(f"Failed to apply process isolation: {str(e)}")
        
        # Drop privileges if configured (after initialization but before main loop)
        if (self.priv_mgr and 
            self.config['privilege']['enabled'].lower() == 'true' and
            self.config['privilege']['drop_privileges'].lower() == 'true'):
            try:
                user = self.config['privilege']['user']
                self.priv_mgr.drop_privileges(user)
                logger.info(f"Dropped privileges to user: {user}")
            except Exception as e:
                logger.error(f"Failed to drop privileges: {str(e)}")
        
        # Default scan interval
        default_interval = int(self.config['monitor']['interval'])
        
        while self.running:
            try:
                # Check if we should be active (if service activator is configured)
                is_active = True
                if self.service_activator:
                    is_active = self.service_activator.is_active
                
                # Start performance monitoring for this scan cycle
                if self.perf_optimizer:
                    self.perf_optimizer.start_operation("detection_scan")
                
                # Perform scan based on service activation status
                if is_active:
                    logger.debug("Starting detection scan with full capabilities")
                    
                    # Temporarily restore privileges for scanning if needed
                    if (self.priv_mgr and 
                        self.config['privilege']['enabled'].lower() == 'true' and
                        self.config['privilege']['restore_privileges_for_actions'].lower() == 'true'):
                        with self.priv_mgr.temporarily_restore_privileges():
                            self._perform_full_scan()
                    else:
                        self._perform_full_scan()
                else:
                    # Perform minimal scan when service is inactive
                    logger.debug("Starting minimal detection scan (reduced capabilities)")
                    self._perform_minimal_scan()
                
                # End performance monitoring
                scan_time = 0
                if self.perf_optimizer:
                    self.perf_optimizer.end_operation("detection_scan")
                    scan_time = self.perf_optimizer.get_last_operation_duration("detection_scan")
                    logger.debug(f"Detection scan completed in {scan_time:.2f}s")
                    
                    # Update system metrics for service activator
                    if self.service_activator:
                        cpu_usage = self.perf_optimizer.get_system_cpu_percent()
                        memory_usage = self.perf_optimizer.get_memory_usage()
                        self.service_activator.update_monitored_value('system_cpu', cpu_usage)
                        self.service_activator.update_monitored_value('system_memory', memory_usage)
                        self.service_activator.update_monitored_value('scan_time', scan_time)
                
                # Determine optimal wait interval
                interval = default_interval
                if self.perf_optimizer and self.config['performance']['adaptive_interval'].lower() == 'true':
                    interval = self.perf_optimizer.get_optimal_interval()
                    logger.debug(f"Using adaptive interval: {interval}s")
                    
                # Wait for next scan
                logger.debug(f"Sleeping for {interval} seconds until next scan")
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(10)  # Shorter wait on error
                
        # Clean up resources
        self._cleanup_resources()
    
    def _perform_full_scan(self):
        """Perform a full detection scan with all capabilities"""
        # Collect network connections
        connections = self.detector.collect_connections()
        
        # Filter connections based on monitoring scope if enabled
        filtered_connections = connections
        if self.monitoring_scope:
            filtered_connections = []
            skipped_count = 0
            
            for conn in connections:
                process_name = conn.process_name
                username = conn.username
                connection_str = f"{conn.remote_addr}:{conn.remote_port}"
                
                # Check if the connection should be monitored based on scope
                if self.monitoring_scope.should_monitor(process=process_name, 
                                                     username=username,
                                                     custom_identifier=connection_str):
                    filtered_connections.append(conn)
                else:
                    skipped_count += 1
            
            logger.debug(f"Monitoring scope filtered out {skipped_count} of {len(connections)} connections")
            
            # Update total connections in service activator
            if self.service_activator:
                self.service_activator.update_monitored_value('total_connections', len(connections))
                self.service_activator.update_monitored_value('monitored_connections', len(filtered_connections))
        
        # Update history of connections for trend analysis
        self.detector.update_history(filtered_connections)
        
        # Detect suspicious connections
        suspicious = self.detector.detect_suspicious_connections(filtered_connections)
        
        # Take action if suspicious connections found
        if any(suspicious.values()):
            total_suspicious = sum(len(conns) for conns in suspicious.values())
            logger.warning(f"Detected {total_suspicious} suspicious connections")
            
            # Log breakdown of suspicious connections
            logger.warning(f"Found suspicious connections: "
                         f"{len(suspicious.get('long_lived_web', []))} long-lived web, "
                         f"{len(suspicious.get('suspicious_ports', []))} suspicious ports, "
                         f"{len(suspicious.get('unexpected_process', []))} unexpected processes, "
                         f"{len(suspicious.get('known_pattern', []))} known patterns")
            
            # Update service activator with number of suspicious connections
            if self.service_activator:
                self.service_activator.update_monitored_value('suspicious_connections', total_suspicious)
                # Trigger activation if there are suspicious connections
                self.service_activator.trigger("new_connection")
                
                # If number exceeds threshold, trigger connection spike event
                threshold = int(self.config['activation']['threshold_connections'])
                if total_suspicious >= threshold:
                    self.service_activator.trigger("connection_spike")
            
            # Process suspicious connections and take actions
            actions_taken = self.detector.take_action(suspicious)
            
            # Generate report
            report_file = self.detector.generate_report(filtered_connections, suspicious, actions_taken)
            
            # Notify admin if configured in the detector
            if 'notify_admin' in self.config.get('action', {}) and self.config['action'].get('notify_admin') == 'true':
                self.detector.notify_admin(report_file, suspicious)
        else:
            logger.info(f"No suspicious connections detected among {len(filtered_connections)} monitored connections")
    
    def _perform_minimal_scan(self):
        """Perform a minimal detection scan when service is inactive"""
        # Only scan for the most critical signs of compromise
        # This is a lightweight version that only checks for known malicious ports
        
        try:
            # Only check for connections on known malicious ports
            malicious_ports = [4444, 5555, 1337, 31337, 666, 6666]  # Commonly used for reverse shells
            suspicious_count = 0
            
            # Use direct system commands to minimize resource usage
            try:
                # Get only the network connections we're interested in
                output = subprocess.check_output(['ss', '-tnp'], text=True)
                lines = output.strip().split('\n')
                
                # Basic parsing to find suspicious connections
                for line in lines[1:]:  # Skip header line
                    if not line.strip():
                        continue
                        
                    parts = line.split()
                    if len(parts) >= 5:  # Make sure we have enough parts
                        try:
                            # Extract remote port
                            remote_addr_port = parts[4]
                            if ':' in remote_addr_port:
                                remote_port = int(remote_addr_port.split(':')[-1])
                                
                                # Check if port is in our malicious list
                                if remote_port in malicious_ports:
                                    suspicious_count += 1
                                    logger.warning(f"Minimal scan: Suspicious connection on port {remote_port}")
                        except (ValueError, IndexError):
                            continue
            except Exception as e:
                logger.error(f"Error in minimal scan command execution: {str(e)}")
            
            # If suspicious connections found, trigger full scan
            if suspicious_count > 0 and self.service_activator:
                logger.info(f"Minimal scan found {suspicious_count} suspicious connections, triggering activation")
                self.service_activator.update_monitored_value('suspicious_minimal', suspicious_count)
                self.service_activator.trigger("new_connection")
        except Exception as e:
            logger.error(f"Error in minimal scan: {str(e)}")
    
    def _cleanup_resources(self):
        """Clean up all resources during shutdown"""
        logger.info("Reverse Shell Detector service shutting down")
        
        # Clean up service activator resources if they exist
        if hasattr(self, 'service_activator') and self.service_activator:
            try:
                self.service_activator.shutdown()
                logger.debug("Service activator shut down successfully")
            except Exception as e:
                logger.error(f"Error shutting down service activator: {str(e)}")
        
        # Clean up isolation resources if they exist
        if hasattr(self, 'isolation_mgr') and self.isolation_mgr:
            try:
                self.isolation_mgr.cleanup_resources()
                logger.debug("Isolation resources cleaned up successfully")
            except Exception as e:
                logger.error(f"Error cleaning up isolation resources: {str(e)}")
        
        # Clean up performance optimizer resources if they exist
        if hasattr(self, 'perf_optimizer') and self.perf_optimizer:
            try:
                self.perf_optimizer.cleanup()
                logger.debug("Performance optimizer resources cleaned up successfully")
            except Exception as e:
                logger.error(f"Error cleaning up performance optimizer: {str(e)}")
        
        # Remove PID file on exit
        try:
            if os.path.exists(self.config['monitor']['pidfile']):
                os.unlink(self.config['monitor']['pidfile'])
                logger.debug("PID file removed successfully")
        except Exception as e:
            logger.error(f"Failed to remove PID file: {e}")
            
        logger.info("All resources cleaned up successfully")


def main():
    """Main function"""
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = "/etc/reverse_shell_detector.conf"
        
    service = ReverseShellDetectorService(config_file)
    service.run()


if __name__ == "__main__":
    main()
