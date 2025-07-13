#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zombie Hunter - Suspicious Process Watchdog
------------------------------------------
Monitors the system for suspicious process activity including:
- Defunct (zombie) process accumulation
- Binaries running from root directory
- Processes with parent PID 0 (except PID 1)
- Suspicious command lines (e.g. base64 encoded)

On detection, reports and optionally terminates suspicious processes.

Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import sys
import time
import signal
import logging
import base64
import re
import json
import psutil
import configparser
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict
from contextlib import contextmanager

# Import our security and performance utility modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.privilege_manager import PrivilegeManager
from utils.isolation_manager import IsolationManager
from utils.performance_optimizer import PerformanceOptimizer
from utils.monitoring_scope import MonitoringScope
from utils.service_activator import ServiceActivator

# Configure logging
log_directory = Path("/var/log/zombie_hunter")
log_directory.mkdir(exist_ok=True, parents=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_directory / "zombie_hunter.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('zombie_hunter')

# Default configuration
DEFAULT_CONFIG = {
    'monitor': {
        'interval': '30',  # Check interval in seconds
        'history_size': '5',  # Number of scans to keep for trend analysis
        'log_level': 'INFO',
        'report_dir': '/var/log/zombie_hunter/reports',
        'pidfile': '/var/run/zombie_hunter.pid',
    },
    'detection': {
        'max_zombies': '20',  # Maximum number of acceptable zombie processes
        'zombie_increase_threshold': '5',  # Alert if zombies increase by this amount
        'check_root_binaries': 'true',  # Check for binaries running from root
        'check_parent_pid': 'true',  # Check for processes with parent PID 0
        'check_suspicious_cmdline': 'true',  # Check for suspicious command lines
        'base64_cmdline_min_length': '20',  # Minimum length to consider for base64 detection
    },
    'action': {
        'kill_zombies': 'false',  # Kill zombie processes
        'kill_root_binaries': 'false',  # Kill binaries running from root
        'kill_suspicious': 'false',  # Kill processes with suspicious command lines
    },
    'whitelist': {
        'processes': 'systemd,init,upstart',  # Processes to ignore (comma separated)
        'users': 'root',  # Users whose processes to ignore (comma separated)
        'paths': '/tmp',  # Path prefixes to ignore (comma separated)
    },
    # New security and performance configuration sections
    'privilege': {
        'enabled': 'true',  # Enable privilege separation
        'user': 'acherus_zombie',  # User to run as after dropping privileges
        'group': 'acherus',  # Group to run as after dropping privileges
        'drop_privileges': 'true',  # Whether to drop privileges after initialization
        'restore_privileges_for_actions': 'true',  # Temporarily restore privileges for scanning/killing
    },
    'isolation': {
        'enabled': 'true',  # Enable isolation features
        'enable_namespaces': 'true',  # Use Linux namespace isolation
        'enable_cgroups': 'true',  # Use cgroups for resource limiting
        'cpu_limit': '30',  # CPU usage limit percentage
        'memory_limit_mb': '100',  # Memory usage limit in MB
    },
    'performance': {
        'enable_optimization': 'true',  # Enable performance optimization
        'adaptive_monitoring': 'true',  # Use adaptive monitoring intervals
        'min_interval': '15',  # Minimum interval between scans (seconds)
        'max_interval': '120',  # Maximum interval between scans (seconds)
        'cpu_threshold': '70',  # CPU threshold for reducing scan frequency
        'memory_threshold': '80',  # Memory threshold for reducing scan frequency
    },
    'monitoring_scope': {
        'include_processes': '',  # Comma-separated list of process names to include (empty = all)
        'exclude_processes': 'chrome,firefox,brave',  # Processes to exclude from monitoring
        'include_users': '',  # Comma-separated list of users to include (empty = all)
        'exclude_users': 'nobody,www-data',  # Users to exclude from monitoring
        'include_paths': '',  # Comma-separated list of paths to include (empty = all)
        'exclude_paths': '/var/lib/docker,/proc',  # Paths to exclude from monitoring
        'priority_processes': 'sshd,httpd,nginx',  # Processes to prioritize in monitoring
        'enable_regex': 'false',  # Whether to treat include/exclude patterns as regex
    },
    'activation': {
        'enabled': 'true',  # Enable configurable service activation
        'mode': 'threshold',  # Activation mode: manual, scheduled, event, threshold
        'activation_threshold': '5',  # Number of suspicious processes to trigger activation
        'active_duration': '600',  # How long to stay active after activation (seconds)
        'schedule': '0 * * * *',  # Cron-style schedule for activation (hourly)
        'check_interval': '60',  # How often to check activation conditions (seconds)
    },
}


class Process:
    """Data class to represent process information"""
    def __init__(self, pid: int, ppid: int, name: str, cmdline: str, 
                 exe: str, username: str, status: str, cwd: str = None):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.cmdline = cmdline
        self.exe = exe
        self.username = username
        self.status = status
        self.cwd = cwd
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'pid': self.pid,
            'ppid': self.ppid,
            'name': self.name,
            'cmdline': self.cmdline,
            'exe': self.exe,
            'username': self.username,
            'status': self.status,
            'cwd': self.cwd,
        }
        
    @staticmethod
    def from_psutil(proc: psutil.Process) -> Optional['Process']:
        """Create Process object from psutil.Process"""
        try:
            with proc.oneshot():
                return Process(
                    pid=proc.pid,
                    ppid=proc.ppid(),
                    name=proc.name(),
                    cmdline=' '.join(proc.cmdline()) if proc.cmdline() else '',
                    exe=proc.exe(),
                    username=proc.username(),
                    status=proc.status(),
                    cwd=proc.cwd()
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.debug(f"Error creating Process from psutil: {e}")
            return None


class ZombieDetector:
    """Detects suspicious processes including zombies and other anomalies"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the detector with configuration settings"""
        self.config = config
        self.process_history = []
        self.history_size = int(config['monitor']['history_size'])
        self.max_zombies = int(config['detection']['max_zombies'])
        self.zombie_increase_threshold = int(config['detection']['zombie_increase_threshold'])
        self.check_root_binaries = config['detection']['check_root_binaries'].lower() == 'true'
        self.check_parent_pid = config['detection']['check_parent_pid'].lower() == 'true'
        self.check_suspicious_cmdline = config['detection']['check_suspicious_cmdline'].lower() == 'true'
        self.base64_cmdline_min_length = int(config['detection']['base64_cmdline_min_length'])
        
        # Parse whitelist configurations
        self.whitelist_processes = set(
            process.strip() for process in config['whitelist']['processes'].split(',')
        )
        self.whitelist_users = set(
            user.strip() for user in config['whitelist']['users'].split(',')
        )
        self.whitelist_paths = [
            path.strip() for path in config['whitelist']['paths'].split(',') if path.strip()
        ]
        
        # Report directory
        self.report_dir = Path(config['monitor']['report_dir'])
        self.report_dir.mkdir(exist_ok=True, parents=True)
        
        # Action settings
        self.kill_zombies = config['action']['kill_zombies'].lower() == 'true'
        self.kill_root_binaries = config['action']['kill_root_binaries'].lower() == 'true'
        self.kill_suspicious = config['action']['kill_suspicious'].lower() == 'true'
        
        logger.info(f"Zombie detector initialized: max_zombies={self.max_zombies}, "
                   f"zombie_increase_threshold={self.zombie_increase_threshold}")
    
    def is_whitelisted(self, process: Process) -> bool:
        """Check if a process is whitelisted based on name, user, or path"""
        if process.name in self.whitelist_processes:
            return True
            
        if process.username in self.whitelist_users:
            return True
            
        if process.exe:
            for path in self.whitelist_paths:
                if process.exe.startswith(path):
                    return True
                    
        return False
        
    def is_suspicious_cmdline(self, cmdline: str) -> Tuple[bool, str]:
        """Check if command line is suspicious (e.g. base64 encoded)"""
        if not cmdline or len(cmdline) < self.base64_cmdline_min_length:
            return False, ""
            
        # Detect base64 encoded commands
        base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        
        # Look for potential base64 encoded strings in the command line
        for part in cmdline.split():
            if len(part) >= self.base64_cmdline_min_length and base64_pattern.fullmatch(part):
                # Try to decode and see if it results in printable ASCII
                try:
                    decoded = base64.b64decode(part).decode('ascii')
                    # Check if decoded string contains shell commands or executable names
                    if any(cmd in decoded for cmd in 
                          ['sh ', 'bash', 'python', 'perl', 'exec', 'eval', '/bin/', '/tmp/']):
                        return True, f"Base64 encoded command detected: {decoded[:50]}..."
                except Exception:
                    pass
                    
        # Check for pipe to bash or other suspicious patterns
        suspicious_patterns = [
            r'bash\s+-[ci]',      # bash -c or -i
            r'\|\s*sh',           # pipe to sh
            r'\|\s*bash',         # pipe to bash
            r'wget\s+.+\s*\|',    # wget piped
            r'curl\s+.+\s*\|',    # curl piped
            r'nc\s+-[el]',        # netcat with -e or -l
            r'mkfifo\s+/tmp',     # mkfifo in /tmp (often for reverse shells)
            r'python\s+-c',       # python -c for one-liners
            r'perl\s+-e'          # perl -e for one-liners
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, cmdline):
                return True, f"Suspicious pattern detected: {pattern} in command"
                
        return False, ""
        
    def scan_processes(self) -> Tuple[List[Process], Dict[str, List[Process]]]:
        """Scan all processes and return list of all processes and suspicious ones by category"""
        all_processes = []
        suspicious = {
            'zombie': [],
            'root_binary': [],
            'parent_pid_zero': [],
            'suspicious_cmdline': []
        }
        
        # Get all processes
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'exe', 'username', 'status']):
                process = Process.from_psutil(proc)
                if process is None:
                    continue
                    
                all_processes.append(process)
                
                # Skip whitelisted processes from detection
                if self.is_whitelisted(process):
                    continue
                    
                # Check for zombie processes
                if process.status == 'zombie':
                    suspicious['zombie'].append(process)
                    
                # Check for binaries running from root directory
                if self.check_root_binaries and process.exe and os.path.dirname(process.exe) == '/':
                    suspicious['root_binary'].append(process)
                    
                # Check for processes with parent PID 0 (except PID 1)
                if self.check_parent_pid and process.ppid == 0 and process.pid != 1:
                    suspicious['parent_pid_zero'].append(process)
                    
                # Check for suspicious command lines
                if self.check_suspicious_cmdline and process.cmdline:
                    is_suspicious, reason = self.is_suspicious_cmdline(process.cmdline)
                    if is_suspicious:
                        process.reason = reason  # Add reason field to process
                        suspicious['suspicious_cmdline'].append(process)
                        
        except Exception as e:
            logger.error(f"Error scanning processes: {e}")
            
        return all_processes, suspicious
        
    def update_history(self, processes: List[Process]):
        """Update the process history list"""
        self.process_history.append(processes)
        if len(self.process_history) > self.history_size:
            self.process_history.pop(0)
            
    def zombie_count_increasing(self) -> Tuple[bool, int]:
        """Check if the number of zombie processes is increasing"""
        if len(self.process_history) < 2:
            return False, 0
            
        zombie_counts = [
            sum(1 for p in scan if p.status == 'zombie')
            for scan in self.process_history
        ]
        
        # Check if there's a consistent increase in zombie count
        if zombie_counts[-1] > zombie_counts[0] + self.zombie_increase_threshold:
            return True, zombie_counts[-1] - zombie_counts[0]
        return False, 0
        
    def kill_process(self, process: Process) -> bool:
        """Kill a suspicious process"""
        try:
            os.kill(process.pid, signal.SIGTERM)
            time.sleep(0.1)  # Give process time to terminate
            
            # Check if still alive and send SIGKILL if needed
            if psutil.pid_exists(process.pid):
                os.kill(process.pid, signal.SIGKILL)
                
            logger.info(f"Killed process: {process.pid} ({process.name})")
            return True
        except Exception as e:
            logger.error(f"Failed to kill process {process.pid}: {e}")
            return False
            
    def take_action(self, suspicious: Dict[str, List[Process]]) -> Dict[str, int]:
        """Take action on suspicious processes based on configuration"""
        actions_taken = {category: 0 for category in suspicious}
        
        # Handle zombie processes
        if self.kill_zombies:
            for process in suspicious['zombie']:
                if self.kill_process(process):
                    actions_taken['zombie'] += 1
                    
        # Handle root binary processes
        if self.kill_root_binaries:
            for process in suspicious['root_binary']:
                if self.kill_process(process):
                    actions_taken['root_binary'] += 1
                    
        # Handle suspicious command line processes
        if self.kill_suspicious:
            for process in suspicious['suspicious_cmdline']:
                if self.kill_process(process):
                    actions_taken['suspicious_cmdline'] += 1
                    
        # Parent PID 0 processes - These are unusual enough to always kill if killable
        if self.kill_suspicious:  # Use same setting as suspicious cmdline
            for process in suspicious['parent_pid_zero']:
                if self.kill_process(process):
                    actions_taken['parent_pid_zero'] += 1
                    
        return actions_taken
        
    def generate_report(self, all_processes: List[Process], suspicious: Dict[str, List[Process]], 
                       actions_taken: Dict[str, int]) -> str:
        """Generate a detailed report of findings"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'total_processes': len(all_processes),
            'suspicious': {
                category: [p.to_dict() for p in processes]
                for category, processes in suspicious.items()
            },
            'actions_taken': actions_taken,
            'summary': {
                'zombie_count': len(suspicious['zombie']),
                'root_binary_count': len(suspicious['root_binary']),
                'parent_pid_zero_count': len(suspicious['parent_pid_zero']),
                'suspicious_cmdline_count': len(suspicious['suspicious_cmdline']),
                'zombie_increasing': self.zombie_count_increasing()[0]
            }
        }
        
        # Generate filename with timestamp
        report_file = self.report_dir / f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        
        # Write report to file
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Generated report: {report_file}")
        return str(report_file)
        
    def notify_admin(self, report_file: str, suspicious: Dict[str, List[Process]]):
        """Email notification functionality removed as requested"""
        # Email notification removed as requested
        return


class ZombieHunterService:
    """Main service class for Zombie Hunter"""
    
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
        self.detector = ZombieDetector(self.config)
        
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
        service_name = "zombie_hunter"
        
        # Initialize isolation manager (must be done early, before fork)
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
            self.priv_mgr = PrivilegeManager(service_name)
            username = self.config['privilege']['user']
            group = self.config['privilege']['group']
            
            try:
                self.priv_mgr.ensure_user_exists(username=username, group=group)
                logger.info(f"Ensured service user {username} exists")
                
                # Set up required directories with proper permissions
                log_dir = Path("/var/log/zombie_hunter")
                report_dir = Path(self.config['monitor']['report_dir'])
                
                self.priv_mgr.prepare_directory(str(log_dir), mode=0o750, uid=username, gid=group)
                self.priv_mgr.prepare_directory(str(report_dir), mode=0o750, uid=username, gid=group)
                logger.info(f"Directories prepared with correct permissions")
            except Exception as e:
                logger.error(f"Failed to set up privileges: {str(e)}")
        else:
            self.priv_mgr = None
            logger.info("Privilege separation disabled in configuration")
        
        # Initialize performance optimizer
        if self.config['performance']['enable_optimization'].lower() == 'true':
            self.perf_optimizer = PerformanceOptimizer(service_name)
            self.perf_optimizer.set_cpu_threshold(int(self.config['performance']['cpu_threshold']))
            self.perf_optimizer.set_memory_threshold(int(self.config['performance']['memory_threshold']))
            
            if self.config['performance']['adaptive_monitoring'].lower() == 'true':
                min_interval = int(self.config['performance']['min_interval'])
                max_interval = int(self.config['performance']['max_interval'])
                self.perf_optimizer.enable_adaptive_interval(min_interval, max_interval)
                
                # Override static interval with adaptive one
                self.interval = None  # Mark that we're using adaptive interval
                logger.info(f"Using adaptive monitoring interval ({min_interval}s-{max_interval}s)")
            else:
                self.interval = int(self.config['monitor']['interval'])
                logger.info(f"Performance optimization enabled with static interval: {self.interval}s")
        else:
            self.perf_optimizer = None
            self.interval = int(self.config['monitor']['interval'])
            logger.info("Performance optimization disabled in configuration")
        
        # Initialize monitoring scope
        if 'monitoring_scope' in self.config:
            self.monitoring_scope = MonitoringScope(service_name)
            self.monitoring_scope.load_from_config(self.config['monitoring_scope'])
            logger.info("Monitoring scope configuration loaded")
        else:
            self.monitoring_scope = None
        
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
        logger.info("Service activated - running with full monitoring capabilities")
    
    def _on_service_deactivated(self):
        """Called when service becomes inactive"""
        logger.info("Service deactivated - running with reduced monitoring capabilities")
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
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
        logger.info("Zombie Hunter service started")
        
        # Drop privileges if configured
        if (self.priv_mgr and 
            self.config['privilege']['enabled'].lower() == 'true' and
            self.config['privilege']['drop_privileges'].lower() == 'true'):
            try:
                user = self.config['privilege']['user']
                self.priv_mgr.drop_privileges(user)
                logger.info(f"Dropped privileges to user: {user}")
            except Exception as e:
                logger.error(f"Failed to drop privileges: {str(e)}")
        
        # Main service loop
        while self.running:
            try:
                # Check if service should be active
                is_active = True
                if self.service_activator:
                    is_active = self.service_activator.is_active
                
                if is_active:
                    # Full monitoring when active
                    self._run_full_scan_cycle()
                else:
                    # Minimal monitoring when inactive
                    self._run_minimal_scan()
                
                # Determine sleep interval
                sleep_time = self._get_optimal_sleep_interval()
                
                # Break sleep into smaller chunks for responsiveness
                chunks = max(1, min(10, sleep_time))  # Between 1-10 chunks
                chunk_time = sleep_time / chunks
                for _ in range(chunks):
                    if not self.running:
                        break
                    time.sleep(chunk_time)
                    
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(10)  # Shorter wait on error
    
    def _get_optimal_sleep_interval(self):
        """Get the optimal sleep interval based on performance optimization settings"""
        if self.interval is None and self.perf_optimizer:
            # Use adaptive interval from performance optimizer
            return self.perf_optimizer.get_optimal_interval()
        else:
            # Use static interval from config
            return int(self.config['monitor']['interval'])
    
    def _run_minimal_scan(self):
        """Run a minimal scan when service is inactive"""
        try:
            # Just do basic system checks that might trigger reactivation
            if self.perf_optimizer:
                # Check overall system load
                cpu_usage = self.perf_optimizer.get_system_cpu_percent()
                
                # Update monitored values that might trigger activation
                if self.service_activator:
                    self.service_activator.update_monitored_value('system_cpu', cpu_usage)
                    
                    # Do a quick check for zombie processes
                    zombie_count = self._count_zombie_processes()
                    self.service_activator.update_monitored_value('zombie_processes', zombie_count)
                    
                    if zombie_count > int(self.config['detection']['max_zombies']):
                        logger.warning(f"Detected {zombie_count} zombie processes during minimal scan")
                        self.service_activator.activate("High zombie count detected")
        except Exception as e:
            logger.error(f"Error in minimal scan: {str(e)}")
    
    def _count_zombie_processes(self):
        """Quick count of zombie processes for activation triggering"""
        zombie_count = 0
        try:
            for proc in psutil.process_iter(['status']):
                try:
                    if proc.info['status'] == psutil.STATUS_ZOMBIE:
                        zombie_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
            
        return zombie_count
    
    def _run_full_scan_cycle(self):
        """Run a full scan cycle with all monitoring features"""
        try:
            # Start performance monitoring for this cycle
            if self.perf_optimizer:
                self.perf_optimizer.start_operation("scan_cycle")
                
            logger.debug("Starting full process scan")
            
            # Temporarily restore privileges for scanning if needed
            if (self.priv_mgr and 
                self.config['privilege']['enabled'].lower() == 'true' and
                self.config['privilege']['restore_privileges_for_actions'].lower() == 'true'):
                with self.priv_mgr.temporarily_restore_privileges():
                    all_processes, suspicious = self.detector.scan_processes()
            else:
                all_processes, suspicious = self.detector.scan_processes()
            
            # Update history
            self.detector.update_history(all_processes)
            
            # Check for anomalies
            total_suspicious = sum(len(processes) for processes in suspicious.values())
            increasing, diff = self.detector.zombie_count_increasing()
            
            # Log findings
            logger.info(f"Scan complete: {len(all_processes)} processes, {total_suspicious} suspicious")
            
            if total_suspicious > 0:
                logger.warning(f"Found suspicious processes: "
                             f"{len(suspicious['zombie'])} zombies, "
                             f"{len(suspicious['root_binary'])} root binaries, "
                             f"{len(suspicious['parent_pid_zero'])} with parent PID 0, "
                             f"{len(suspicious['suspicious_cmdline'])} with suspicious command lines")
                
                # Take action if needed - requires elevated privileges
                if (self.priv_mgr and 
                    self.config['privilege']['enabled'].lower() == 'true' and
                    self.config['privilege']['restore_privileges_for_actions'].lower() == 'true'):
                    with self.priv_mgr.temporarily_restore_privileges():
                        actions_taken = self.detector.take_action(suspicious)
                else:
                    actions_taken = self.detector.take_action(suspicious)
                
                # Generate report
                report_file = self.detector.generate_report(all_processes, suspicious, actions_taken)
                
                # Update service activator with metrics
                if self.service_activator:
                    self.service_activator.update_monitored_value('suspicious_processes', total_suspicious)
            
            # Check if zombie count is increasing
            if increasing:
                logger.warning(f"Zombie process count increasing: +{diff} over last {self.detector.history_size} scans")
                
            # End performance monitoring for this cycle
            if self.perf_optimizer:
                self.perf_optimizer.end_operation("scan_cycle")
                
                # Update system metrics
                cpu_usage = self.perf_optimizer.get_system_cpu_percent()
                memory_usage = self.perf_optimizer.get_memory_usage()
                
                # Update service activator with system metrics
                if self.service_activator:
                    self.service_activator.update_monitored_value('system_cpu', cpu_usage)
                    self.service_activator.update_monitored_value('system_memory', memory_usage)
                    
                logger.debug(f"System: CPU {cpu_usage}%, Memory {memory_usage}MB")
                
        except Exception as e:
            logger.error(f"Error in scan cycle: {str(e)}")
                
        logger.info("Zombie Hunter service shutting down")
        
        # Remove PID file on exit
        try:
            os.unlink(self.config['monitor']['pidfile'])
        except Exception as e:
            logger.error(f"Failed to remove PID file: {e}")


def main():
    """Main function"""
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = "/etc/zombie_hunter.conf"
        
    service = ZombieHunterService(config_file)
    service.run()


if __name__ == "__main__":
    main()
