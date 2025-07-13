#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Anomaly CPU/Mem Hunter
----------------------
Monitors all processes for CPU and memory usage anomalies.
Alerts if CPU or memory usage exceeds configured thresholds.
Optionally takes a process dump (e.g., with gcore) for high resource consumers.
Helps detect exploits, crypto miners, DoS attacks.

Author: root0emir - Securonis Linux
License: GPLv3
NOTE: This is a prototype with limited testing time
"""

import os
import sys
import time
import logging
import subprocess
import signal
import configparser
import psutil
import json
import re
import socket
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# Import security and performance utility modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.privilege_manager import PrivilegeManager
from utils.isolation_manager import IsolationManager
from utils.performance_optimizer import PerformanceOptimizer
from utils.monitoring_scope import MonitoringScope
from utils.service_activator import ServiceActivator

# Configure logging with a default configuration
# This will be updated after loading the config file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/anomaly_hunter.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('anomaly_hunter')


class AnomalyHunter:
    """Main class for the Anomaly CPU/Mem Hunter."""
    
    def __init__(self, config_path: str = '/etc/anomaly_hunter.conf'):
        """Initialize the AnomalyHunter."""
        # Load configuration
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Parse configuration
        self.check_interval = int(self.config['monitor']['interval'])
        self.history_size = int(self.config['monitor']['history_size'])
        self.dump_dir = self.config['monitor']['dump_dir']
        
        # Parse thresholds
        self.cpu_threshold = int(self.config['thresholds']['cpu_threshold'])
        self.memory_threshold = int(self.config['thresholds']['memory_threshold'])
        self.cpu_trend_count = int(self.config['thresholds']['cpu_trend_count'])
        self.memory_trend_count = int(self.config['thresholds']['memory_trend_count'])
        self.io_threshold = int(self.config['thresholds']['io_threshold'])
        self.max_threads = int(self.config['thresholds']['max_threads'])
        self.max_file_descriptors = int(self.config['thresholds']['max_file_descriptors'])
        
        # Parse actions
        self.enable_dump = self.config['actions'].getboolean('enable_dump')
        self.dump_command = self.config['actions']['dump_command']
        self.max_dump_size = int(self.config['actions']['max_dump_size'])
        self.enable_kill = self.config['actions'].getboolean('enable_kill')
        
        # Parse whitelist
        self.whitelist_processes = self._parse_whitelist('processes')
        self.whitelist_users = self._parse_whitelist('users')
        self.whitelist_paths = self._parse_whitelist('paths')
        
        # Parse baseline settings
        self.enable_baselines = self.config['baselines'].getboolean('enable_baselines')
        self.baseline_period = int(self.config['baselines']['baseline_period'])
        self.baseline_margin = int(self.config['baselines']['baseline_margin'])
        
        # Initialize process history and tracking
        self.process_history = defaultdict(lambda: defaultdict(lambda: deque(maxlen=self.history_size)))
        self.baselines = defaultdict(lambda: defaultdict(float))
        self.anomalies_detected = set()
        self.dump_history = set()
        
        # Create dump directory if needed and enabled
        if self.enable_dump:
            os.makedirs(self.dump_dir, exist_ok=True)
        
        # Initialize security and performance modules
        self._setup_security_and_performance()
        
        # Signal handling for graceful shutdown
        self.running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        logger.info("Anomaly CPU/Mem Hunter initialized")
        logger.info(f"Monitoring interval: {self.check_interval} seconds")
        logger.info(f"CPU threshold: {self.cpu_threshold}%, Memory threshold: {self.memory_threshold}%")
        logger.info(f"Process dump enabled: {self.enable_dump}")
        if self.enable_dump:
            logger.info(f"Process dumps will be stored in: {self.dump_dir}")
            logger.info(f"Maximum dump size: {self.max_dump_size} MB")
    
    def _load_config(self, config_path: str) -> configparser.ConfigParser:
        """Load configuration from file or use defaults."""
        # Default configuration
        defaults = {
            'monitor': {
                'interval': '30',
                'log_level': 'INFO',
                'log_file': '/var/log/anomaly_hunter.log',
                'pidfile': '/var/run/anomaly_hunter.pid',
                'history_size': '10',
                'dump_dir': '/var/log/anomaly_hunter/dumps'
            },
            'thresholds': {
                'cpu_threshold': '90',
                'memory_threshold': '90',
                'cpu_trend_count': '3',
                'memory_trend_count': '3',
                'io_threshold': '10000',
                'max_threads': '500',
                'max_file_descriptors': '1000'
            },
            'actions': {
                'enable_dump': 'true',
                'dump_command': 'gcore -o %DUMP_DIR%/%TIMESTAMP%_%USER%_%PROCESS%_%PID%.core %PID%',
                'max_dump_size': '500',
                'enable_kill': 'false'
            },
            'whitelist': {
                'processes': 'systemd,init,chrome,firefox,brave,gnome-shell',
                'users': 'root',
                'paths': '/usr/bin/X,/usr/lib/xorg/Xorg'
            },
            'baselines': {
                'enable_baselines': 'true',
                'baseline_period': '3600',
                'baseline_margin': '20'
            },
            'privilege_separation': {
                'enabled': 'true',
                'run_as_user': 'anomaly-hunter',
                'drop_capabilities': 'true',
                'retained_capabilities': 'CAP_DAC_OVERRIDE,CAP_SYS_PTRACE'
            },
            'isolation': {
                'enabled': 'true',
                'use_namespaces': 'true',
                'namespace_types': 'mount,uts,ipc,pid',
                'use_cgroups': 'true',
                'memory_limit_mb': '256',
                'cpu_limit_percent': '20'
            },
            'performance': {
                'enabled': 'true',
                'adaptive_monitoring': 'true',
                'min_interval': '15',    # Minimum 15 seconds
                'max_interval': '120',   # Maximum 2 minutes
                'cpu_threshold': '70',   # Reduce activity if CPU usage is above this
                'memory_threshold': '75' # Reduce activity if memory usage is above this
            },
            'monitoring_scope': {
                'enabled': 'true',
                'include_patterns': '/usr/bin/*,/usr/local/bin/*,/bin/*,/sbin/*',
                'exclude_patterns': '/proc/*,/dev/*,/sys/*,/run/*,/tmp/*',
                'use_process_context': 'true'
            },
            'service_activation': {
                'enabled': 'true',
                'run_on_boot': 'true',
                'run_on_schedule': 'true',
                'schedule': '*/30 * * * *',  # Every 30 minutes
                'run_on_events': 'true',
                'events': 'high_load,new_process,login',
                'minimal_checks_only': 'false'
            }
        }
        
        config = configparser.ConfigParser()
        
        # Set default values
        for section, options in defaults.items():
            if not config.has_section(section):
                config.add_section(section)
            for option, value in options.items():
                config.set(section, option, value)
        
        # Try to read config file
        if os.path.exists(config_path):
            try:
                config.read(config_path)
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.error(f"Error reading config file {config_path}: {e}")
                logger.info("Using default configuration")
        else:
            logger.warning(f"Config file {config_path} not found, using default configuration")
        
        return config
    
    def _setup_logging(self):
        """Configure logging based on config"""
        log_level = self.config['monitor']['log_level']
        log_file = self.config['monitor']['log_file']
        
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            numeric_level = logging.INFO
        
        logger.setLevel(numeric_level)
        
        # Remove all handlers
        for handler in logger.handlers[:]:  
            logger.removeHandler(handler)
        
        # Add file and stream handlers
        fh = logging.FileHandler(log_file)
        ch = logging.StreamHandler()
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
    def _setup_security_and_performance(self):
        """Initialize security and performance utility modules"""
        try:
            # Initialize privilege manager
            priv_config = self.config.get('privilege_separation', {})
            self.privilege_enabled = priv_config.get('enabled', 'true').lower() == 'true'
            if self.privilege_enabled:
                self.privilege_manager = PrivilegeManager(
                    target_user=priv_config.get('run_as_user', 'anomaly-hunter'),
                    drop_capabilities=priv_config.get('drop_capabilities', 'true').lower() == 'true',
                    retained_capabilities=priv_config.get('retained_capabilities', '').split(',')
                )
                logger.info("Privilege separation enabled")
            else:
                self.privilege_manager = None
                logger.info("Privilege separation disabled")
            
            # Initialize isolation manager
            iso_config = self.config.get('isolation', {})
            self.isolation_enabled = iso_config.get('enabled', 'true').lower() == 'true'
            if self.isolation_enabled:
                self.isolation_manager = IsolationManager(
                    use_namespaces=iso_config.get('use_namespaces', 'true').lower() == 'true',
                    namespace_types=iso_config.get('namespace_types', '').split(','),
                    use_cgroups=iso_config.get('use_cgroups', 'true').lower() == 'true',
                    memory_limit_mb=int(iso_config.get('memory_limit_mb', '256')),
                    cpu_limit_percent=int(iso_config.get('cpu_limit_percent', '20'))
                )
                logger.info("Process isolation enabled")
            else:
                self.isolation_manager = None
                logger.info("Process isolation disabled")
            
            # Initialize performance optimizer
            perf_config = self.config.get('performance', {})
            self.performance_enabled = perf_config.get('enabled', 'true').lower() == 'true'
            if self.performance_enabled:
                self.performance_optimizer = PerformanceOptimizer(
                    adaptive_monitoring=perf_config.get('adaptive_monitoring', 'true').lower() == 'true',
                    min_interval=int(perf_config.get('min_interval', '15')),
                    max_interval=int(perf_config.get('max_interval', '120')),
                    cpu_threshold=int(perf_config.get('cpu_threshold', '70')),
                    memory_threshold=int(perf_config.get('memory_threshold', '75'))
                )
                logger.info("Performance optimization enabled")
            else:
                self.performance_optimizer = None
                logger.info("Performance optimization disabled")
            
            # Initialize monitoring scope manager
            scope_config = self.config.get('monitoring_scope', {})
            self.scope_enabled = scope_config.get('enabled', 'true').lower() == 'true'
            if self.scope_enabled:
                include_patterns = scope_config.get('include_patterns', '').split(',')
                exclude_patterns = scope_config.get('exclude_patterns', '').split(',')
                self.monitoring_scope = MonitoringScope(
                    include_patterns=include_patterns if include_patterns != [''] else [],
                    exclude_patterns=exclude_patterns if exclude_patterns != [''] else [],
                    use_process_context=scope_config.get('use_process_context', 'true').lower() == 'true'
                )
                logger.info("Fine-grained monitoring scope enabled")
            else:
                self.monitoring_scope = None
                logger.info("Fine-grained monitoring scope disabled")
            
            # Initialize service activator
            activator_config = self.config.get('service_activation', {})
            self.activation_enabled = activator_config.get('enabled', 'true').lower() == 'true'
            if self.activation_enabled:
                self.service_activator = ServiceActivator(
                    run_on_boot=activator_config.get('run_on_boot', 'true').lower() == 'true',
                    run_on_schedule=activator_config.get('run_on_schedule', 'true').lower() == 'true',
                    schedule=activator_config.get('schedule', '*/30 * * * *'),
                    run_on_events=activator_config.get('run_on_events', 'true').lower() == 'true',
                    events=activator_config.get('events', '').split(','),
                    minimal_checks_only=activator_config.get('minimal_checks_only', 'false').lower() == 'true'
                )
                logger.info("Configurable service activation enabled")
            else:
                self.service_activator = None
                logger.info("Configurable service activation disabled")
                
        except Exception as e:
            logger.error(f"Failed to initialize security and performance modules: {e}")
            # Fallback to operating without enhanced security if initialization fails
            self.privilege_manager = None
            self.isolation_manager = None
            self.performance_optimizer = None
            self.monitoring_scope = None
            self.service_activator = None
        
        logger.debug(f"Logging configured at level {log_level}")
    
    def _handle_signal(self, signum, frame):
        """Handle termination signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def _parse_whitelist(self, whitelist_name: str) -> Set[str]:
        """Parse whitelist configuration into a set."""
        whitelist_str = self.config['whitelist'].get(whitelist_name, '')
        if not whitelist_str:
            return set()
        return set(item.strip() for item in whitelist_str.split(',') if item.strip())
    
    def check_processes(self):
        """Check all processes for resource usage anomalies."""
        logger.debug("Checking processes for resource anomalies")
        
        # Get system-wide CPU and memory info for context
        system_memory = psutil.virtual_memory()
        system_cpu = psutil.cpu_percent(interval=None)
        
        # Track the current scan time for history
        scan_time = datetime.now()
        
        # Process all running processes
        for process in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
            try:
                # Get basic process info
                pid = process.info['pid']
                name = process.info['name']
                username = process.info['username']
                exe_path = process.info['exe'] if process.info['exe'] else ''
                cmdline = ' '.join(process.info['cmdline']) if process.info['cmdline'] else ''
                
                # Check if this process should be monitored based on scope
                if self.scope_enabled and self.monitoring_scope:
                    should_monitor = self.monitoring_scope.should_monitor(exe_path)
                    if not should_monitor:
                        logger.debug(f"Skipping process {name} (PID: {pid}) based on monitoring scope")
                        continue
                
                # Check whitelists
                if (name in self.whitelist_processes or
                    username in self.whitelist_users or
                    any(exe_path.startswith(path) for path in self.whitelist_paths if exe_path and path)):
                    logger.debug(f"Skipping whitelisted process {name} (PID: {pid})")
                    continue
                
                # Get detailed process info
                process_obj = psutil.Process(pid)
                
                # Get CPU and memory usage
                try:
                    cpu_percent = process_obj.cpu_percent(interval=0.1)
                    memory_percent = process_obj.memory_percent()
                    
                    # Add to history
                    self.process_history[pid]['cpu'].append(cpu_percent)
                    self.process_history[pid]['memory'].append(memory_percent)
                    self.process_history[pid]['time'].append(scan_time)
                    
                    # Get additional metrics if needed
                    if self.io_threshold > 0:
                        io_counters = process_obj.io_counters() if hasattr(process_obj, 'io_counters') else None
                        if io_counters:
                            self.process_history[pid]['io_read'].append(io_counters.read_bytes)
                            self.process_history[pid]['io_write'].append(io_counters.write_bytes)
                    
                    if self.max_threads > 0:
                        num_threads = len(process_obj.threads())
                        self.process_history[pid]['threads'].append(num_threads)
                    
                    if self.max_file_descriptors > 0:
                        try:
                            num_fds = len(process_obj.open_files())
                            self.process_history[pid]['fds'].append(num_fds)
                        except:
                            pass
                    
                    # Check for anomalies
                    self._check_process_anomalies(pid, name, username, exe_path, cmdline, process_obj)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    # Process ended or no permissions to access it
                    logger.debug(f"Could not access process {pid}: {e}")
                    continue
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                # Process ended or no permissions to access it
                continue
        
        # Clean up history for processes that no longer exist
        current_pids = set(p.info['pid'] for p in psutil.process_iter(['pid']))
        for pid in list(self.process_history.keys()):
            if pid not in current_pids:
                del self.process_history[pid]
        
        # Update baselines if enabled
        if self.enable_baselines:
            self._update_baselines()
    
    def _check_process_anomalies(self, pid: int, name: str, username: str, exe_path: str, cmdline: str, process_obj: psutil.Process):
        """Check a specific process for anomalies."""
        # Skip if not enough history
        if len(self.process_history[pid]['cpu']) < self.cpu_trend_count:
            return
        
        anomalies = []
        
        # Check CPU usage
        cpu_anomaly = self._detect_cpu_anomaly(pid)
        if cpu_anomaly:
            anomalies.append(f"CPU usage: {cpu_anomaly:.1f}%")
        
        # Check memory usage
        memory_anomaly = self._detect_memory_anomaly(pid)
        if memory_anomaly:
            anomalies.append(f"Memory usage: {memory_anomaly:.1f}%")
        
        # Check IO usage (if configured)
        io_anomaly = self._detect_io_anomaly(pid)
        if io_anomaly:
            anomalies.append(f"IO operations: {io_anomaly} ops/sec")
        
        # Check thread count (if configured)
        thread_anomaly = self._detect_thread_anomaly(pid)
        if thread_anomaly:
            anomalies.append(f"Thread count: {thread_anomaly}")
        
        # Check file descriptors (if configured)
        fd_anomaly = self._detect_fd_anomaly(pid)
        if fd_anomaly:
            anomalies.append(f"Open file descriptors: {fd_anomaly}")
        
        # Take action if anomalies detected
        if anomalies:
            # Track this anomalous process
            process_key = f"{pid}:{name}:{username}"
            
            # Generate report
            report = self._generate_anomaly_report(pid, name, username, exe_path, cmdline, anomalies, process_obj)
            
            # Take dump if enabled and not already taken for this process
            if self.enable_dump and process_key not in self.dump_history:
                self._take_process_dump(pid, name, username, process_obj)
                self.dump_history.add(process_key)
            
            # Terminate process if enabled
            if self.enable_kill:
                self._terminate_process(pid, name, process_obj)
            
            # Send email if enabled
            if self.enable_email:
                self._send_email_alert(report)
    
    def _detect_cpu_anomaly(self, pid: int) -> Optional[float]:
        """Detect CPU usage anomaly for a process."""
        cpu_history = list(self.process_history[pid]['cpu'])
        threshold = self._get_effective_threshold(pid, 'cpu')
        
        # Check for sustained high usage
        high_usage_count = sum(1 for cpu in cpu_history[-self.cpu_trend_count:] if cpu > threshold)
        
        if high_usage_count >= self.cpu_trend_count:
            return cpu_history[-1]
        
        return None
    
    def _detect_memory_anomaly(self, pid: int) -> Optional[float]:
        """Detect memory usage anomaly for a process."""
        memory_history = list(self.process_history[pid]['memory'])
        threshold = self._get_effective_threshold(pid, 'memory')
        
        # Check for sustained high usage
        high_usage_count = sum(1 for mem in memory_history[-self.memory_trend_count:] if mem > threshold)
        
        if high_usage_count >= self.memory_trend_count:
            return memory_history[-1]
        
        return None
    
    def _detect_io_anomaly(self, pid: int) -> Optional[int]:
        """Detect IO usage anomaly for a process."""
        if self.io_threshold <= 0 or 'io_read' not in self.process_history[pid]:
            return None
        
        if len(self.process_history[pid]['io_read']) < 2:
            return None
        
        # Calculate IO operations per second
        io_read = self.process_history[pid]['io_read']
        io_write = self.process_history[pid]['io_write']
        times = self.process_history[pid]['time']
        
        read_rate = (io_read[-1] - io_read[-2]) / (times[-1] - times[-2]).total_seconds()
        write_rate = (io_write[-1] - io_write[-2]) / (times[-1] - times[-2]).total_seconds()
        total_io_rate = read_rate + write_rate
        
        if total_io_rate > self.io_threshold:
            return int(total_io_rate)
        
        return None
    
    def _detect_thread_anomaly(self, pid: int) -> Optional[int]:
        """Detect thread count anomaly for a process."""
        if self.max_threads <= 0 or 'threads' not in self.process_history[pid]:
            return None
        
        threads = self.process_history[pid]['threads'][-1]
        if threads > self.max_threads:
            return threads
        
        return None
    
    def _detect_fd_anomaly(self, pid: int) -> Optional[int]:
        """Detect file descriptor count anomaly for a process."""
        if self.max_file_descriptors <= 0 or 'fds' not in self.process_history[pid]:
            return None
        
        fds = self.process_history[pid]['fds'][-1]
        if fds > self.max_file_descriptors:
            return fds
        
        return None
    
    def _get_effective_threshold(self, pid: int, metric: str) -> float:
        """Get effective threshold based on baselines if enabled."""
        if not self.enable_baselines or pid not in self.baselines or metric not in self.baselines[pid]:
            if metric == 'cpu':
                return self.cpu_threshold
            elif metric == 'memory':
                return self.memory_threshold
            return 0
        
        baseline = self.baselines[pid][metric]
        margin = baseline * (self.baseline_margin / 100.0)
        dynamic_threshold = baseline + margin
        
        # Use the higher of static or dynamic threshold
        if metric == 'cpu':
            return max(self.cpu_threshold, dynamic_threshold)
        elif metric == 'memory':
            return max(self.memory_threshold, dynamic_threshold)
        return 0
    
    def _update_baselines(self):
        """Update baseline calculations for processes."""
        # Only update periodically
        current_time = datetime.now()
        for pid, metrics in self.process_history.items():
            # Skip processes with too little history
            if len(metrics['cpu']) < 3:
                continue
            
            # Calculate averages
            cpu_avg = sum(metrics['cpu']) / len(metrics['cpu'])
            memory_avg = sum(metrics['memory']) / len(metrics['memory'])
            
            # Update baselines
            self.baselines[pid]['cpu'] = cpu_avg
            self.baselines[pid]['memory'] = memory_avg
    
    def _generate_anomaly_report(self, pid: int, name: str, username: str, exe_path: str, 
                               cmdline: str, anomalies: List[str], process_obj: psutil.Process) -> str:
        """Generate a detailed report of the anomaly."""
        # Get process creation time
        try:
            create_time = datetime.fromtimestamp(process_obj.create_time()).strftime('%Y-%m-%d %H:%M:%S')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            create_time = "Unknown"
        
        # Get parent process
        try:
            parent = process_obj.parent()
            parent_info = f"{parent.pid} ({parent.name()})" if parent else "None"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            parent_info = "Unknown"
        
        # Get connections
        connections = []
        try:
            for conn in process_obj.connections():
                if conn.status == 'ESTABLISHED':
                    local = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    connections.append(f"{local} -> {remote} ({conn.status})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        # Memory maps
        try:
            memory_maps = [m.path for m in process_obj.memory_maps(grouped=True) if m.path]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            memory_maps = []
        
        # Format report
        report = []
        report.append(f"ANOMALY DETECTED: {name} (PID: {pid})")
        report.append("-" * 60)
        report.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Host: {socket.gethostname()}")
        report.append(f"Process: {name} (PID: {pid})")
        report.append(f"User: {username}")
        report.append(f"Path: {exe_path}")
        report.append(f"Command: {cmdline}")
        report.append(f"Creation time: {create_time}")
        report.append(f"Parent: {parent_info}")
        report.append(f"Anomalies detected: {', '.join(anomalies)}")
        report.append("")
        
        # Add resource details
        cpu_history = list(self.process_history[pid]['cpu'])
        memory_history = list(self.process_history[pid]['memory'])
        
        report.append("Resource usage:")
        report.append(f"  CPU: current={cpu_history[-1]:.1f}%, avg={sum(cpu_history)/len(cpu_history):.1f}%, max={max(cpu_history):.1f}%")
        report.append(f"  Memory: current={memory_history[-1]:.1f}%, avg={sum(memory_history)/len(memory_history):.1f}%, max={max(memory_history):.1f}%")
        
        # Add connections
        if connections:
            report.append("\nNetwork connections:")
            for conn in connections[:10]:  # Limit to 10 connections
                report.append(f"  {conn}")
            if len(connections) > 10:
                report.append(f"  ... and {len(connections) - 10} more connections")
        
        # Add memory maps
        if memory_maps:
            report.append("\nLoaded modules (first 10):")
            for path in memory_maps[:10]:
                report.append(f"  {path}")
            if len(memory_maps) > 10:
                report.append(f"  ... and {len(memory_maps) - 10} more modules")
        
        # Log the anomaly
        anomaly_str = "\n".join(report)
        logger.warning(anomaly_str)
        
        return anomaly_str
    
    def _take_process_dump(self, pid: int, name: str, username: str, process_obj: psutil.Process):
        """Take a memory dump of a process for further analysis."""
        # Check if process is too large to dump
        if self.max_dump_size > 0:
            try:
                memory_info = process_obj.memory_info()
                process_size_mb = memory_info.rss / (1024 * 1024)  # Convert to MB
                
                if process_size_mb > self.max_dump_size:
                    logger.warning(f"Process {name} (PID: {pid}) is too large to dump: {process_size_mb:.1f} MB exceeds limit of {self.max_dump_size} MB")
                    return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.warning(f"Could not determine size of process {name} (PID: {pid}), skipping dump")
                return
        
        # Format the dump command
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        cmd = self.dump_command
        cmd = cmd.replace('%PID%', str(pid))
        cmd = cmd.replace('%PROCESS%', name)
        cmd = cmd.replace('%USER%', username)
        cmd = cmd.replace('%TIMESTAMP%', timestamp)
        cmd = cmd.replace('%DUMP_DIR%', self.dump_dir)
        
        try:
            # Ensure the dump directory exists
            os.makedirs(self.dump_dir, exist_ok=True)
            
            # Execute the dump command
            logger.info(f"Taking memory dump of process {name} (PID: {pid})")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully created memory dump for process {name} (PID: {pid})")
            else:
                logger.error(f"Failed to create memory dump for process {name} (PID: {pid}): {result.stderr}")
        except Exception as e:
            logger.error(f"Error creating memory dump for process {name} (PID: {pid}): {e}")
    
    def _terminate_process(self, pid: int, name: str, process_obj: psutil.Process):
        """Terminate an anomalous process if enabled."""
        if not self.enable_kill:
            return
        
        logger.warning(f"Attempting to terminate anomalous process {name} (PID: {pid})")
        
        try:
            process_obj.terminate()
            # Give it some time to terminate
            gone, alive = psutil.wait_procs([process_obj], timeout=3)
            
            if process_obj.is_running():
                # Force kill if still running
                logger.warning(f"Process {name} (PID: {pid}) did not terminate, sending SIGKILL")
                process_obj.kill()
            
            logger.info(f"Successfully terminated process {name} (PID: {pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to terminate process {name} (PID: {pid}): {e}")
    
    def _send_email_alert(self, report: str):
        """Send email alert if enabled."""
        if not self.enable_email:
            return
        
        try:
            msg = EmailMessage()
            msg.set_content(report)
            msg['Subject'] = self.email_subject
            msg['From'] = self.email_from
            msg['To'] = self.email_to
            
            # Simple localhost sendmail, replace with SMTP configuration if needed
            with smtplib.SMTP('localhost') as s:
                s.send_message(msg)
            
            logger.info(f"Email alert sent to {self.email_to}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def run(self):
        """Main monitoring loop."""
        logger.info("Starting Anomaly CPU/Mem Hunter")
        
        # Apply isolation if enabled (early in the startup)  
        if self.isolation_enabled and self.isolation_manager:
            try:
                self.isolation_manager.apply_isolation()
                logger.info("Process isolation applied successfully")
            except Exception as e:
                logger.error(f"Failed to apply process isolation: {e}")
                
        # Write PID file if configured
        pidfile = self.config['monitor'].get('pidfile', '')
        if pidfile:
            try:
                with open(pidfile, 'w') as f:
                    f.write(str(os.getpid()))
                logger.info(f"PID {os.getpid()} written to {pidfile}")
            except Exception as e:
                logger.error(f"Could not write PID file {pidfile}: {e}")
                
        # Drop privileges after initialization if enabled
        if self.privilege_enabled and self.privilege_manager:
            try:
                self.privilege_manager.drop_privileges()
                logger.info("Privileges dropped successfully")
            except Exception as e:
                logger.error(f"Failed to drop privileges: {e}")
                
        try:
            # Run until signaled to stop
            while self.running:
                # Check if service should be activated
                should_run_full_scan = True
                if self.activation_enabled and self.service_activator:
                    should_run_full_scan = self.service_activator.should_activate()
                    if not should_run_full_scan:
                        logger.info("Skipping full scan based on activation policy")
                        time.sleep(self.check_interval)
                        continue
                
                # Get optimal sleep interval if performance optimization is enabled
                check_interval = self.check_interval
                if self.performance_enabled and self.performance_optimizer:
                    check_interval = self.performance_optimizer.get_optimal_interval(self.check_interval)
                    if check_interval != self.check_interval:
                        logger.debug(f"Adjusted monitoring interval to {check_interval} seconds")
                
                # Track resource usage before scan if performance optimization is enabled
                if self.performance_enabled and self.performance_optimizer:
                    self.performance_optimizer.track_resource_usage_start()
                
                # Perform the process check
                self.check_processes()
                
                # Track resource usage after scan if performance optimization is enabled
                if self.performance_enabled and self.performance_optimizer:
                    self.performance_optimizer.track_resource_usage_end()
                
                # Wait for the next check interval
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, stopping Anomaly Hunter")
        except Exception as e:
            logger.critical(f"Critical error in main loop: {e}")
            sys.exit(1)
        finally:
            # Clean up PID file
            if pidfile and os.path.exists(pidfile):
                try:
                    os.unlink(pidfile)
                except Exception as e:
                    logger.error(f"Could not remove PID file {pidfile}: {e}")


def main():
    """Main entry point."""
    try:
        # Check for custom config path
        config_path = '/etc/anomaly_hunter.conf'
        if len(sys.argv) > 1:
            config_path = sys.argv[1]
        
        hunter = AnomalyHunter(config_path)
        hunter.run()
    except Exception as e:
        logger.critical(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
