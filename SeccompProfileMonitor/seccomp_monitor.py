#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Seccomp Profile Monitor
----------------------
Monitors all processes for seccomp usage and reports critical services
that are running without seccomp protection.

This service continuously monitors the system's processes by reading
/proc/$pid/status files and checking the Seccomp field.

Seccomp values:
- 0: disabled
- 1: strict mode
- 2: filter mode

Author: Root0Emir - Securonis Linux
"""

import os
import sys
import time
import logging
import subprocess
import configparser
import signal
import multiprocessing
import threading
import queue
import json
import statistics
import psutil
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Set, List, Tuple, Optional, Any

# Import utility modules
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ''))
from utils.privilege_manager import PrivilegeManager
from utils.isolation_manager import IsolationManager
from utils.performance_optimizer import PerformanceOptimizer
from utils.monitoring_scope import MonitoringScope
from utils.service_activator import ServiceActivator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/seccomp_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('seccomp_monitor')

# Add custom rate-limited logging handler
class RateLimitedLogHandler(logging.Handler):
    """Rate-limited logging handler to prevent log flooding"""
    
    def __init__(self, rate_limit: int = 60, burst: int = 10):
        """
        Initialize rate-limited log handler
        
        Args:
            rate_limit: Maximum number of logs per minute
            burst: Maximum number of logs allowed in a burst
        """
        super().__init__()
        self.rate_limit = rate_limit
        self.burst = burst
        self.log_bucket = burst  # Token bucket algorithm
        self.last_refill = datetime.now()
        self.log_queue = deque(maxlen=100)  # Store recent logs
        self.suppressed_count = 0
        
    def emit(self, record):
        """
        Emit a log record with rate limiting
        """
        current_time = datetime.now()
        time_passed = (current_time - self.last_refill).total_seconds()
        
        # Refill the bucket based on time passed
        self.log_bucket = min(
            self.burst, 
            self.log_bucket + int(time_passed * self.rate_limit / 60)
        )
        self.last_refill = current_time
        
        # If we have tokens, log normally
        if self.log_bucket > 0:
            self.log_bucket -= 1
            if self.suppressed_count > 0:
                logger.warning(f"Rate limiting suppressed {self.suppressed_count} similar messages")
                self.suppressed_count = 0
            self.log_queue.append((current_time, record.msg))
            return True
        else:
            # No tokens, suppress the message
            self.suppressed_count += 1
            return False
            
    def flush(self):
        """Flush any suppressed messages"""
        if self.suppressed_count > 0:
            logger.warning(f"Rate limiting suppressed {self.suppressed_count} similar messages")
            self.suppressed_count = 0

# Default configuration
DEFAULT_CONFIG = {
    'monitor': {
        'interval': '60',  # Check interval in seconds
        'critical_services': 'sshd,nginx,apache2,tor,mysqld',
        'ignore_services': 'chrome-sandbox',
        'log_level': 'INFO',
        'max_workers': '4',  # Number of parallel workers
        'log_rate_limit': '60',  # Max logs per minute
        'log_burst': '20',  # Burst log capacity
        'memory_check': 'true',  # Enable memory footprint checking
        'memory_history': '10',  # Number of memory samples to keep
        'memory_threshold': '50',  # Percent change to trigger alert
        'pidfile': '/var/run/seccomp_monitor.pid',
    },
    'privilege': {
        'enabled': 'true',
        'drop_privileges': 'true',
        'user': 'nobody',
        'restore_privileges_for_actions': 'true',
        'capabilities': 'net_admin,net_raw',
    },
    'isolation': {
        'enabled': 'true',
        'enable_namespaces': 'true',
        'enable_cgroups': 'true',
        'cpu_limit': '20',  # percentage
        'memory_limit_mb': '100',
        'mount_namespace': 'true',
        'net_namespace': 'false',  # Need network access
    },
    'performance': {
        'enabled': 'true',
        'adaptive_interval': 'true',
        'min_interval': '30',  # 30 seconds minimum
        'max_interval': '300',  # 5 minutes maximum
        'cpu_threshold': '80',  # percentage
        'memory_threshold': '80',  # percentage
        'sample_window': '5',  # Number of samples to average
    },
    'monitoring_scope': {
        'enabled': 'true',
        'included_processes': '*',  # Monitor all processes by default
        'excluded_processes': 'chrome-sandbox',  # Same as ignore_services for backward compatibility
        'included_users': '*',
        'excluded_users': 'nobody,www-data',
        'custom_rules': '',
    },
    'activation': {
        'enabled': 'true',
        'mode': 'adaptive',  # always, scheduled, adaptive, trigger
        'schedule': '0 */2 * * *',  # Every 2 hours
        'active_duration': '600',  # 10 minutes
        'triggers': 'seccomp_violation,anomaly_detected,system_event',
        'threshold_violations': '3',
        'inactivity_timeout': '3600',  # 1 hour
    }
}


class SeccompMonitor:
    """
    Monitor and report on seccomp usage across all processes.
    """
    
    def __init__(self, config_path: str = '/etc/seccomp_monitor.conf'):
        """Initialize the Seccomp Monitor"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Parse configuration
        self.interval = int(self.config['monitor']['interval'])
        self.critical_services = set(self.config['monitor']['critical_services'].split(','))
        self.ignore_services = set(self.config['monitor']['ignore_services'].split(','))
        self.max_workers = int(self.config['monitor'].get('max_workers', '4'))
        self.log_rate_limit = int(self.config['monitor'].get('log_rate_limit', '60'))
        self.log_burst = int(self.config['monitor'].get('log_burst', '20'))
        self.memory_check = self.config['monitor'].get('memory_check', 'true').lower() == 'true'
        self.memory_history = int(self.config['monitor'].get('memory_history', '10'))
        self.memory_threshold = int(self.config['monitor'].get('memory_threshold', '50'))
        
        # Initialize state
        self.running = True
        self.process_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.workers = []
        self.rate_limited_handler = RateLimitedLogHandler(
            rate_limit=self.log_rate_limit, 
            burst=self.log_burst
        )
        logger.addHandler(self.rate_limited_handler)
        
        # Memory tracking
        self.memory_footprint = defaultdict(lambda: deque(maxlen=self.memory_history))
        
        # Write PID file
        pid_file = self.config['monitor'].get('pidfile', '/var/run/seccomp_monitor.pid')
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        logger.info(f"PID written to {pid_file}")
        
        # Initialize security and performance modules
        self._setup_security_and_performance()
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        logger.info("Seccomp Monitor initialized")
        logger.info(f"Monitoring interval: {self.interval} seconds")
        logger.info(f"Critical services: {self.critical_services}")
        logger.info(f"Using {self.max_workers} parallel workers")
        logger.info(f"Log rate limiting: {self.log_rate_limit} per minute, burst: {self.log_burst}")
        if self.memory_check:
            logger.info(f"Memory footprint monitoring enabled, threshold: {self.memory_threshold}%")
            
    def _setup_security_and_performance(self):
        """Setup security and performance modules"""
        service_name = "seccomp_monitor"
        
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
        logger.info("Service activated - running with full monitoring capabilities")
    
    def _on_service_deactivated(self):
        """Called when service becomes inactive"""
        logger.info("Service deactivated - running with reduced monitoring capabilities")
        
    def _load_config(self, config_path: str) -> configparser.ConfigParser:
        """Load configuration from file or use defaults"""
        config = configparser.ConfigParser()
        
        # Set default configuration
        for section, options in DEFAULT_CONFIG.items():
            if not config.has_section(section):
                config.add_section(section)
            for key, value in options.items():
                config.set(section, key, value)
        
        # Try to load from file
        if os.path.exists(config_path):
            logger.info(f"Loading configuration from {config_path}")
            config.read(config_path)
        else:
            logger.warning(f"Config file {config_path} not found, using defaults")
            
        return config
        
    def _setup_logging(self):
        """Configure logging based on config"""
        log_level = self.config['monitor']['log_level']
        numeric_level = getattr(logging, log_level.upper(), None)
        if isinstance(numeric_level, int):
            logger.setLevel(numeric_level)
    
    def _handle_signal(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, shutting down")
        self.running = False
    
    def get_process_list(self) -> List[int]:
        """Get a list of all running process IDs"""
        try:
            return [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
        except Exception as e:
            logger.error(f"Error getting process list: {e}")
            return []
    
    def get_process_info(self, pid: int) -> Dict[str, str]:
        """
        Get process information from /proc/$pid/status
        
        Returns a dictionary with process information or None if process doesn't exist
        """
        try:
            proc_path = Path(f"/proc/{pid}/status")
            if not proc_path.exists():
                return {}
            
            process_info = {}
            with open(proc_path, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        process_info[key.strip()] = value.strip()
            
            # Get command line for better identification
            cmdline_path = Path(f"/proc/{pid}/cmdline")
            if cmdline_path.exists():
                with open(cmdline_path, 'rb') as f:
                    cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
                    process_info['Cmdline'] = cmdline
                    
            # Get executable name
            exe_path = Path(f"/proc/{pid}/exe")
            if exe_path.exists():
                try:
                    exe = os.readlink(exe_path)
                    process_info['Executable'] = exe
                except (OSError, PermissionError) as e:
                    # This is normal for some processes
                    pass
            
            return process_info
        except (PermissionError, FileNotFoundError):
            # This is normal as processes can terminate while we're checking
            return {}
        except Exception as e:
            logger.error(f"Error reading process {pid} info: {e}")
            return {}

    def get_process_name(self, process_info: Dict[str, str]) -> str:
        """Extract a meaningful process name from process info"""
        # Try different fields to get the most useful name
        if 'Name' in process_info:
            return process_info['Name']
        if 'Cmdline' in process_info:
            cmdline = process_info['Cmdline']
            return cmdline.split()[0] if cmdline else "unknown"
        if 'Executable' in process_info:
            return os.path.basename(process_info['Executable'])
        return "unknown"
    
    def get_seccomp_status(self, process_info: Dict[str, str]) -> Optional[int]:
        """Extract seccomp status from process info"""
        if 'Seccomp' in process_info:
            try:
                return int(process_info['Seccomp'])
            except ValueError:
                logger.error(f"Invalid seccomp value: {process_info.get('Seccomp')}")
        return None
    
    def is_critical_service(self, process_name: str, process_info: Dict[str, str]) -> bool:
        """Determine if a process is a critical service"""
        # Check direct match with critical services list
        if process_name in self.critical_services:
            return True
            
        # Check if process name is in the command line of any critical service
        cmdline = process_info.get('Cmdline', '')
        for service in self.critical_services:
            if service in cmdline:
                return True
                
        return False
        
    def should_ignore(self, process_name: str, process_info: Dict[str, str]) -> bool:
        """Determine if a process should be ignored"""
        # Check direct match with ignore list
        if process_name in self.ignore_services:
            return True
            
        # Check if any ignored service name is in the command line
        cmdline = process_info.get('Cmdline', '')
        for service in self.ignore_services:
            if service in cmdline:
                return True
                
        return False
        
    def process_worker(self, worker_id: int):
        """Worker process to handle process checking"""
        logger.debug(f"Worker {worker_id} started")
        while self.running:
            try:
                # Get a PID from the queue or timeout after 1 second
                try:
                    pid = self.process_queue.get(timeout=1)
                    
                    # Exit condition
                    if pid is None:
                        logger.debug(f"Worker {worker_id} received exit signal")
                        break
                        
                except queue.Empty:
                    continue
                    
                # Process the PID
                process_info = self.get_process_info(pid)
                if not process_info:
                    continue
                    
                process_name = self.get_process_name(process_info)
                seccomp_status = self.get_seccomp_status(process_info)
                
                # Skip processes we can't get seccomp status for
                if seccomp_status is None:
                    continue
                    
                # Skip processes we should ignore
                if self.should_ignore(process_name, process_info):
                    continue
                
                # Check memory usage if enabled
                memory_anomaly = None
                if self.memory_check:
                    try:
                        proc = psutil.Process(pid)
                        memory_info = proc.memory_info()
                        memory_usage = memory_info.rss  # Resident Set Size in bytes
                        
                        # Store memory usage history
                        self.memory_footprint[pid].append(memory_usage)
                        
                        # Check for anomalies if we have enough history
                        if len(self.memory_footprint[pid]) >= 2:
                            oldest = self.memory_footprint[pid][0]
                            newest = self.memory_footprint[pid][-1]
                            if oldest > 0:  # Avoid division by zero
                                percent_change = ((newest - oldest) / oldest) * 100
                                if percent_change > self.memory_threshold:
                                    memory_anomaly = {
                                        'old_value': oldest,
                                        'new_value': newest,
                                        'percent_change': percent_change
                                    }
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                
                # Log critical services without seccomp
                if seccomp_status == 0 and self.is_critical_service(process_name, process_info):
                    result = {
                        'pid': pid,
                        'name': process_name,
                        'cmdline': process_info.get('Cmdline', ''),
                        'executable': process_info.get('Executable', ''),
                        'seccomp': seccomp_status
                    }
                    if memory_anomaly:
                        result['memory_anomaly'] = memory_anomaly
                        
                    self.result_queue.put(result)
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                
        logger.debug(f"Worker {worker_id} stopped")
        
    def _start_workers(self):
        """Start worker processes if not already running"""
        # Clean up any dead workers first
        for i, worker in enumerate(self.workers[:]):
            if not worker.is_alive():
                logger.warning(f"Worker process {i} has died, restarting")
                self.workers.remove(worker)
        
        # Start new workers up to max_workers
        current_workers = len(self.workers)
        for i in range(current_workers, self.max_workers):
            worker = multiprocessing.Process(target=self.process_worker, args=(i,))
            worker.daemon = True
            worker.start()
            self.workers.append(worker)
            logger.debug(f"Started worker process {i} (PID: {worker.pid})")
            
    def check_processes(self) -> List[Dict[str, Any]]:
        """Check all processes for seccomp status"""
        logger.info("Starting process seccomp check")
        
        # Get all process IDs
        pids = self.get_process_list()
        total_processes = len(pids)
        logger.info(f"Found {total_processes} running processes to check")
        
        # Filter processes using monitoring scope if available
        filtered_pids = pids
        if self.monitoring_scope:
            try:
                # Apply monitoring scope filtering
                filtered_pids = []
                for pid in pids:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                        proc_user = proc.username()
                        
                        if self.monitoring_scope.is_process_monitored(pid, proc_name, proc_user):
                            filtered_pids.append(pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                logger.info(f"Monitoring scope reduced check list from {total_processes} to {len(filtered_pids)} processes")
            except Exception as e:
                logger.error(f"Error applying monitoring scope filter: {str(e)}")
                # Fall back to using all processes if filtering fails
                filtered_pids = pids
        
        # Refresh worker pool in case any died
        self._start_workers()
        
        # Add filtered processes to the queue for workers to process
        for pid in filtered_pids:
            self.process_queue.put(pid)
            
        # Add None sentinel values to signal end of work for each worker
        for _ in range(self.max_workers):
            self.process_queue.put(None)
            
        # Collect the results
        vulnerable_processes = []
        
        # Wait for a reasonable time for workers to process the PIDs
        # Use a timeout slightly shorter than the interval to ensure we don't block forever
        timeout = max(5, min(30, self.interval * 0.8))
        start_time = time.time()
        
        # Collect results as they come in with timeout
        while time.time() - start_time < timeout:
            try:
                result = self.result_queue.get(timeout=0.5)
                if result:
                    # Check if this result includes a memory anomaly
                    if 'memory_anomaly' in result:
                        anomaly = result['memory_anomaly']
                        # Use rate-limited logging for memory anomalies
                        if self.rate_limited_handler.emit(logging.makeLogRecord({'msg': 'memory_anomaly'})):
                            logger.warning(
                                f"Memory anomaly detected for {result['name']} (PID {result['pid']}): "
                                f"Usage changed by {anomaly['percent_change']:.1f}% "
                                f"({anomaly['old_value']/1024/1024:.1f}MB → {anomaly['new_value']/1024/1024:.1f}MB)"
                            )
                    
                    # Use rate-limited logging for seccomp warnings
                    if self.rate_limited_handler.emit(logging.makeLogRecord({'msg': 'seccomp_warning'})):
                        logger.warning(
                            f"Critical service {result['name']} (PID {result['pid']}) "
                            f"is running without seccomp protection"
                        )
                    vulnerable_processes.append(result)
            except queue.Empty:
                # No results ready yet
                time.sleep(0.1)
                
        # Flush any suppressed messages
        self.rate_limited_handler.flush()
                
        return vulnerable_processes
        
    def generate_report(self, vulnerable_processes: List[Dict[str, str]]):
        """Generate a report of vulnerable processes"""
        if not vulnerable_processes:
            logger.info("No critical services found running without seccomp protection")
            return
        
        # Group processes by name to avoid log flooding for many instances of same service
        grouped_processes = defaultdict(list)
        for proc in vulnerable_processes:
            grouped_processes[proc['name']].append(proc)
        
        # Use rate limiting for the summary report
        if self.rate_limited_handler.emit(logging.makeLogRecord({'msg': 'report_summary'})):
            logger.warning(f"Found {len(vulnerable_processes)} critical services without seccomp protection across {len(grouped_processes)} unique service types")
            
            # Report only one instance of each service type to prevent log flooding
            for service_name, processes in grouped_processes.items():
                if processes:
                    example = processes[0]
                    if len(processes) == 1:
                        logger.warning(f"  Service: {service_name}, PID: {example['pid']}, Path: {example['executable']}")
                    else:
                        logger.warning(f"  Service: {service_name}, {len(processes)} instances, Example PID: {example['pid']}")
        
        # Save detailed report to a rotating JSON file for later analysis
        try:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            report_dir = Path("/var/log/seccomp_monitor")
            report_dir.mkdir(exist_ok=True)
            
            # Keep only the 10 most recent reports
            reports = sorted(report_dir.glob("report-*.json"))
            if len(reports) >= 10:
                for old_report in reports[:-9]:
                    old_report.unlink()
            
            report_path = report_dir / f"report-{timestamp}.json"
            with open(report_path, 'w') as f:
                json.dump(
                    {
                        "timestamp": timestamp,
                        "total_processes": len(vulnerable_processes),
                        "vulnerable_processes": vulnerable_processes
                    },
                    f,
                    indent=2
                )
            logger.info(f"Detailed report saved to {report_path}")
        except Exception as e:
            logger.error(f"Failed to save detailed report: {e}")
        
    def run(self):
        """Main monitoring loop"""
        logger.info("Starting Seccomp Profile Monitor")
        
        try:
            # Apply process isolation early
            if self.isolation_mgr:
                try:
                    self.isolation_mgr.apply_isolation()
                    logger.info("Process isolation applied")
                except Exception as e:
                    logger.error(f"Failed to apply isolation: {str(e)}")
            
            # Drop privileges after initialization if configured
            if self.priv_mgr and self.config['privilege']['drop_privileges'].lower() == 'true':
                user = self.config['privilege']['user']
                capabilities = self.config['privilege']['capabilities'].split(',')
                try:
                    self.priv_mgr.drop_privileges(user, capabilities)
                    logger.info(f"Dropped privileges to user {user} with capabilities {capabilities}")
                except Exception as e:
                    logger.error(f"Failed to drop privileges: {str(e)}")
            
            active_mode = True
            last_adjustment_time = time.time()
            current_interval = self.interval
            
            while self.running:
                start_time = time.time()
                
                # Check if service should be active based on activation policy
                if self.service_activator:
                    active_mode = self.service_activator.is_active()
                
                # Check if it's time to adjust the interval based on system load
                if self.perf_optimizer and (time.time() - last_adjustment_time) > 60:  # Adjust every minute
                    recommended_interval = self.perf_optimizer.get_recommended_interval(current_interval)
                    if recommended_interval != current_interval:
                        logger.info(f"Adjusting scan interval from {current_interval}s to {recommended_interval}s based on system load")
                        current_interval = recommended_interval
                    last_adjustment_time = time.time()
                
                # Temporarily restore privileges if configured
                if active_mode and self.priv_mgr and self.config['privilege']['restore_privileges_for_actions'].lower() == 'true':
                    self.priv_mgr.restore_privileges()
                
                # Perform appropriate scan based on activation mode
                if active_mode:
                    logger.info("Performing full seccomp profile check...")
                    vulnerable_processes = self.check_processes()
                    self.generate_report(vulnerable_processes)
                else:
                    # In inactive mode, perform minimal check for critical violations only
                    logger.info("Running in minimal mode - checking only critical processes")
                    self._check_critical_processes_minimal()
                
                # Drop privileges again after scan if they were restored
                if active_mode and self.priv_mgr and self.config['privilege']['restore_privileges_for_actions'].lower() == 'true':
                    user = self.config['privilege']['user']
                    capabilities = self.config['privilege']['capabilities'].split(',')
                    self.priv_mgr.drop_privileges(user, capabilities)
                
                # Calculate how long the check took
                elapsed = time.time() - start_time
                
                # If the check took longer than the interval, log a warning
                if elapsed > current_interval:
                    logger.warning(f"Process check took {elapsed:.1f}s which exceeds the monitoring interval of {current_interval}s")
                    # Sleep for a short time to avoid CPU hogging
                    time.sleep(1)
                else:
                    # Sleep for the remaining time in the interval
                    time.sleep(max(0.1, current_interval - elapsed))
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
        finally:
            # Clean up resources
            self._cleanup_resources()
            
    def _check_critical_processes_minimal(self):
        """Perform a minimal check on critical processes only"""
        try:
            # Get a list of processes belonging to critical services
            critical_procs = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_name = proc.name()
                    if proc_name in self.critical_services:
                        critical_procs.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check if any critical processes have seccomp disabled
            for proc in critical_procs:
                try:
                    seccomp_status = self._get_seccomp_status(proc.pid)
                    if seccomp_status == 0:  # seccomp disabled
                        logger.warning(f"CRITICAL: Process {proc.name()} (PID {proc.pid}) running without seccomp protection")
                except Exception as e:
                    logger.error(f"Error checking process {proc.pid}: {e}")
        except Exception as e:
            logger.error(f"Error in minimal check: {e}")
            
    def _cleanup_resources(self):
        """Clean up resources when shutting down"""
        # Terminate worker processes
        logger.info("Shutting down worker processes...")
        for worker in self.workers:
            if worker.is_alive():
                worker.terminate()
                
        # Release isolation resources if they exist
        if self.isolation_mgr:
            try:
                self.isolation_mgr.cleanup()
                logger.info("Isolation resources cleaned up")
            except Exception as e:
                logger.error(f"Failed to clean up isolation resources: {str(e)}")
                
        # Clean up service activator if it exists
        if self.service_activator:
            try:
                self.service_activator.deactivate("shutdown")
                logger.info("Service activator deactivated")
            except Exception as e:
                logger.error(f"Failed to deactivate service activator: {str(e)}")
                
        # Clean up performance optimizer if it exists
        if self.perf_optimizer:
            try:
                self.perf_optimizer.cleanup()
                logger.info("Performance optimizer cleaned up")
            except Exception as e:
                logger.error(f"Failed to clean up performance optimizer: {str(e)}")
                
        # Clean up PID file
        try:
            pid_file = self.config['monitor'].get('pidfile', '/var/run/seccomp_monitor.pid')
            if os.path.exists(pid_file):
                os.remove(pid_file)
                logger.info(f"Removed PID file {pid_file}")
        except Exception as e:
            logger.error(f"Failed to remove PID file: {str(e)}")
                
        logger.info("Seccomp Profile Monitor shutting down")


def main():
    """Main entry point"""
    monitor = SeccompMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
