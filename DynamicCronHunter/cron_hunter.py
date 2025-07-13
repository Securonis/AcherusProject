#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dynamic Cron & Timer Hunter
---------------------------
This script monitors crontab files, /etc/cron.* directories, and systemd timer units
for changes, reports new jobs, analyzes for suspicious strings, and detects
persistence mechanisms.

Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import sys
import time
import logging
import subprocess
import re
import hashlib
import json
import tempfile
import configparser
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from contextlib import contextmanager

# Import our security and performance utility modules
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
        logging.FileHandler("/var/log/cron_hunter.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('cron_hunter')


class CronHunter:
    """Main class for the Dynamic Cron & Timer Hunter."""
    
    def __init__(self, config_path: str = '/etc/cron_hunter.conf'):
        """Initialize the CronHunter."""
        # Load configuration
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Parse configuration
        self.check_interval = int(self.config['monitor']['interval'])
        self.hash_algorithm = self.config['monitor']['hash_algorithm']
        self.cron_dirs = self.config['detection']['cron_dirs'].split(',')
        self.systemd_timer_dirs = self.config['detection']['timer_dirs'].split(',')
        self.user_crontab_check = self.config['detection'].getboolean('user_crontab_check')
        
        # Load suspicious patterns
        self.suspicious_patterns = {}
        for key, pattern in self.config['suspicious_patterns'].items():
            self.suspicious_patterns[key] = pattern
        
        # Initialize security and performance modules
        self._setup_security_and_performance()
        
        # Signal handling
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        # Store file hashes for change detection
        self.file_hashes = {}
        self.timer_hashes = {}
        self.user_crontabs = {}
        self.running = True
        
        # Initialize tracking
        self.initialize_tracking()
        
        logger.info("Dynamic Cron & Timer Hunter initialized")
        logger.info(f"Monitoring interval: {self.check_interval} seconds")
        logger.info(f"Monitoring {len(self.cron_dirs)} cron directories and {len(self.systemd_timer_dirs)} systemd timer directories")
    
    def _load_config(self, config_path: str) -> configparser.ConfigParser:
        """Load configuration from file or use defaults."""
        # Default configuration
        defaults = {
            'monitor': {
                'interval': '60',
                'log_level': 'INFO',
                'log_file': '/var/log/cron_hunter.log',
                'detailed_logging': 'true',
                'hash_algorithm': 'sha256',
                'pidfile': '/var/run/cron_hunter.pid'
            },
            'detection': {
                'user_crontab_check': 'true',
                'cron_dirs': '/etc/crontab,/etc/cron.d,/etc/cron.hourly,/etc/cron.daily,/etc/cron.weekly,/etc/cron.monthly',
                'timer_dirs': '/etc/systemd/system,/usr/lib/systemd/system'
            },
            'suspicious_patterns': {
                'wget_http': 'wget\s+http',
                'curl_http': 'curl\s+http',
                'base64_encoded_commands': 'base64\s+-d|base64\s+--decode',
                'reverse_shell_patterns': 'nc\s+-e|bash\s+-i\s+>|\\bncat\s+[^>]*\|\s*bash',
                'pipe_to_shell': '\|\s*sh|\|\s*bash|\|\s*\/bin\/sh|\|\s*\/bin\/bash',
                'suspicious_pipe_shell': '\/dev\/tcp\/|\/dev\/udp\/',
                'suspicious_download': 'curl\s+.*\s+\|\s*sh|wget\s+.*\s+\|\s*sh',
                'suspicious_eval': 'eval\s*\(.*\$',
                'obfuscated_shells': 'python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r',
                'execution_from_tmp': '\/tmp\/.*\.sh|\/tmp\/.*\.pl|\/tmp\/.*\.py'
            },
            'privilege': {
                'enabled': 'false',
                'user': 'cron_hunter',
                'group': 'cron_hunter',
                'drop_privileges': 'true',
                'restore_privileges_for_actions': 'true',
                'create_user_if_not_exists': 'true',
                'data_directory': '/var/lib/cron_hunter'
            },
            'isolation': {
                'enabled': 'false',
                'use_namespaces': 'true',
                'use_cgroups': 'true',
                'cgroup_name': 'cron_hunter',
                'memory_limit_mb': '128',
                'cpu_quota_percent': '20',
                'restrict_network': 'false',
                'restrict_filesystem': 'true'
            },
            'performance': {
                'enabled': 'true',
                'adaptive_monitoring': 'true',
                'min_interval': '30',
                'max_interval': '300',
                'cpu_threshold_percent': '70',
                'memory_threshold_percent': '70',
                'track_resource_usage': 'true'
            },
            'monitoring_scope': {
                'enabled': 'true',
                'exclude_patterns': '^/dev,^/proc,^/sys,^/run',
                'include_only_patterns': '',
                'priority_patterns': '\.service$,\.timer$',
                'use_regex': 'true'
            },
            'service_activation': {
                'enabled': 'true',
                'default_mode': 'always',  # always, manual, scheduled, event, threshold
                'schedule': '0 * * * *',  # hourly in cron format
                'activation_duration': '300',  # seconds to stay active when triggered
                'event_triggers': 'file_change,timer_change',
                'threshold_metric': 'suspicious_files',
                'threshold_value': '1'
            },
            'action': {
                'alert_command': ''
            },
            'whitelist': {
                'ignore_paths': '',
                'ignore_users': ''
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
        """Configure logging based on config."""
        log_level_name = self.config['monitor']['log_level']
        log_level = getattr(logging, log_level_name.upper(), logging.INFO)
        log_file = self.config['monitor']['log_file']
        
        # Configure root logger
        logger.setLevel(log_level)
        
        # Remove all handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Add file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        
        # Add console handler if we're not daemonized
        if os.isatty(sys.stderr.fileno()):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(console_handler)
            
    def _setup_security_and_performance(self):
        """Initialize security and performance modules based on configuration."""
        # Initialize attribute placeholders
        self.priv_mgr = None
        self.isolation_mgr = None
        self.perf_optimizer = None
        self.monitoring_scope = None
        self.service_activator = None
        self.interval = None
        
        try:
            # Initialize IsolationManager if enabled
            if self.config['isolation']['enabled'].lower() == 'true':
                namespaces = self.config['isolation']['use_namespaces'].lower() == 'true'
                cgroups = self.config['isolation']['use_cgroups'].lower() == 'true'
                
                if namespaces or cgroups:
                    self.isolation_mgr = IsolationManager(
                        use_namespaces=namespaces,
                        use_cgroups=cgroups,
                        cgroup_name=self.config['isolation']['cgroup_name'],
                        memory_limit_mb=int(self.config['isolation']['memory_limit_mb']),
                        cpu_quota_percent=int(self.config['isolation']['cpu_quota_percent']),
                        restrict_network=self.config['isolation']['restrict_network'].lower() == 'true',
                        restrict_filesystem=self.config['isolation']['restrict_filesystem'].lower() == 'true'
                    )
                    logger.info(f"Initialized isolation with namespaces={namespaces}, cgroups={cgroups}")
            
            # Initialize PrivilegeManager if enabled
            if self.config['privilege']['enabled'].lower() == 'true':
                self.priv_mgr = PrivilegeManager(
                    user=self.config['privilege']['user'],
                    group=self.config['privilege']['group'],
                    create_if_not_exists=self.config['privilege']['create_user_if_not_exists'].lower() == 'true',
                    data_dir=self.config['privilege']['data_directory']
                )
                logger.info(f"Initialized privilege manager for user {self.config['privilege']['user']}")
                
                # Create necessary directories with appropriate permissions
                if self.config['privilege']['create_user_if_not_exists'].lower() == 'true':
                    data_dir = self.config['privilege']['data_directory']
                    self.priv_mgr.prepare_directory(data_dir)
                    logger.info(f"Created data directory: {data_dir}")
            
            # Initialize PerformanceOptimizer if enabled
            if self.config['performance']['enabled'].lower() == 'true':
                self.perf_optimizer = PerformanceOptimizer(
                    base_interval=int(self.config['monitor']['interval']),
                    min_interval=int(self.config['performance']['min_interval']),
                    max_interval=int(self.config['performance']['max_interval']),
                    cpu_threshold=float(self.config['performance']['cpu_threshold_percent']),
                    memory_threshold=float(self.config['performance']['memory_threshold_percent']),
                    adaptive=self.config['performance']['adaptive_monitoring'].lower() == 'true',
                    track_usage=self.config['performance']['track_resource_usage'].lower() == 'true'
                )
                logger.info("Initialized performance optimizer")
            
            # Initialize MonitoringScope if enabled
            if self.config['monitoring_scope']['enabled'].lower() == 'true':
                exclude_patterns = self.config['monitoring_scope']['exclude_patterns'].split(',') if self.config['monitoring_scope']['exclude_patterns'] else []
                include_patterns = self.config['monitoring_scope']['include_only_patterns'].split(',') if self.config['monitoring_scope']['include_only_patterns'] else []
                priority_patterns = self.config['monitoring_scope']['priority_patterns'].split(',') if self.config['monitoring_scope']['priority_patterns'] else []
                
                self.monitoring_scope = MonitoringScope(
                    exclude_patterns=exclude_patterns,
                    include_patterns=include_patterns,
                    priority_patterns=priority_patterns,
                    use_regex=self.config['monitoring_scope']['use_regex'].lower() == 'true'
                )
                logger.info(f"Initialized monitoring scope with {len(exclude_patterns)} exclude patterns, {len(include_patterns)} include patterns")
            
            # Initialize ServiceActivator if enabled
            if self.config['service_activation']['enabled'].lower() == 'true':
                mode = self.config['service_activation']['default_mode']
                schedule = self.config['service_activation']['schedule']
                duration = int(self.config['service_activation']['activation_duration'])
                event_triggers = self.config['service_activation']['event_triggers'].split(',') if self.config['service_activation']['event_triggers'] else []
                threshold_metric = self.config['service_activation']['threshold_metric']
                threshold_value = float(self.config['service_activation']['threshold_value'])
                
                self.service_activator = ServiceActivator(
                    mode=mode,
                    schedule=schedule,
                    activation_duration=duration,
                    event_triggers=event_triggers,
                    threshold_metric=threshold_metric,
                    threshold_value=threshold_value,
                    on_activate_callback=self._on_service_activated,
                    on_deactivate_callback=self._on_service_deactivated
                )
                logger.info(f"Initialized service activator in {mode} mode")
                
        except Exception as e:
            logger.error(f"Error setting up security and performance modules: {e}")
            
    def _on_service_activated(self, reason: str):
        """Callback when service is activated"""
        logger.info(f"Service activated: {reason}")
        
    def _on_service_deactivated(self):
        """Callback when service is deactivated"""
        logger.info("Service deactivated")
        # Reset suspicious file count metrics when deactivated
        if self.service_activator:
            self.service_activator.update_monitored_value('suspicious_files', 0)
            
    def _get_optimal_sleep_interval(self):
        """Get the optimal sleep interval based on performance optimization settings"""
        if self.perf_optimizer and self.config['performance']['adaptive_monitoring'].lower() == 'true':
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
                    
            # Do a quick check for any changed critical files
            for directory in self.cron_dirs[:1]:  # Only check the first directory
                if os.path.exists(directory):
                    changes_found = self._quick_check_directory(directory)
                    
                    if changes_found and self.service_activator:
                        self.service_activator.activate("Critical file change detected during minimal scan")
                        return
                        
        except Exception as e:
            logger.error(f"Error in minimal scan: {str(e)}")
    
    def _quick_check_directory(self, directory):
        """Quickly check if any files in a directory have changed"""
        changes_found = False
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip if this file should be excluded based on monitoring scope
                    if self.monitoring_scope and not self.monitoring_scope.should_monitor(file_path):
                        continue
                    
                    # Only check files we're already tracking
                    if file_path in self.file_hashes:
                        current_hash = self._calculate_file_hash(file_path)
                        if current_hash != self.file_hashes[file_path]['hash']:
                            changes_found = True
                            logger.info(f"Change detected in {file_path} during minimal scan")
                            break
                            
                if changes_found:
                    break
        except Exception as e:
            logger.debug(f"Error in quick directory check: {e}")
            
        return changes_found
        
    def _run_full_scan_cycle(self):
        """Run a full scan cycle with all monitoring features"""
        try:
            # Start performance monitoring for this cycle
            if self.perf_optimizer:
                self.perf_optimizer.start_operation("scan_cycle")
                
            logger.debug("Starting full scan cycle")
            
            # Temporarily restore privileges for scanning if needed
            if (self.priv_mgr and 
                self.config['privilege']['enabled'].lower() == 'true' and
                self.config['privilege']['restore_privileges_for_actions'].lower() == 'true'):
                with self.priv_mgr.temporarily_restore_privileges():
                    changes = self.check_for_changes()
            else:
                changes = self.check_for_changes()
                
            # Track metrics for service activation
            if self.service_activator:
                self.service_activator.update_monitored_value('suspicious_files', changes)
                
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
            logger.error(f"Error in full scan cycle: {str(e)}")
        
    def _handle_signal(self, signum, frame):
        """Handle termination signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def initialize_tracking(self):
        """Initialize tracking by recording initial states."""
        logger.info("Initializing tracking of cron files and systemd timers")
        
        # Track cron files
        for cron_dir in self.cron_dirs:
            if os.path.isdir(cron_dir):
                self._process_directory(cron_dir)
            elif os.path.isfile(cron_dir):
                self._add_file_to_tracking(cron_dir)
        
        # Track systemd timer units
        for timer_dir in self.systemd_timer_dirs:
            if os.path.isdir(timer_dir):
                self._process_systemd_directory(timer_dir)
        
        # Track user crontabs if enabled
        if USER_CRONTAB_CHECK:
            self._track_user_crontabs()
        
        logger.info(f"Initial tracking complete. Monitoring {len(self.file_hashes)} files and {len(self.timer_hashes)} timer units")
    
    def _process_directory(self, directory: str):
        """Process all files in a directory for tracking."""
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    self._add_file_to_tracking(file_path)
        except Exception as e:
            logger.error(f"Error processing directory {directory}: {e}")
    
    def _process_systemd_directory(self, directory: str):
        """Process systemd timer files in a directory."""
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.timer'):
                        file_path = os.path.join(root, file)
                        self._add_timer_to_tracking(file_path)
        except Exception as e:
            logger.error(f"Error processing systemd directory {directory}: {e}")
    
    def _add_file_to_tracking(self, file_path: str):
        """Add a file to tracking by calculating and storing its hash."""
        try:
            file_hash = self._calculate_file_hash(file_path)
            if file_hash:
                self.file_hashes[file_path] = {
                    'hash': file_hash,
                    'last_checked': datetime.now(),
                    'content': self._get_file_content(file_path)
                }
                logger.debug(f"Added {file_path} to tracking")
        except Exception as e:
            logger.error(f"Error adding file to tracking {file_path}: {e}")
    
    def _add_timer_to_tracking(self, file_path: str):
        """Add a systemd timer to tracking."""
        try:
            file_hash = self._calculate_file_hash(file_path)
            if file_hash:
                self.timer_hashes[file_path] = {
                    'hash': file_hash,
                    'last_checked': datetime.now(),
                    'properties': self._get_timer_properties(file_path)
                }
                logger.debug(f"Added timer {file_path} to tracking")
        except Exception as e:
            logger.error(f"Error adding timer to tracking {file_path}: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate the hash of a file."""
        try:
            hash_obj = hashlib.new(self.hash_algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def _get_file_content(self, file_path: str) -> str:
        """Get the content of a file as a string."""
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file content {file_path}: {e}")
            return ""
    
    def _get_timer_properties(self, timer_path: str) -> Dict[str, Any]:
        """Get properties of a systemd timer using systemctl."""
        properties = {}
        try:
            # Get timer unit name
            unit_name = os.path.basename(timer_path)
            
            # Use systemctl show to get properties
            cmd = ['systemctl', 'show', unit_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse properties
                for line in result.stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        properties[key.strip()] = value.strip()
            
            # Also store the raw content
            properties['RawContent'] = self._get_file_content(timer_path)
            
            return properties
        except Exception as e:
            logger.error(f"Error getting timer properties for {timer_path}: {e}")
            return {'Error': str(e)}
    
    def _track_user_crontabs(self):
        """Track user crontabs."""
        if not self.user_crontab_check:
            return
            
        try:
            # Get all users
            result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'], 
                                   capture_output=True, text=True)
            
            if result.returncode == 0:
                users = result.stdout.strip().split('\n')
                # Check whitelist
                ignored_users = self.config['whitelist'].get('ignore_users', '').split(',')
                ignored_users = [user.strip() for user in ignored_users if user.strip()]
                
                for user in users:
                    if user not in ignored_users:
                        self._check_user_crontab(user)
        except Exception as e:
            logger.error(f"Error tracking user crontabs: {e}")
    
    def _check_user_crontab(self, user: str):
        """Check a specific user's crontab."""
        try:
            # Use temporary file to avoid permission issues
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name
            
            # Try to get user's crontab
            cmd = ['sudo', '-u', user, 'crontab', '-l']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                # Write to temp file to calculate hash
                with open(tmp_path, 'w') as f:
                    f.write(result.stdout)
                
                file_hash = self._calculate_file_hash(tmp_path)
                
                if file_hash:
                    self.user_crontabs[user] = {
                        'hash': file_hash,
                        'last_checked': datetime.now(),
                        'content': result.stdout
                    }
                    logger.debug(f"Added crontab for user {user} to tracking")
            
            # Clean up temp file
            os.unlink(tmp_path)
        except Exception as e:
            logger.debug(f"No crontab or error for user {user}: {e}")
    
    def check_for_changes(self):
        """Check for changes in tracked files and timers.
        
        Returns:
            int: Number of suspicious changes detected
        """
        logger.info("Checking for changes in cron files and systemd timers")
        
        # Counter for suspicious changes (used for service activation decisions)
        suspicious_changes = 0
        
        # Check cron files
        for cron_dir in self.cron_dirs:
            # Skip if excluded by monitoring scope
            if self.monitoring_scope and not self.monitoring_scope.should_monitor(cron_dir):
                logger.debug(f"Skipping excluded directory: {cron_dir}")
                continue
                
            if os.path.isdir(cron_dir):
                suspicious_changes += self._check_directory_for_changes(cron_dir)
            elif os.path.isfile(cron_dir):
                suspicious_changes += self._check_file_for_changes(cron_dir)
        
        # Check systemd timer units
        for timer_dir in self.systemd_timer_dirs:
            # Skip if excluded by monitoring scope
            if self.monitoring_scope and not self.monitoring_scope.should_monitor(timer_dir):
                logger.debug(f"Skipping excluded timer directory: {timer_dir}")
                continue
                
            if os.path.isdir(timer_dir):
                suspicious_changes += self._check_systemd_directory_for_changes(timer_dir)
        
        # Check user crontabs if enabled
        if self.user_crontab_check:
            suspicious_changes += self._check_user_crontabs_for_changes()
        
        logger.info(f"Change detection cycle completed. Found {suspicious_changes} suspicious changes")
        
        return suspicious_changes
    
    def _check_directory_for_changes(self, directory: str) -> int:
        """Check a directory for new, modified, or deleted files.
        
        Args:
            directory (str): Directory to check for changes
            
        Returns:
            int: Number of suspicious changes detected
        """
        suspicious_count = 0
        try:
            # Keep track of existing files
            existing_files = []
            
            # Check for new or modified files
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip files that shouldn't be monitored
                    if self.monitoring_scope and not self.monitoring_scope.should_monitor(file_path):
                        logger.debug(f"Skipping excluded file: {file_path}")
                        continue
                        
                    existing_files.append(file_path)
                    
                    if file_path not in self.file_hashes:
                        # New file detected
                        self._add_file_to_tracking(file_path)
                        is_suspicious = self._analyze_and_report(file_path, "NEW_CRON_FILE")
                        if is_suspicious:
                            suspicious_count += 1
                    else:
                        # Check for changes
                        is_suspicious = self._check_file_for_changes(file_path)
                        if is_suspicious:
                            suspicious_count += 1
            
            # Check for deleted files
            tracked_files = [path for path in self.file_hashes.keys() 
                            if path.startswith(directory)]
            
            for file_path in tracked_files:
                if file_path not in existing_files:
                    # File was deleted
                    is_suspicious = self._report_deletion(file_path, "DELETED_CRON_FILE")
                    if is_suspicious:
                        suspicious_count += 1
                    del self.file_hashes[file_path]
        
        except Exception as e:
            logger.error(f"Error checking directory for changes {directory}: {e}")
            
        return suspicious_count
    
    def _check_systemd_directory_for_changes(self, directory: str) -> int:
        """Check a systemd directory for new, modified, or deleted timer files.
        
        Args:
            directory (str): Systemd directory to check for changes
            
        Returns:
            int: Number of suspicious changes detected
        """
        suspicious_count = 0
        try:
            # Keep track of existing timer files
            existing_timers = []
            
            # Check for new or modified timer files
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.timer'):
                        file_path = os.path.join(root, file)
                        
                        # Skip files that shouldn't be monitored
                        if self.monitoring_scope and not self.monitoring_scope.should_monitor(file_path):
                            logger.debug(f"Skipping excluded timer file: {file_path}")
                            continue
                            
                        existing_timers.append(file_path)
                        
                        if file_path not in self.timer_hashes:
                            # New timer detected
                            self._add_timer_to_tracking(file_path)
                            is_suspicious = self._analyze_and_report(file_path, "NEW_TIMER_UNIT", is_timer=True)
                            if is_suspicious:
                                suspicious_count += 1
                        else:
                            # Check for changes
                            is_suspicious = self._check_timer_for_changes(file_path)
                            if is_suspicious:
                                suspicious_count += 1
            
            # Check for deleted timers
            tracked_timers = [path for path in self.timer_hashes.keys() 
                             if path.startswith(directory)]
            
            for timer_path in tracked_timers:
                if timer_path not in existing_timers:
                    # Timer was deleted
                    is_suspicious = self._report_deletion(timer_path, "DELETED_TIMER_UNIT", is_timer=True)
                    if is_suspicious:
                        suspicious_count += 1
                    del self.timer_hashes[timer_path]
                    
        except Exception as e:
            logger.error(f"Error checking systemd directory for changes {directory}: {e}")
            
        return suspicious_count
    
    def _check_file_for_changes(self, file_path: str) -> bool:
        """Check if a file has changed.
        
        Args:
            file_path (str): Path to the file to check
            
        Returns:
            bool: True if suspicious changes were found, False otherwise
        """
        suspicious = False
        try:
            # Skip if excluded by monitoring scope
            if self.monitoring_scope and not self.monitoring_scope.should_monitor(file_path):
                logger.debug(f"Skipping excluded file: {file_path}")
                return False
                
            if not os.path.exists(file_path):
                # File was deleted
                if file_path in self.file_hashes:
                    suspicious = self._report_deletion(file_path, "DELETED_CRON_FILE")
                    del self.file_hashes[file_path]
                return suspicious
            
            new_hash = self._calculate_file_hash(file_path)
            
            if file_path in self.file_hashes:
                old_hash = self.file_hashes[file_path]['hash']
                
                if new_hash != old_hash:
                    # File was modified
                    old_content = self.file_hashes[file_path]['content']
                    new_content = self._get_file_content(file_path)
                    
                    # Update tracking
                    self.file_hashes[file_path] = {
                        'hash': new_hash,
                        'last_checked': datetime.now(),
                        'content': new_content
                    }
                    
                    # Report the change
                    self._report_modification(file_path, "MODIFIED_CRON_FILE", old_content, new_content)
                    
                    # Analyze the modified file - returns True if suspicious content found
                    suspicious = self._analyze_file_content(file_path, new_content)
            else:
                # New file detected
                self._add_file_to_tracking(file_path)
                suspicious = self._analyze_and_report(file_path, "NEW_CRON_FILE")
                
        except Exception as e:
            logger.error(f"Error checking file for changes {file_path}: {e}")
            
        return suspicious
    
    def _check_timer_for_changes(self, timer_path: str) -> bool:
        """Check if a systemd timer has changed.
        
        Args:
            timer_path (str): Path to the timer file to check
            
        Returns:
            bool: True if suspicious changes were found, False otherwise
        """
        suspicious = False
        try:
            # Skip if excluded by monitoring scope
            if self.monitoring_scope and not self.monitoring_scope.should_monitor(timer_path):
                logger.debug(f"Skipping excluded timer: {timer_path}")
                return False
                
            if not os.path.exists(timer_path):
                # Timer was deleted
                if timer_path in self.timer_hashes:
                    suspicious = self._report_deletion(timer_path, "DELETED_TIMER_UNIT", is_timer=True)
                    del self.timer_hashes[timer_path]
                return suspicious
            
            new_hash = self._calculate_file_hash(timer_path)
            
            if timer_path in self.timer_hashes:
                old_hash = self.timer_hashes[timer_path]['hash']
                
                if new_hash != old_hash:
                    # Timer was modified
                    old_props = self.timer_hashes[timer_path]['properties']
                    new_props = self._get_timer_properties(timer_path)
                    
                    # Update tracking
                    self.timer_hashes[timer_path] = {
                        'hash': new_hash,
                        'last_checked': datetime.now(),
                        'properties': new_props
                    }
                    
                    # Report the change
                    suspicious = self._report_timer_modification(timer_path, "MODIFIED_TIMER_UNIT", 
                                                               old_props, new_props)
                    
                    # Analyze the modified timer
                    if new_props and 'RawContent' in new_props:
                        is_susp = self._analyze_timer_content(timer_path, new_props['RawContent'])
                        suspicious = suspicious or is_susp
            else:
                # New timer detected
                self._add_timer_to_tracking(timer_path)
                suspicious = self._analyze_and_report(timer_path, "NEW_TIMER_UNIT", is_timer=True)
                
        except Exception as e:
            logger.error(f"Error checking timer for changes {timer_path}: {e}")
            
        return suspicious
    
    def _check_user_crontabs_for_changes(self):
        """Check user crontabs for changes."""
        try:
            # Get all users
            result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'], 
                                   capture_output=True, text=True)
            
            if result.returncode == 0:
                users = result.stdout.strip().split('\n')
                
                # Track existing users
                existing_users = []
                
                for user in users:
                    existing_users.append(user)
                    
                    # Use temporary file to avoid permission issues
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                    
                    # Try to get user's crontab
                    cmd = ['sudo', '-u', user, 'crontab', '-l']
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        # Write to temp file to calculate hash
                        with open(tmp_path, 'w') as f:
                            f.write(result.stdout)
                        
                        new_hash = self._calculate_file_hash(tmp_path)
                        
                        if user in self.user_crontabs:
                            old_hash = self.user_crontabs[user]['hash']
                            
                            if new_hash != old_hash:
                                # Crontab was modified
                                old_content = self.user_crontabs[user]['content']
                                new_content = result.stdout
                                
                                # Update tracking
                                self.user_crontabs[user] = {
                                    'hash': new_hash,
                                    'last_checked': datetime.now(),
                                    'content': new_content
                                }
                                
                                # Report the change
                                self._report_user_crontab_modification(user, old_content, new_content)
                        else:
                            # New user crontab detected
                            self.user_crontabs[user] = {
                                'hash': new_hash,
                                'last_checked': datetime.now(),
                                'content': result.stdout
                            }
                            self._report_new_user_crontab(user, result.stdout)
                    
                    # Clean up temp file
                    os.unlink(tmp_path)
                
                # Check for deleted user crontabs
                for user in list(self.user_crontabs.keys()):
                    if user not in existing_users:
                        # User no longer exists
                        self._report_deleted_user_crontab(user)
                        del self.user_crontabs[user]
        
        except Exception as e:
            logger.error(f"Error checking user crontabs for changes: {e}")
    
    def _analyze_and_report(self, file_path: str, event_type: str):
        """Analyze a file and report findings."""
        try:
            if event_type.startswith("NEW_SYSTEMD_TIMER") or event_type.startswith("MODIFIED_SYSTEMD_TIMER"):
                content = self.timer_hashes[file_path]['properties'].get('RawContent', '')
                self._analyze_timer_content(file_path, content)
            else:
                content = self.file_hashes[file_path]['content']
                self._analyze_file_content(file_path, content)
            
            logger.info(f"{event_type}: {file_path}")
        except Exception as e:
            logger.error(f"Error analyzing and reporting {file_path}: {e}")
    
    def _analyze_file_content(self, file_path: str, content: str):
        """Analyze file content for suspicious patterns."""
        try:
            for pattern_name, pattern in self.suspicious_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self._report_suspicious_pattern(file_path, "SUSPICIOUS_CRON_CONTENT", pattern_name)
                    break
        except Exception as e:
            logger.error(f"Error analyzing file content {file_path}: {e}")
    
    def _analyze_timer_content(self, timer_path: str, content: str):
        """Analyze timer content for suspicious patterns."""
        try:
            for pattern_name, pattern in self.suspicious_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self._report_suspicious_pattern(timer_path, "SUSPICIOUS_TIMER_CONTENT", pattern_name)
                    break
        except Exception as e:
            logger.error(f"Error analyzing timer content {timer_path}: {e}")
    
    def _report_deletion(self, file_path: str, event_type: str):
        """Report deletion of a tracked file."""
        logger.warning(f"{event_type}: {file_path}")
        
        # Send alert if configured
        if ALERT_COMMAND:
            self._send_alert(f"{event_type}: {file_path}")
    
    def _report_modification(self, file_path: str, event_type: str, old_content: str, new_content: str):
        """Report modification of a tracked file."""
        logger.warning(f"{event_type}: {file_path}")
        
        # Log detailed changes if enabled
        if self.config['monitor'].getboolean('detailed_logging'):
            # Create a diff of the changes
            with tempfile.NamedTemporaryFile(delete=False) as old_file:
                old_path = old_file.name
                old_file.write(old_content.encode())
            
            with tempfile.NamedTemporaryFile(delete=False) as new_file:
                new_path = new_file.name
                new_file.write(new_content.encode())
            
            try:
                diff_cmd = ['diff', old_path, new_path]
                diff_result = subprocess.run(diff_cmd, capture_output=True, text=True)
                
                if diff_result.returncode != 0:  # diff returns 1 if files are different
                    logger.info(f"Changes in {file_path}:\n{diff_result.stdout}")
            except Exception as e:
                logger.error(f"Error creating diff for {file_path}: {e}")
            finally:
                os.unlink(old_path)
                os.unlink(new_path)
        
        # Send alert if configured
        alert_command = self.config['action'].get('alert_command', '')
        if alert_command:
            self._send_alert(f"{event_type}: {file_path}")
    
    def _report_timer_modification(self, timer_path: str, event_type: str, old_props: Dict[str, Any], new_props: Dict[str, Any]):
        """Report modification of a systemd timer."""
        logger.warning(f"{event_type}: {timer_path}")
        
        # Log detailed changes if enabled
        if self.config['monitor'].getboolean('detailed_logging'):
            # Compare important properties
            important_props = ['Unit', 'OnCalendar', 'OnBootSec', 'OnUnitActiveSec', 'ExecStart']
            changes = []
            
            for prop in important_props:
                old_val = old_props.get(prop, 'N/A')
                new_val = new_props.get(prop, 'N/A')
                
                if old_val != new_val:
                    changes.append(f"{prop}: '{old_val}' -> '{new_val}'")
            
            if changes:
                logger.info(f"Changes in {timer_path}:\n" + "\n".join(changes))
        
        # Send alert if configured
        alert_command = self.config['action'].get('alert_command', '')
        if alert_command:
            self._send_alert(f"{event_type}: {timer_path}")
    
    def _report_suspicious_pattern(self, file_path: str, event_type: str, pattern_name: str):
        """Report suspicious pattern found in a file."""
        message = f"{event_type}: {file_path} contains suspicious pattern '{pattern_name}'"
        logger.critical(message)
        
        # Send alert if configured
        if ALERT_COMMAND:
            self._send_alert(message)
    
    def _report_new_user_crontab(self, user: str, content: str):
        """Report new user crontab."""
        message = f"NEW_USER_CRONTAB: New crontab detected for user {user}"
        logger.warning(message)
        
        # Log the content
        if ENABLE_DETAILED_LOGGING:
            logger.info(f"Content of new crontab for user {user}:\n{content}")
        
        # Analyze for suspicious patterns
        for pattern_name, pattern in self.suspicious_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                suspicious_msg = f"SUSPICIOUS_USER_CRONTAB: User {user} crontab contains suspicious pattern '{pattern_name}'"
                logger.critical(suspicious_msg)
                
                # Send alert if configured
                if ALERT_COMMAND:
                    self._send_alert(suspicious_msg)
                break
        
        # Send alert if configured
        if ALERT_COMMAND:
            self._send_alert(message)
    
    def _report_user_crontab_modification(self, user: str, old_content: str, new_content: str):
        """Report modification of a user crontab."""
        message = f"MODIFIED_USER_CRONTAB: Crontab modified for user {user}"
        logger.warning(message)
        
        # Log detailed changes if enabled
        if ENABLE_DETAILED_LOGGING:
            # Create a diff of the changes
            with tempfile.NamedTemporaryFile(delete=False) as old_file:
                old_path = old_file.name
                old_file.write(old_content.encode())
            
            with tempfile.NamedTemporaryFile(delete=False) as new_file:
                new_path = new_file.name
                new_file.write(new_content.encode())
            
            try:
                diff_cmd = ['diff', old_path, new_path]
                diff_result = subprocess.run(diff_cmd, capture_output=True, text=True)
                
                if diff_result.returncode != 0:  # diff returns 1 if files are different
                    logger.info(f"Changes in crontab for user {user}:\n{diff_result.stdout}")
            except Exception as e:
                logger.error(f"Error creating diff for user {user} crontab: {e}")
            finally:
                os.unlink(old_path)
                os.unlink(new_path)
        
        # Analyze for suspicious patterns
        for pattern_name, pattern in self.suspicious_patterns.items():
            if re.search(pattern, new_content, re.IGNORECASE) and not re.search(pattern, old_content, re.IGNORECASE):
                suspicious_msg = f"SUSPICIOUS_USER_CRONTAB_MODIFICATION: User {user} crontab modified to include suspicious pattern '{pattern_name}'"
                logger.critical(suspicious_msg)
                
                # Send alert if configured
                if ALERT_COMMAND:
                    self._send_alert(suspicious_msg)
                break
        
        # Send alert if configured
        if ALERT_COMMAND:
            self._send_alert(message)
    
    def _report_deleted_user_crontab(self, user: str):
        """Report deletion of a user crontab."""
        message = f"DELETED_USER_CRONTAB: Crontab deleted for user {user}"
        logger.warning(message)
        
        # Send alert if configured
        if ALERT_COMMAND:
            self._send_alert(message)
    
    def _send_alert(self, message: str):
        """Send an alert using the configured alert command."""
        try:
            alert_command = self.config['action'].get('alert_command', '')
            if alert_command:
                cmd = alert_command.replace("%MESSAGE%", message)
                subprocess.run(cmd, shell=True)
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    def run(self):
        """Main execution loop."""
        logger.info("Starting Dynamic Cron & Timer Hunter")
        
        # Write PID file if configured
        pidfile = self.config['monitor'].get('pidfile', '')
        if pidfile:
            try:
                with open(pidfile, 'w') as f:
                    f.write(str(os.getpid()))
                logger.info(f"PID {os.getpid()} written to {pidfile}")
            except Exception as e:
                logger.error(f"Could not write PID file {pidfile}: {e}")
        
        # Apply isolation if configured
        if (self.isolation_mgr and 
            self.config['isolation']['enabled'].lower() == 'true'):
            try:
                self.isolation_mgr.apply_isolation()
                logger.info("Applied process isolation")
            except Exception as e:
                logger.error(f"Failed to apply isolation: {str(e)}")
        
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
        
        try:
            # Main service loop
            while self.running:
                try:
                    # Check if service should be active
                    is_active = True
                    if self.service_activator:
                        is_active = self.service_activator.is_active
                    
                    if is_active:
                        # Full monitoring when active
                        logger.debug("Running full scan cycle")
                        self._run_full_scan_cycle()
                    else:
                        # Minimal monitoring when inactive
                        logger.debug("Running minimal scan cycle")
                        self._run_minimal_scan()
                    
                    # Determine sleep interval
                    sleep_time = self._get_optimal_sleep_interval()
                    
                    # Break sleep into smaller chunks for responsiveness
                    chunks = max(1, min(10, sleep_time))  # Between 1-10 chunks
                    chunk_time = sleep_time / chunks
                    for _ in range(int(chunks)):
                        if not self.running:
                            break
                        time.sleep(chunk_time)
                except Exception as e:
                    logger.error(f"Error in scan cycle: {e}")
                    time.sleep(10)  # Shorter wait on error
                    
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, stopping Dynamic Cron & Timer Hunter")
        except Exception as e:
            logger.critical(f"Critical error in main loop: {e}")
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
        config_path = '/etc/cron_hunter.conf'
        if len(sys.argv) > 1:
            config_path = sys.argv[1]
        
        hunter = CronHunter(config_path)
        hunter.run()
    except Exception as e:
        logger.critical(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
