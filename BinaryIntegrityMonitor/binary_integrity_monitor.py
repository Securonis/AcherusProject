#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Binary Integrity Monitor
-----------------------
Monitors critical binary files for unauthorized modifications by tracking their
cryptographic hash values (SHA-256). When a change is detected, the service:
1. Logs the incident
2. Quarantines the modified file
3. Triggers system lockdown mode

Author: Root0Emir - Securonis Linux
License: GPLv3
NOTE: This is a prototype with limited testing time
"""

import os
import sys
import time
import hashlib
import logging
import shutil
import json
import signal
import configparser
import subprocess
import threading
import queue
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Tuple, Union

# Import security and performance utility modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.privilege_manager import PrivilegeManager
from utils.isolation_manager import IsolationManager
from utils.performance_optimizer import PerformanceOptimizer
from utils.monitoring_scope import MonitoringScope
from utils.service_activator import ServiceActivator

# Configure logging
log_directory = Path("/var/log/binary_integrity")
log_directory.mkdir(exist_ok=True, parents=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_directory / "binary_integrity_monitor.log"),
        logging.StreamHandler(),
        # Critical alerts handler - separate file for critical events
        logging.FileHandler(log_directory / "binary_integrity_alerts.log", 
                           level=logging.CRITICAL)
    ]
)
logger = logging.getLogger('binary_integrity_monitor')

# Default configuration
DEFAULT_CONFIG = {
    'monitor': {
        'interval': '600',  # Check interval in seconds (10 minutes)
        'quarantine_dir': '/var/quarantine/binaries',
        'database_path': '/var/lib/binary_integrity/hashes.json',
        'log_level': 'INFO',
        'max_workers': '4',  # Number of parallel workers
        'lockdown_script': '/usr/local/bin/lockdown.sh',
    },
    'binaries': {
        'critical_binaries': '/bin/bash,/usr/bin/sudo,/usr/bin/python3,/bin/sh,/usr/bin/ssh,/usr/bin/sshd,/usr/bin/su',
        'system_binaries': '/sbin/*,/bin/*,/usr/bin/*,/usr/sbin/*',
        'include_libraries': 'true',  # Also monitor critical libraries
        'critical_libraries': '/lib*/libc.so*,/lib*/libssl.so*,/lib*/libcrypto.so*',
    },
    'lockdown': {
        'enable_lockdown': 'true',
        'auto_restore_backup': 'false',
    },
    'privilege_separation': {
        'enabled': 'true',
        'run_as_user': 'binary-monitor',
        'drop_capabilities': 'true',
        'retained_capabilities': 'CAP_DAC_OVERRIDE,CAP_AUDIT_WRITE',
    },
    'isolation': {
        'enabled': 'true',
        'use_namespaces': 'true',
        'namespace_types': 'mount,uts,ipc,pid,net',
        'use_cgroups': 'true',
        'memory_limit_mb': '512',
        'cpu_limit_percent': '20',
    },
    'performance': {
        'enabled': 'true',
        'adaptive_monitoring': 'true',
        'min_interval': '300',  # Minimum 5 minutes
        'max_interval': '1800',  # Maximum 30 minutes
        'cpu_threshold': '70',   # Reduce activity if CPU usage is above this
        'memory_threshold': '75', # Reduce activity if memory usage is above this
    },
    'monitoring_scope': {
        'enabled': 'true',
        'include_patterns': '/bin/*,/sbin/*,/usr/bin/*,/usr/sbin/*',
        'exclude_patterns': '*.bak,*.tmp,/proc/*,/dev/*,/sys/*,/run/*,/tmp/*',
        'use_process_context': 'true',
    },
    'service_activation': {
        'enabled': 'true',
        'run_on_boot': 'true',
        'run_on_schedule': 'true',
        'schedule': '0 */6 * * *',  # Every 6 hours
        'run_on_events': 'true',
        'events': 'package_install,boot,user_login',
        'minimal_checks_only': 'false',
    },
}


class BinaryIntegrityMonitor:
    """
    Monitor critical binary files for unauthorized modifications.
    """
    
    def __init__(self, config_path: str = '/etc/binary_integrity_monitor.conf'):
        """Initialize the Binary Integrity Monitor"""
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Parse configuration
        self.interval = int(self.config['monitor']['interval'])
        self.quarantine_dir = Path(self.config['monitor']['quarantine_dir'])
        self.database_path = Path(self.config['monitor']['database_path'])
        self.lockdown_script = Path(self.config['monitor']['lockdown_script'])
        self.max_workers = int(self.config['monitor'].get('max_workers', '4'))
        
        # Lockdown settings
        self.enable_lockdown = self.config['lockdown'].get('enable_lockdown', 'true').lower() == 'true'
        self.auto_restore = self.config['lockdown'].get('auto_restore_backup', 'false').lower() == 'true'
        
        # Parse binary paths
        self.critical_binaries = self._expand_paths(
            self.config['binaries']['critical_binaries'].split(',')
        )
        self.system_binaries = self._expand_paths(
            self.config['binaries']['system_binaries'].split(',')
        )
        
        # Include libraries if configured
        self.include_libraries = self.config['binaries'].get('include_libraries', 'true').lower() == 'true'
        if self.include_libraries:
            self.critical_libraries = self._expand_paths(
                self.config['binaries']['critical_libraries'].split(',')
            )
        else:
            self.critical_libraries = []
            
        # Create required directories
        self.quarantine_dir.mkdir(exist_ok=True, parents=True)
        self.database_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Initialize security and performance utility modules
        self._setup_security_and_performance()
        
        # Initialize state
        self.running = True
        self.file_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.workers = []
        self.hash_database = self._load_hash_database()
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        logger.info("Binary Integrity Monitor initialized")
        logger.info(f"Monitoring interval: {self.interval} seconds")
        logger.info(f"Monitoring {len(self.critical_binaries)} critical binaries")
        if self.include_libraries:
            logger.info(f"Monitoring {len(self.critical_libraries)} critical libraries")
        logger.info(f"Using {self.max_workers} parallel workers")
        if self.enable_lockdown:
            logger.info("System lockdown enabled on detection")
            
    def _setup_security_and_performance(self):
        """Initialize security and performance utility modules."""
        try:
            # Initialize privilege separation
            privilege_config = self.config.get('privilege_separation', {})
            self.privilege_enabled = privilege_config.get('enabled', 'true').lower() == 'true'
            if self.privilege_enabled:
                self.privilege_manager = PrivilegeManager(
                    user=privilege_config.get('run_as_user', 'binary-monitor'),
                    drop_capabilities=privilege_config.get('drop_capabilities', 'true').lower() == 'true',
                    retained_capabilities=privilege_config.get('retained_capabilities', '').split(',')
                )
                logger.info(f"Privilege separation enabled, will run as {privilege_config.get('run_as_user')}")
            else:
                self.privilege_manager = None
                logger.info("Privilege separation disabled")
                
            # Initialize update-safe mode settings
            if 'updates' in self.config:
                self.update_safe_mode_enabled = self.config['updates'].get('enable_update_safe_mode', 'true').lower() == 'true'
                self.detect_package_managers = self.config['updates'].get('detect_package_managers', 'true').lower() == 'true'
                self.package_managers = self.config['updates'].get('package_managers', '').split(',')
                self.update_lock_files = self.config['updates'].get('update_lock_files', '').split(',')
                self.auto_update_database = self.config['updates'].get('auto_update_database_after_updates', 'true').lower() == 'true'
                self.verify_signatures = self.config['updates'].get('verify_package_signatures', 'true').lower() == 'true'
                self.trusted_signatures = self.config['updates'].get('trusted_signatures', '').split(',')
                logger.info(f"Update-safe mode {'enabled' if self.update_safe_mode_enabled else 'disabled'}")
                self.update_mode_active = False
            else:
                self.update_safe_mode_enabled = False
                self.detect_package_managers = False
                self.update_mode_active = False
            
            # Initialize isolation manager
            isolation_config = self.config.get('isolation', {})
            self.isolation_enabled = isolation_config.get('enabled', 'true').lower() == 'true'
            if self.isolation_enabled:
                self.isolation_manager = IsolationManager(
                    use_namespaces=isolation_config.get('use_namespaces', 'true').lower() == 'true',
                    namespace_types=isolation_config.get('namespace_types', '').split(','),
                    use_cgroups=isolation_config.get('use_cgroups', 'true').lower() == 'true',
                    memory_limit_mb=int(isolation_config.get('memory_limit_mb', '512')),
                    cpu_limit_percent=int(isolation_config.get('cpu_limit_percent', '20'))
                )
                logger.info("Process isolation enabled")
            else:
                self.isolation_manager = None
                logger.info("Process isolation disabled")
            
            # Initialize performance optimizer
            performance_config = self.config.get('performance', {})
            self.performance_enabled = performance_config.get('enabled', 'true').lower() == 'true'
            if self.performance_enabled:
                self.performance_optimizer = PerformanceOptimizer(
                    adaptive_monitoring=performance_config.get('adaptive_monitoring', 'true').lower() == 'true',
                    min_interval=int(performance_config.get('min_interval', '300')),
                    max_interval=int(performance_config.get('max_interval', '1800')),
                    cpu_threshold=int(performance_config.get('cpu_threshold', '70')),
                    memory_threshold=int(performance_config.get('memory_threshold', '75'))
                )
                logger.info("Performance optimization enabled")
            else:
                self.performance_optimizer = None
                logger.info("Performance optimization disabled")
            
            # Initialize monitoring scope
            scope_config = self.config.get('monitoring_scope', {})
            self.scope_enabled = scope_config.get('enabled', 'true').lower() == 'true'
            if self.scope_enabled:
                include_patterns = scope_config.get('include_patterns', '').split(',')
                exclude_patterns = scope_config.get('exclude_patterns', '').split(',')
                self.monitoring_scope = MonitoringScope(
                    include_patterns=include_patterns if include_patterns[0] else [],
                    exclude_patterns=exclude_patterns if exclude_patterns[0] else [],
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
                    schedule=activator_config.get('schedule', '0 */6 * * *'),
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
    
    def detect_package_manager_activity(self) -> bool:
        """Detect if any package manager is running."""
        if not self.detect_package_managers or not self.update_safe_mode_enabled:
            return False
            
        try:
            # Check for package manager processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                proc_name = proc.info['name'].lower() if proc.info.get('name') else ''
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info.get('cmdline') else ''
                
                # Check against our list of package managers
                if any(pm.lower() in proc_name for pm in self.package_managers):
                    logger.info(f"Package manager detected: {proc_name}")
                    return True
                    
                # Check for common update commands
                if any(cmd in cmdline for cmd in ['install', 'update', 'upgrade', '-U', 'dist-upgrade']):
                    if any(pm.lower() in cmdline for pm in self.package_managers):
                        logger.info(f"System update in progress: {cmdline[:50]}...")
                        return True
        except Exception as e:
            logger.warning(f"Error detecting package manager activity: {e}")
        
        return False
        
    def is_update_in_progress(self) -> bool:
        """Check if system update is in progress by examining lock files and processes."""
        if not self.update_safe_mode_enabled:
            return False
            
        try:
            # Check for update lock files
            for lock_file in self.update_lock_files:
                if os.path.exists(lock_file):
                    logger.info(f"Update lock file detected: {lock_file}")
                    return True
                    
            # Also check package manager activity
            return self.detect_package_manager_activity()
        except Exception as e:
            logger.warning(f"Error checking update status: {e}")
            
        return False
        
    def enter_update_safe_mode(self):
        """Enter a mode where binary changes from trusted sources are allowed."""
        if not self.update_safe_mode_enabled:
            return
            
        logger.info("Entering update-safe mode")
        self.update_mode_active = True
        
        # Adjust monitoring settings for update-safe mode
        self.enable_lockdown = False  # Temporarily disable lockdown
        logger.info("Lockdown temporarily disabled during system update")
        
    def exit_update_safe_mode(self):
        """Exit update-safe mode and restore normal monitoring."""
        if not self.update_safe_mode_enabled or not self.update_mode_active:
            return
            
        logger.info("Exiting update-safe mode")
        self.update_mode_active = False
        
        # Restore original settings
        self.enable_lockdown = self.config['lockdown'].get('enable_lockdown', 'true').lower() == 'true'
        logger.info("Normal monitoring settings restored")
        
        # If configured, update hash database after updates
        if self.auto_update_database:
            logger.info("Rebuilding hash database after system update")
            self._rebuild_hash_database()
            
    def _rebuild_hash_database(self):
        """Rebuild the entire hash database after system updates."""
        logger.info("Starting hash database rebuild")
        
        # Get all monitored files
        all_files = set()
        all_files.update(self.critical_binaries)
        all_files.update(self.system_binaries)
        if self.include_libraries:
            all_files.update(self.critical_libraries)
        
        # Recalculate hashes and update database
        updated_count = 0
        for file_path in all_files:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                current_info = self.calculate_file_hash(file_path)
                self.hash_database[file_path] = current_info
                updated_count += 1
        
        # Save the updated database
        self._save_hash_database()
        logger.info(f"Hash database rebuilt, updated {updated_count} files")
    
    def verify_package_signature(self, file_path: str) -> bool:
        """Verify if file changes come from a trusted package."""
        if not self.verify_signatures:
            return False
            
        try:
            # Check which package owns this file (works on Debian/Ubuntu)
            result = subprocess.run(
                ['dpkg', '-S', file_path], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                package_info = result.stdout.strip()
                package_name = package_info.split(':')[0]
                
                # Verify package integrity (Debian/Ubuntu)
                logger.info(f"Verifying package integrity for {package_name}")
                verify_result = subprocess.run(
                    ['debsums', '-c', package_name],
                    capture_output=True
                )
                
                if verify_result.returncode == 0:
                    logger.info(f"File {file_path} verified as legitimate package update")
                    return True
                else:
                    logger.warning(f"Package verification failed for {package_name}")
        except Exception as e:
            logger.warning(f"Error verifying package signature: {e}")
        
        return False
        
    def _handle_signal(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, shutting down gracefully")
        self.running = False
        
    def run(self):
        """Start monitoring binary files for changes"""
        try:
            # Apply security settings
            if self.privilege_manager:
                self.privilege_manager.drop_privileges()
                
            if self.isolation_manager:
                self.isolation_manager.apply_isolation()
                
            # Start worker threads
            for i in range(self.max_workers):
                worker = threading.Thread(
                    target=self.worker_thread,
                    args=(i,),
                    daemon=True
                )
                worker.start()
                self.workers.append(worker)
                
            # Set up performance optimizations
            if self.performance_optimizer:
                scan_interval = self.performance_optimizer.get_optimal_interval(self.interval)
            else:
                scan_interval = self.interval
                
            logger.info(f"Starting binary integrity monitoring with {len(self.workers)} workers")
            
            while self.running:
                start_time = time.time()
                
                # Check for system updates before scanning
                if self.update_safe_mode_enabled and self.is_update_in_progress():
                    if not self.update_mode_active:
                        self.enter_update_safe_mode()
                        logger.info("System update detected - entering update-safe mode")
                else:
                    if self.update_mode_active:
                        self.exit_update_safe_mode()
                        logger.info("System update completed - exiting update-safe mode")
                
                # Perform the actual scan
                modified_files = self.check_binary_integrity()
                
                if modified_files:
                    logger.warning(f"Detected {len(modified_files)} modified files")
                    
                    # In update-safe mode, verify if changes are due to legitimate updates
                    trusted_updates = []
                    untrusted_changes = []
                    
                    for file_info in modified_files:
                        file_path = file_info['path']
                        logger.warning(f"Modified file: {file_path}")
                        logger.warning(f"Old hash: {file_info['old_hash']}")
                        logger.warning(f"New hash: {file_info['new_hash']}")
                        
                        # If in update-safe mode, check if the change is legitimate
                        if self.update_mode_active and self.verify_signatures and self.verify_package_signature(file_path):
                            logger.info(f"File {file_path} verified as legitimate package update")
                            trusted_updates.append(file_info)
                        else:
                            untrusted_changes.append(file_info)
                    
                    # Update database with trusted changes
                    if trusted_updates:
                        for file_info in trusted_updates:
                            file_path = file_info['path']
                            # Update hash in database with new value
                            self.hash_database[file_path] = self.calculate_file_hash(file_path)
                        logger.info(f"Updated hash database for {len(trusted_updates)} verified package updates")
                    
                    # Handle untrusted changes
                    if untrusted_changes and self.enable_lockdown and not self.update_mode_active:
                        logger.critical(f"Detected {len(untrusted_changes)} unauthorized binary modifications")
                        self.initiate_lockdown(untrusted_changes)
                    elif untrusted_changes and self.update_mode_active:
                        logger.warning(f"Detected {len(untrusted_changes)} suspicious changes during update-safe mode")
                        logger.warning("Not initiating lockdown due to update-safe mode, but recording incident")
                else:
                    logger.info("All binary files intact")
                    
                # Save the hash database
                self._save_hash_database()
                
                # Calculate time to sleep based on performance
                elapsed = time.time() - start_time
                if self.performance_optimizer:
                    sleep_time = self.performance_optimizer.get_optimal_interval(scan_interval, elapsed)
                else:
                    sleep_time = max(1, scan_interval - elapsed)
                    
                logger.debug(f"Scan completed in {elapsed:.2f} seconds. Sleeping for {sleep_time:.2f} seconds")
                
                # Sleep until next scan
                for _ in range(int(sleep_time)):
                    if not self.running:
                        break
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            
        finally:
            # Cleanup
            logger.info("Shutting down Binary Integrity Monitor")
            self.running = False
            
            # Wait for workers to finish
            for worker in self.workers:
                worker.join(1.0)  # Wait up to 1 second
                
            # Save hash database one final time
            self._save_hash_database()
            
            # Restore privileges if needed
            if self.privilege_manager:
                self.privilege_manager.restore_privileges()
        
    def verify_critical_files(self):
        """Verify only critical binary files - minimal mode"""
        logger.info("Verifying critical binary files")
        
        # Queue only critical files
        for binary in self.critical_binaries:
            if self.scope_enabled and self.monitoring_scope:
                if not self.monitoring_scope.should_monitor(binary):
                    logger.debug(f"Skipping excluded critical binary: {binary}")
                    continue
            self.file_queue.put(binary)
        
        # Wait for all files to be processed
        self.file_queue.join()
        
        # Process results
        modified_files = []
        while not self.result_queue.empty():
            result = self.result_queue.get()
            if not result['match']:
                modified_files.append(result)
                
        # Handle modified files
        if modified_files:
            logger.critical(f"Found {len(modified_files)} modified critical binary files")
            self._handle_modified_files(modified_files)
        else:
            logger.info("No changes detected in critical binary files")
        
        return len(modified_files)
    
    def _expand_paths(self, path_patterns: List[str]) -> List[str]:
        """Expand path patterns to actual file paths"""
        expanded_paths = []
        
        for pattern in path_patterns:
            pattern = pattern.strip()
            if not pattern:
                continue
                
            # Handle wildcard patterns
            if '*' in pattern:
                import glob
                expanded = glob.glob(pattern)
                expanded_paths.extend(expanded)
            else:
                if os.path.exists(pattern):
                    expanded_paths.append(pattern)
                else:
                    logger.warning(f"Path not found: {pattern}")
        
        return sorted(set(expanded_paths))  # Remove duplicates and sort
    
    def _load_hash_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Load the hash database from disk or create a new one
        
        Returns a dictionary with file paths as keys and hash information as values
        """
        if not self.database_path.exists():
            logger.info("Hash database not found, creating a new one")
            return {}
            
        try:
            with open(self.database_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading hash database: {e}")
            # Backup the corrupt file
            backup_path = f"{self.database_path}.bak-{int(time.time())}"
            try:
                shutil.copy2(self.database_path, backup_path)
                logger.info(f"Backed up corrupt database to {backup_path}")
            except IOError as e:
                logger.error(f"Failed to create backup of hash database: {e}")
            return {}
            
    def _save_hash_database(self) -> bool:
        """Save the hash database to disk"""
        try:
            # Create a temporary file first, then rename for atomicity
            temp_path = f"{self.database_path}.tmp"
            with open(temp_path, 'w') as f:
                json.dump(self.hash_database, f, indent=2)
                
            # Make sure the file is flushed to disk
            os.fsync(f.fileno())
            
            # Rename the temporary file to the actual database file
            os.rename(temp_path, self.database_path)
            logger.debug(f"Hash database saved to {self.database_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving hash database: {e}")
            return False
            
    def calculate_file_hash(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Calculate SHA-256 hash of a file
        
        Returns a dictionary with hash value and metadata
        """
        try:
            if not os.path.isfile(file_path):
                logger.warning(f"Not a file: {file_path}")
                return None
                
            # Get file stats
            stat_info = os.stat(file_path)
            file_size = stat_info.st_size
            modify_time = stat_info.st_mtime
            
            # Calculate SHA-256 hash
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                # Read the file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
                    
            hash_value = sha256_hash.hexdigest()
            
            return {
                'path': file_path,
                'hash': hash_value,
                'size': file_size,
                'mtime': modify_time,
                'last_checked': time.time()
            }
        except (IOError, PermissionError) as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
            
    def verify_file_integrity(self, file_path: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Verify the integrity of a file by comparing current hash with stored hash
        
        Returns:
            - Integrity status (True = unchanged, False = modified)
            - Current file info
            - Previous file info (None if file is new)
        """
        current_info = self.calculate_file_hash(file_path)
        if not current_info:
            return False, None, None
            
        previous_info = self.hash_database.get(file_path)
        
        # If we have no previous hash, this is a new file
        if not previous_info:
            return True, current_info, None
            
        # Check if the hash matches the stored hash
        if current_info['hash'] == previous_info['hash']:
            # Update last checked time
            previous_info['last_checked'] = time.time()
            return True, current_info, previous_info
        
        # Hash doesn't match - file has been modified
        return False, current_info, previous_info
        
    def quarantine_file(self, file_path: str, current_info: Dict[str, Any]) -> bool:
        """
        Move a suspicious file to quarantine
        
        Returns True if successful, False otherwise
        """
        try:
            # Create quarantine path
            quarantine_path = self.quarantine_dir / f"{os.path.basename(file_path)}.{int(time.time())}"
            
            # Copy file to quarantine with original permissions
            shutil.copy2(file_path, quarantine_path)
            
            # Log quarantine action
            logger.warning(f"Quarantined modified file: {file_path} -> {quarantine_path}")
            
            # Store metadata about the quarantined file
            metadata_path = f"{quarantine_path}.json"
            with open(metadata_path, 'w') as f:
                json.dump({
                    'original_path': file_path,
                    'quarantine_time': time.time(),
                    'current_info': current_info,
                    'previous_info': self.hash_database.get(file_path, {}),
                }, f, indent=2)
                
            return True
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
            
    def initiate_lockdown(self, modified_files: List[Dict[str, Any]]) -> bool:
        """
        Initiate system lockdown due to detected modifications
        
        Returns True if lockdown was successful, False otherwise
        """
        if not self.enable_lockdown:
            logger.warning("Lockdown disabled in configuration, not initiating")
            return False
            
        logger.critical("!!! SECURITY BREACH DETECTED !!! Initiating system lockdown")
        logger.critical(f"Modified files: {', '.join(f['path'] for f in modified_files)}")
        
        # Create an incident report
        incident_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        incident_path = log_directory / f"incident-{incident_time}.json"
        
        try:
            with open(incident_path, 'w') as f:
                json.dump({
                    'timestamp': time.time(),
                    'modified_files': modified_files,
                }, f, indent=2)
            logger.info(f"Incident report saved to {incident_path}")
        except Exception as e:
            logger.error(f"Failed to create incident report: {e}")
            
        # Execute the lockdown script if it exists
        if self.lockdown_script.exists():
            try:
                logger.critical("Executing lockdown script")
                subprocess.run([str(self.lockdown_script), incident_path], check=True)
                logger.critical("Lockdown script executed successfully")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Lockdown script failed: {e}")
                return False
        else:
            logger.error(f"Lockdown script not found: {self.lockdown_script}")
            
            # Attempt basic lockdown actions even if script is missing
            try:
                # Log the event to system journal with high priority
                subprocess.run(["logger", "-p", "auth.alert", 
                               "SECURITY ALERT: Binary integrity violation detected!"], check=False)
                
                # Notify admin if configured
                if self.notify_admin and self.admin_email:
                    subject = "SECURITY ALERT: Binary Integrity Violation on " + socket.gethostname()
                    message = f"Binary integrity violations detected on {socket.gethostname()}.\n\n"
                    message += f"Time: {datetime.now()}\n\n"
                    message += "Modified files:\n"
                    for f in modified_files:
                        message += f"  {f['path']}\n"
                    message += "\nSystem has been placed in lockdown mode."
                    
                    # Use mail command to send email
                    mail_proc = subprocess.Popen(["mail", "-s", subject, self.admin_email], 
                                               stdin=subprocess.PIPE)
                    mail_proc.communicate(message.encode())
                
                return True
            except Exception as e:
                logger.error(f"Basic lockdown actions failed: {e}")
                return False
    
    def worker_thread(self, worker_id: int):
        """Worker thread to verify file integrity"""
        logger.debug(f"Worker {worker_id} started")
        
        while self.running:
            try:
                # Get a file from the queue with timeout
                try:
                    file_path = self.file_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Verify file integrity
                integrity_ok, current_info, previous_info = self.verify_file_integrity(file_path)
                
                # If the file is new, just record the hash
                if integrity_ok and not previous_info:
                    logger.debug(f"New file recorded: {file_path}")
                    self.result_queue.put(('new', file_path, current_info, None))
                # If the file has changed, report it
                elif not integrity_ok:
                    logger.warning(f"File modification detected: {file_path}")
                    self.result_queue.put(('modified', file_path, current_info, previous_info))
                # File is unchanged
                else:
                    logger.debug(f"File integrity verified: {file_path}")
                    self.result_queue.put(('verified', file_path, current_info, previous_info))
            except Exception as e:
                logger.error(f"Error in worker {worker_id}: {e}")
        
        logger.debug(f"Worker {worker_id} stopped")
                
    def check_binary_integrity(self) -> List[Dict[str, Any]]:
        """
        Check the integrity of all monitored binaries
        
        Returns a list of modified files
        """
        # Create worker threads if not already running
        if not self.workers:
            for i in range(self.max_workers):
                worker = threading.Thread(target=self.worker_thread, args=(i,))
                worker.daemon = True
                worker.start()
                self.workers.append(worker)
                
        # Combine all files to monitor
        all_files = []
        all_files.extend(self.critical_binaries)
        if self.include_libraries:
            all_files.extend(self.critical_libraries)
            
        # For system-wide check, optionally add all system binaries
        # This is intentionally separate to prioritize critical binaries
        # all_files.extend(self.system_binaries)
        
        # Make sure the list is unique
        all_files = sorted(set(all_files))
        logger.info(f"Checking integrity of {len(all_files)} files")
        
        # Add all files to the queue for workers to process
        for file_path in all_files:
            self.file_queue.put(file_path)
            
        # Wait for workers to process all files
        modified_files = []
        new_files = []
        verified_files = []
        
        # Give workers time to process all files
        files_to_process = len(all_files)
        files_processed = 0
        timeout = max(10, min(300, self.interval * 0.5))  # Between 10s and 5min
        start_time = time.time()
        
        while files_processed < files_to_process and time.time() - start_time < timeout:
            try:
                status, file_path, current_info, previous_info = self.result_queue.get(timeout=0.5)
                
                files_processed += 1
                
                if status == 'modified':
                    modified_files.append({
                        'path': file_path,
                        'current': current_info,
                        'previous': previous_info
                    })
                    # Quarantine the file immediately
                    self.quarantine_file(file_path, current_info)
                elif status == 'new':
                    new_files.append(file_path)
                    # Add to database
                    self.hash_database[file_path] = current_info
                elif status == 'verified':
                    verified_files.append(file_path)
                    # Update last_checked time
                    self.hash_database[file_path]['last_checked'] = current_info['last_checked']
                
            except queue.Empty:
                # No results ready yet
                time.sleep(0.1)
                
        # Log summary
        logger.info(f"Processed {files_processed} of {files_to_process} files")
        logger.info(f"  - {len(verified_files)} files verified")
        logger.info(f"  - {len(new_files)} new files recorded")
        logger.info(f"  - {len(modified_files)} modified files detected")
        
        # Save the updated hash database
        self._save_hash_database()
        
        # If any files were modified, initiate lockdown
        if modified_files:
            self.initiate_lockdown(modified_files)
            
        return modified_files
        
    def run(self):
        """Main monitoring loop"""
        logger.info("Starting Binary Integrity Monitor")
        
        try:
            # Initial hash calculation for all binaries
            if not self.hash_database:
                logger.info("Performing initial hash calculation for all binaries")
                self.check_binary_integrity()
                logger.info(f"Initial hash database created with {len(self.hash_database)} entries")
                self._save_hash_database()
            
            # Main monitoring loop
            while self.running:
                start_time = time.time()
                
                # Check binary integrity
                modified_files = self.check_binary_integrity()
                
                # Calculate how long the check took
                elapsed = time.time() - start_time
                
                # If the check took longer than the interval, log a warning
                if elapsed > self.interval:
                    logger.warning(f"Integrity check took {elapsed:.1f}s which exceeds the monitoring interval of {self.interval}s")
                    # Sleep for a short time to avoid CPU hogging
                    time.sleep(1)
                else:
                    # Sleep for the remaining time in the interval
                    time.sleep(max(0.1, self.interval - elapsed))
                    
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
        finally:
            # Clean up and exit
            self._save_hash_database()
            logger.info("Binary Integrity Monitor shutting down")


def main():
    """Main entry point"""
    monitor = BinaryIntegrityMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
