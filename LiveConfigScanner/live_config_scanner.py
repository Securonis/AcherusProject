#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Live Configuration Integrity Scanner
-----------------------------------
A security tool that monitors critical configuration files for changes
to detect silent privilege escalation and unauthorized system modifications.

License: GNU General Public License v3.0
Author: root0emir
"""

import os
import sys
import time
import json
import hashlib
import difflib
import logging
import subprocess
import configparser
import signal
import socket
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional
import shutil

# Import utility modules
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ''))
from utils.privilege_manager import PrivilegeManager
from utils.isolation_manager import IsolationManager
from utils.performance_optimizer import PerformanceOptimizer
from utils.monitoring_scope import MonitoringScope
from utils.service_activator import ServiceActivator

# Configure logging
log_dir = Path("/var/log/live_config_scanner")
log_dir.mkdir(exist_ok=True, parents=True)

log_file = log_dir / "live_config_scanner.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LiveConfigScanner")

# Default configuration
DEFAULT_CONFIG = {
    'monitor': {
        'interval': '300',  # 5 minutes
        'snapshot_dir': '/var/lib/live_config_scanner/snapshots',
        'report_dir': '/var/log/live_config_scanner/reports',
        'log_level': 'INFO',
        'pidfile': '/var/run/live_config_scanner.pid'
    },
    'files': {
        'track_passwd': 'true',
        'track_shadow': 'true',
        'track_sudoers': 'true',
        'track_hosts': 'true',
        'track_sshd_config': 'true',
        'additional_files': '/etc/group,/etc/crontab,/etc/fstab'  # Comma separated list
    },
    'detection': {
        'track_permissions': 'true',
        'track_ownership': 'true',
        'track_content': 'true'
    },
    'action': {
        'exec_script': '',  # Custom script to run when changes detected
    },
    'whitelist': {
        'file_patterns': '',  # Comma separated regex patterns to ignore
        'content_patterns': ''  # Comma separated regex patterns to ignore in content
    },
    # Security and performance settings
    'privilege': {
        'enabled': 'true',
        'user': 'nobody',
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
        'min_interval': '60',  # Seconds
        'max_interval': '600',  # Seconds
        'cpu_threshold': '80',  # Percentage
        'memory_threshold': '80',  # Percentage
        'sample_window': '5'  # Number of samples to average
    },
    'monitoring_scope': {
        'enabled': 'true',
        'include_paths': '/etc,/usr/bin,/usr/sbin,/usr/local/bin,/usr/local/sbin',
        'exclude_paths': '/var/log,/tmp,/proc,/sys',
        'include_users': 'root,daemon',
        'exclude_users': 'nobody,www-data',
        'include_patterns': '',
        'exclude_patterns': '\.bak$,\.tmp$'
    },
    'activation': {
        'enabled': 'true',
        'mode': 'auto',  # 'always', 'auto', 'scheduled', 'triggered'
        'schedule': '0 * * * *',  # Hourly in cron format
        'active_period': '60',  # Seconds to stay active when triggered
        'trigger_on': 'file_change,system_load',  # Events that trigger activation
        'threshold_cpu': '70',  # CPU usage percentage that triggers activation
        'threshold_memory': '70'  # Memory usage percentage that triggers activation
    }
}


class ConfigFile:
    """Class representing a tracked configuration file"""
    
    def __init__(self, path: str):
        """Initialize with file path"""
        self.path = path
        self.exists = os.path.isfile(path)
        self.size = 0
        self.permissions = ""
        self.owner = ""
        self.group = ""
        self.modified_time = 0
        self.content = ""
        self.hash = ""
        self.snapshot_time = ""
        
        if self.exists:
            self._collect_metadata()
            self._read_content()
            self._calculate_hash()
            self.snapshot_time = datetime.now().isoformat()
            
    def _collect_metadata(self):
        """Collect file metadata"""
        stat = os.stat(self.path)
        self.size = stat.st_size
        self.permissions = oct(stat.st_mode)[-4:]  # Last 4 digits of octal representation
        self.owner = str(stat.st_uid)
        self.group = str(stat.st_gid)
        self.modified_time = stat.st_mtime
        
    def _read_content(self):
        """Read file content safely"""
        try:
            with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
                self.content = f.read()
        except Exception as e:
            logger.error(f"Failed to read {self.path}: {e}")
            self.content = ""
            
    def _calculate_hash(self):
        """Calculate SHA-256 hash of content"""
        if self.content:
            self.hash = hashlib.sha256(self.content.encode('utf-8')).hexdigest()
        else:
            self.hash = ""
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'path': self.path,
            'exists': self.exists,
            'size': self.size,
            'permissions': self.permissions,
            'owner': self.owner,
            'group': self.group,
            'modified_time': self.modified_time,
            'content': self.content,
            'hash': self.hash,
            'snapshot_time': self.snapshot_time
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigFile':
        """Create ConfigFile from dictionary"""
        config_file = cls(data['path'])
        config_file.exists = data['exists']
        config_file.size = data['size']
        config_file.permissions = data['permissions']
        config_file.owner = data['owner']
        config_file.group = data['group']
        config_file.modified_time = data['modified_time']
        config_file.content = data['content']
        config_file.hash = data['hash']
        config_file.snapshot_time = data['snapshot_time']
        return config_file


class Change:
    """Class representing a detected change"""
    
    def __init__(self, file_path: str, change_type: str, details: Dict[str, Any]):
        """Initialize change object"""
        self.file_path = file_path
        self.change_type = change_type  # 'permission', 'ownership', 'content', 'created', 'deleted'
        self.details = details
        self.timestamp = datetime.now().isoformat()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'file_path': self.file_path,
            'change_type': self.change_type,
            'details': self.details,
            'timestamp': self.timestamp
        }


class LiveConfigScanner:
    """Main scanner class for Live Configuration Integrity Scanner"""
    
    def __init__(self, config: Dict[str, Dict[str, str]]):
        """Initialize with configuration"""
        self.config = config
        
        # Get tracking settings
        self.track_permissions = config['detection']['track_permissions'].lower() == 'true'
        self.track_ownership = config['detection']['track_ownership'].lower() == 'true'
        self.track_content = config['detection']['track_content'].lower() == 'true'
        
        # Get action settings
        self.notify_admin = config['action']['notify_admin'].lower() == 'true'
        self.admin_email = config['action']['admin_email']
        self.restore_backups = config['action']['restore_backups'].lower() == 'true'
        self.exec_script = config['action']['exec_script']
        
        # Create directories
        self.snapshot_dir = Path(config['monitor']['snapshot_dir'])
        self.report_dir = Path(config['monitor']['report_dir'])
        
        self.snapshot_dir.mkdir(exist_ok=True, parents=True)
        self.report_dir.mkdir(exist_ok=True, parents=True)
        
        # Build list of tracked files
        self.tracked_files = self._get_tracked_files()
        
        # Load whitelist patterns
        self.file_patterns = [p.strip() for p in config['whitelist']['file_patterns'].split(',') if p.strip()]
        self.content_patterns = [p.strip() for p in config['whitelist']['content_patterns'].split(',') if p.strip()]
    
    def _get_tracked_files(self) -> List[str]:
        """Get list of files to track based on configuration"""
        tracked_files = []
        
        # Add standard files if enabled
        if self.config['files']['track_passwd'].lower() == 'true':
            tracked_files.append('/etc/passwd')
            
        if self.config['files']['track_shadow'].lower() == 'true':
            tracked_files.append('/etc/shadow')
            
        if self.config['files']['track_sudoers'].lower() == 'true':
            tracked_files.append('/etc/sudoers')
            
        if self.config['files']['track_hosts'].lower() == 'true':
            tracked_files.append('/etc/hosts')
            
        if self.config['files']['track_sshd_config'].lower() == 'true':
            tracked_files.append('/etc/ssh/sshd_config')
            
        # Add additional files
        additional = self.config['files']['additional_files']
        if additional:
            for file_path in additional.split(','):
                file_path = file_path.strip()
                if file_path and os.path.isfile(file_path):
                    tracked_files.append(file_path)
                    
        return tracked_files
        
    def _is_whitelisted(self, file_path: str) -> bool:
        """Check if a file path matches any whitelist pattern"""
        import re
        return any(re.search(pattern, file_path) for pattern in self.file_patterns)
        
    def _content_contains_whitelist(self, content: str) -> bool:
        """Check if content contains any whitelisted patterns"""
        import re
        return any(re.search(pattern, content) for pattern in self.content_patterns)
        
    def take_snapshot(self) -> Dict[str, ConfigFile]:
        """Take snapshot of all tracked files"""
        snapshots = {}
        
        for file_path in self.tracked_files:
            if not self._is_whitelisted(file_path):
                logger.debug(f"Taking snapshot of {file_path}")
                config_file = ConfigFile(file_path)
                snapshots[file_path] = config_file
                
        return snapshots
        
    def save_snapshot(self, snapshots: Dict[str, ConfigFile], timestamp: str = None) -> str:
        """Save snapshots to file"""
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            
        snapshot_file = self.snapshot_dir / f"snapshot-{timestamp}.json"
        
        serializable = {
            'timestamp': timestamp,
            'files': {path: config_file.to_dict() for path, config_file in snapshots.items()}
        }
        
        with open(snapshot_file, 'w') as f:
            json.dump(serializable, f, indent=2)
            
        logger.info(f"Saved snapshot to {snapshot_file}")
        return str(snapshot_file)
        
    def load_snapshot(self, snapshot_file: str = None) -> Dict[str, ConfigFile]:
        """Load snapshot from file, or most recent if not specified"""
        if snapshot_file is None:
            # Find most recent snapshot
            snapshot_files = list(self.snapshot_dir.glob("snapshot-*.json"))
            if not snapshot_files:
                logger.warning("No previous snapshots found")
                return {}
                
            snapshot_file = str(sorted(snapshot_files, key=lambda f: f.stat().st_mtime, reverse=True)[0])
            
        with open(snapshot_file, 'r') as f:
            data = json.load(f)
            
        snapshots = {}
        for path, file_data in data['files'].items():
            snapshots[path] = ConfigFile.from_dict(file_data)
            
        logger.info(f"Loaded snapshot from {snapshot_file}")
        return snapshots
        
    def compare_snapshots(self, old_snapshots: Dict[str, ConfigFile], 
                        new_snapshots: Dict[str, ConfigFile]) -> List[Change]:
        """Compare two snapshots and return list of changes"""
        changes = []
        
        # Check for files in both snapshots
        common_files = set(old_snapshots.keys()) & set(new_snapshots.keys())
        for file_path in common_files:
            old_file = old_snapshots[file_path]
            new_file = new_snapshots[file_path]
            
            # Check permissions if enabled
            if self.track_permissions and old_file.permissions != new_file.permissions:
                changes.append(Change(
                    file_path, 'permission', {
                        'old': old_file.permissions,
                        'new': new_file.permissions
                    }
                ))
                
            # Check ownership if enabled
            if self.track_ownership and (old_file.owner != new_file.owner or old_file.group != new_file.group):
                changes.append(Change(
                    file_path, 'ownership', {
                        'old_owner': old_file.owner,
                        'new_owner': new_file.owner,
                        'old_group': old_file.group,
                        'new_group': new_file.group
                    }
                ))
                
            # Check content if enabled
            if self.track_content and old_file.hash != new_file.hash:
                # Generate diff
                old_lines = old_file.content.splitlines()
                new_lines = new_file.content.splitlines()
                diff = list(difflib.unified_diff(
                    old_lines, new_lines, 
                    fromfile=f"{file_path}.old",
                    tofile=f"{file_path}.new",
                    lineterm=''
                ))
                
                # Skip if content matches whitelist patterns
                if not self._content_contains_whitelist(new_file.content):
                    changes.append(Change(
                        file_path, 'content', {
                            'old_hash': old_file.hash,
                            'new_hash': new_file.hash,
                            'diff': diff
                        }
                    ))
        
        # Check for deleted files
        deleted_files = set(old_snapshots.keys()) - set(new_snapshots.keys())
        for file_path in deleted_files:
            changes.append(Change(
                file_path, 'deleted', {
                    'old_snapshot': old_snapshots[file_path].snapshot_time
                }
            ))
        
        # Check for created files
        created_files = set(new_snapshots.keys()) - set(old_snapshots.keys())
        for file_path in created_files:
            changes.append(Change(
                file_path, 'created', {
                    'new_snapshot': new_snapshots[file_path].snapshot_time,
                    'permissions': new_snapshots[file_path].permissions,
                    'owner': new_snapshots[file_path].owner,
                    'group': new_snapshots[file_path].group
                }
            ))
            
        return changes
        
    def generate_report(self, changes: List[Change]) -> str:
        """Generate a report of changes"""
        if not changes:
            logger.info("No changes detected")
            return ""
            
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        report_file = self.report_dir / f"report-{timestamp}.json"
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'changes': [change.to_dict() for change in changes],
            'summary': {
                'total_changes': len(changes),
                'by_type': {
                    'permission': len([c for c in changes if c.change_type == 'permission']),
                    'ownership': len([c for c in changes if c.change_type == 'ownership']),
                    'content': len([c for c in changes if c.change_type == 'content']),
                    'created': len([c for c in changes if c.change_type == 'created']),
                    'deleted': len([c for c in changes if c.change_type == 'deleted'])
                }
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Generated report: {report_file}")
        return str(report_file)
        
    def notify_admin(self, report_file: str, changes: List[Change]):
        """Send email notification to admin about changes"""
        if not self.notify_admin or not self.admin_email:
            return
            
        if not changes:
            return
            
        # Prepare email content
        subject = f"[SECURITY] Configuration file changes detected on {socket.gethostname()}"
        
        by_type = {
            'permission': [c for c in changes if c.change_type == 'permission'],
            'ownership': [c for c in changes if c.change_type == 'ownership'],
            'content': [c for c in changes if c.change_type == 'content'],
            'created': [c for c in changes if c.change_type == 'created'],
            'deleted': [c for c in changes if c.change_type == 'deleted']
        }
        
        body = f"""Live Configuration Integrity Scanner has detected {len(changes)} changes:
        
- Permission changes: {len(by_type['permission'])}
- Ownership changes: {len(by_type['ownership'])}
- Content changes: {len(by_type['content'])}
- Created files: {len(by_type['created'])}
- Deleted files: {len(by_type['deleted'])}

See the full report at: {report_file}

"""
        
        # Add details of some changes
        for change_type, changes_list in by_type.items():
            if changes_list:
                body += f"\n{change_type.title()} changes:\n"
                for i, change in enumerate(changes_list[:3]):  # Show up to 3 changes of each type
                    if change_type == 'permission':
                        body += f"- {change.file_path}: {change.details['old']} -> {change.details['new']}\n"
                    elif change_type == 'ownership':
                        body += f"- {change.file_path}: {change.details['old_owner']}:{change.details['old_group']} -> {change.details['new_owner']}:{change.details['new_group']}\n"
                    elif change_type == 'content':
                        body += f"- {change.file_path}: Content modified\n"
                        # Add a few lines of diff if available
                        if 'diff' in change.details and change.details['diff']:
                            body += "  Partial diff:\n"
                            for diff_line in change.details['diff'][:10]:  # First 10 lines of diff
                                body += f"    {diff_line}\n"
                            if len(change.details['diff']) > 10:
                                body += "    ...\n"
                    elif change_type == 'created':
                        body += f"- {change.file_path}: File created with permissions {change.details['permissions']}\n"
                    elif change_type == 'deleted':
                        body += f"- {change.file_path}: File deleted\n"
                
                if len(changes_list) > 3:
                    body += f"  (and {len(changes_list) - 3} more...)\n"
                    
        # Try to send email
        try:
            p = subprocess.Popen(
                ['mail', '-s', subject, self.admin_email],
                stdin=subprocess.PIPE
            )
            p.communicate(body.encode())
            logger.info(f"Notification sent to {self.admin_email}")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            
    def restore_from_snapshot(self, snapshot_file: str, paths: List[str] = None):
        """Restore files from snapshot"""
        if not self.restore_backups:
            logger.warning("Backup restoration is disabled in configuration")
            return False
            
        logger.warning(f"Attempting to restore files from {snapshot_file}")
        
        try:
            snapshots = self.load_snapshot(snapshot_file)
            
            if not snapshots:
                logger.error("Failed to load snapshot")
                return False
                
            # Filter by paths if specified
            if paths:
                snapshots = {path: snapshots[path] for path in paths if path in snapshots}
                
            # Restore each file
            for path, config_file in snapshots.items():
                # First make a backup of the current file
                if os.path.exists(path):
                    backup_path = f"{path}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    logger.info(f"Backing up current {path} to {backup_path}")
                    shutil.copy2(path, backup_path)
                    
                # Write snapshot content to file
                logger.info(f"Restoring {path} from snapshot")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(config_file.content)
                    
                # Restore permissions if possible
                try:
                    os.chmod(path, int(config_file.permissions, 8))
                except Exception as e:
                    logger.error(f"Failed to restore permissions for {path}: {e}")
                    
                # Attempt to restore ownership if running as root
                if os.geteuid() == 0:
                    try:
                        os.chown(path, int(config_file.owner), int(config_file.group))
                    except Exception as e:
                        logger.error(f"Failed to restore ownership for {path}: {e}")
                        
            logger.info(f"Successfully restored {len(snapshots)} files from snapshot")
            return True
        except Exception as e:
            logger.error(f"Failed to restore from snapshot: {e}")
            return False
            
    def execute_response_script(self, report_file: str):
        """Execute configured response script when changes detected"""
        if not self.exec_script or not os.path.isfile(self.exec_script):
            return
            
        logger.info(f"Executing response script: {self.exec_script}")
        
        try:
            subprocess.run(
                [self.exec_script, report_file],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Response script executed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Response script failed with exit code {e.returncode}: {e.stderr}")
        except Exception as e:
            logger.error(f"Failed to execute response script: {e}")

class LiveConfigScannerService:
    """Service wrapper for LiveConfigScanner"""
    
    def __init__(self, config_file=None):
        """Initialize the service"""
        self.running = True
        self.config = self._load_config(config_file)
        
        # Configure logging level based on config
        log_level = getattr(logging, self.config['monitor']['log_level'].upper(), logging.INFO)
        logger.setLevel(log_level)
        
        # Initialize security and performance modules
        self._setup_security_and_performance()
        
        # Create scanner instance
        self.scanner = LiveConfigScanner(self.config)
        
        # Write PID file
        pid_file = self.config['monitor']['pidfile']
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        logger.info(f"PID written to {pid_file}")
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        
        # Track if this is the first run (no previous snapshot)
        self._first_run = True
        
    def _setup_security_and_performance(self):
        """Setup security and performance modules"""
        service_name = "live_config_scanner"
        
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
        logger.info("Live Configuration Integrity Scanner service started")
        
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
                    self.perf_optimizer.start_operation("scan_cycle")
                
                # Perform scan if service is active or no activation policy is configured
                if is_active:
                    logger.debug("Starting integrity scan (full capabilities)")
                    
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
                    logger.debug("Starting minimal integrity scan (reduced capabilities)")
                    self._perform_minimal_scan()
                
                # End performance monitoring
                scan_time = 0
                if self.perf_optimizer:
                    self.perf_optimizer.end_operation("scan_cycle")
                    scan_time = self.perf_optimizer.get_last_operation_duration("scan_cycle")
                    logger.debug(f"Scan completed in {scan_time:.2f}s")
                    
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
                
                # Wait for next scan using 1-second increments to allow clean shutdown
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(10)  # Shorter wait on error
                
    def _perform_full_scan(self):
        """Perform a full scan of monitored configuration files"""
        # Take current snapshot
        current_snapshots = self.scanner.take_snapshot()
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        
        # Save current snapshot
        self.scanner.save_snapshot(current_snapshots, timestamp)
        
        # Compare with previous snapshot if not first run
        if not self._first_run:
            # Load previous snapshot
            previous_snapshots = self.scanner.load_snapshot()
            
            # Compare snapshots
            changes = self.scanner.compare_snapshots(previous_snapshots, current_snapshots)
            
            # If changes detected
            if changes:
                logger.warning(f"Detected {len(changes)} changes in configuration files")
                
                # Update service activator if configured
                if self.service_activator:
                    self.service_activator.update_monitored_value('file_changes', len(changes))
                    self.service_activator.trigger("file_change")
                
                # Generate report
                report_file = self.scanner.generate_report(changes)
                
                # Execute response script if configured
                self.scanner.execute_response_script(report_file)
        else:
            logger.info("First run completed, initial snapshot taken")
            self._first_run = False
            
    def _perform_minimal_scan(self):
        """Perform a minimal scan when the service is inactive"""
        # Just check critical files that might trigger service activation
        critical_files = ["/etc/passwd", "/etc/sudoers"]
        changes_detected = False
        
        # Quick check for critical files
        try:
            for file_path in critical_files:
                if os.path.exists(file_path):
                    modified_time = os.path.getmtime(file_path)
                    
                    # Check if file has been modified recently
                    if hasattr(self, '_last_checked_times') and file_path in self._last_checked_times:
                        if modified_time > self._last_checked_times[file_path]:
                            logger.info(f"Critical file {file_path} has been modified")
                            changes_detected = True
                    
                    # Update last checked time
                    if not hasattr(self, '_last_checked_times'):
                        self._last_checked_times = {}
                    self._last_checked_times[file_path] = modified_time
            
            # Trigger service activation if changes detected
            if changes_detected and self.service_activator:
                logger.info("Changes detected in critical files during minimal scan")
                self.service_activator.update_monitored_value('file_changes', 1)
                self.service_activator.trigger("file_change")
        except Exception as e:
            logger.error(f"Error in minimal scan: {str(e)}")
        
        # Cleanup resources when shutting down
        self._cleanup_resources()
        
    def _cleanup_resources(self):
        """Clean up all resources during shutdown"""
        logger.info("Live Configuration Integrity Scanner service shutting down")
        
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
    # Parse command line arguments
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = "/etc/live_config_scanner.conf"
        
    # Run service
    service = LiveConfigScannerService(config_file)
    service.run()


if __name__ == "__main__":
    main()
