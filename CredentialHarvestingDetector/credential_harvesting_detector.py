#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Credential Harvesting Detector
-----------------------------------
A security tool that monitors process command lines and optionally memory
to detect credential exposure and harvesting attempts.

Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import sys
import time
import json
import re
import logging
import subprocess
import configparser
import signal
import socket
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional

# Add project root to system path for module imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import security and performance modules
try:
    from utils.privilege_manager import PrivilegeManager
    from utils.isolation_manager import IsolationManager
    from utils.performance_optimizer import PerformanceOptimizer
    from utils.monitoring_scope import MonitoringScope
    from utils.service_activator import ServiceActivator
except ImportError:
    print("Error: Acherus Project utility modules not found in utils/ directory")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("Error: psutil module not found. Please install it using 'pip install psutil'")
    sys.exit(1)

# Configure logging
log_dir = Path("/var/log/credential_harvesting_detector")
log_dir.mkdir(exist_ok=True, parents=True)

log_file = log_dir / "credential_harvesting_detector.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CredentialHarvestingDetector")

# Default configuration
DEFAULT_CONFIG = {
    'monitor': {
        'interval': '60',  # 1 minute
        'report_dir': '/var/log/credential_harvesting_detector/reports',
        'log_level': 'INFO',
        'pidfile': '/var/run/credential_harvesting_detector.pid'
    },
    'detection': {
        'scan_cmdline': 'true',
        'scan_env_vars': 'true',
        'scan_memory': 'false',  # Memory scanning is resource-intensive and disabled by default
        'memory_scan_threshold': '50',  # Process size threshold in MB for memory scan
        'check_for_basic_auth': 'true',
        'check_for_password_params': 'true',
        'check_for_url_auth': 'true',
        'check_for_api_keys': 'true',
        'check_for_tokens': 'true',
        'check_for_aws_keys': 'true',
        'check_for_curl_wget': 'true',
        'custom_patterns': ''  # Comma-separated regex patterns for custom credential formats
    },
    'action': {
        'terminate_processes': 'false',  # Be cautious with this setting!
        'exec_script': '',  # Custom script to run when credential exposure detected
    },
    'whitelist': {
        'users': 'root,nobody',  # Users to ignore
        'processes': 'firefox,chrome,chromium,ssh,sshd',  # Process names to ignore
        'patterns': '',  # Regex patterns to whitelist
        'paths': '/usr/bin/git,/usr/bin/ssh'  # Full paths to whitelist
    },
    'privilege': {
        'enabled': 'true',
        'user': 'acherus',
        'group': 'acherus',
        'drop_privileges': 'true',
        'restore_privileges_for_actions': 'true'
    },
    'isolation': {
        'enabled': 'true',
        'enable_namespaces': 'true',
        'enable_cgroups': 'true',
        'cpu_limit': '10',  # % of CPU time
        'memory_limit_mb': '100'
    },
    'performance': {
        'enable_optimization': 'true',
        'cpu_threshold': '70',  # % CPU usage
        'memory_threshold': '200',  # MB
        'adaptive_monitoring': 'true',
        'min_interval': '30',  # Minimum monitoring interval (seconds)
        'max_interval': '300'   # Maximum monitoring interval (seconds)
    },
    'monitoring_scope': {
        'paths': {
            'include': [],
            'exclude': []
        },
        'processes': {
            'include': [],
            'exclude': []
        }
    },
    'activation': {
        'enabled': 'true',
        'mode': 'threshold',  # 'manual', 'scheduled', 'event', 'threshold'
        'active_duration': '3600',  # 1 hour
        'threshold_triggers': {
            'cpu_usage': {
                'enabled': 'true',
                'value_name': 'system_cpu',
                'threshold': '80',
                'operator': '>'
            },
            'suspicious_process': {
                'enabled': 'true',
                'value_name': 'suspicious_processes',
                'threshold': '1',
                'operator': '>='
            }
        }
    }
}

# Regex patterns for credential detection
CREDENTIAL_PATTERNS = {
    # Basic auth pattern (user:pass format)
    'basic_auth': [
        r'--user[=\s]([^:]+):([^\s]+)',
        r'-u[=\s]([^:]+):([^\s]+)',
    ],
    
    # Password parameters
    'password_param': [
        r'-p\s*(\S+)',
        r'--password[=\s](\S+)',
        r'password[=\s]([^\s&;]+)',
        r'pwd[=\s]([^\s&;]+)',
        r'passwd[=\s]([^\s&;]+)',
    ],
    
    # URL auth embedded credentials
    'url_auth': [
        r'https?://([^:]+):([^@]+)@',
    ],
    
    # API keys
    'api_key': [
        r'api[-_]?key[=\s]([^\s&;]+)',
        r'apikey[=\s]([^\s&;]+)',
        r'key[=\s]([A-Za-z0-9_\-]{16,64})',
    ],
    
    # Bearer tokens
    'token': [
        r'bearer\s+([A-Za-z0-9_\-\.]+)',
        r'token[=\s]([^\s&;]+)',
        r'access_token[=\s]([^\s&;]+)',
        r'auth[=\s]([A-Za-z0-9_\-\.]+)',
    ],
    
    # AWS keys
    'aws_key': [
        r'(AKIA[0-9A-Z]{16})',
        r'(aws_access_key_id|aws_secret_access_key)[=\s]([^\s]+)',
    ],
    
    # Curl/wget auth
    'curl_wget': [
        r'curl\s+.*-H\s*[\'"]Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)[\'"]',
        r'curl\s+.*-H\s*[\'"]Authorization:\s*Bearer\s+([^\'"]+)[\'"]',
        r'wget\s+.*--header=[\'"]Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)[\'"]',
        r'wget\s+.*--header=[\'"]Authorization:\s*Bearer\s+([^\'"]+)[\'"]',
    ],
}

class CredentialFinding:
    """Class representing a credential exposure finding"""
    
    def __init__(self, pid: int, process_name: str, username: str, 
                 cmdline: List[str], finding_type: str, matched_pattern: str, 
                 matched_value: str, raw_command: str = ""):
        """Initialize credential finding"""
        self.pid = pid
        self.process_name = process_name
        self.username = username
        self.cmdline = cmdline
        self.finding_type = finding_type
        self.matched_pattern = matched_pattern
        self.matched_value = self._sanitize_credential(matched_value)
        self.raw_command = raw_command
        self.timestamp = datetime.now().isoformat()
        
    def _sanitize_credential(self, value: str) -> str:
        """Sanitize credential for logging by partially masking it"""
        if not value or len(value) < 4:
            return "***"
            
        # Mask the middle part of the credential
        visible_chars = min(2, len(value) // 4)
        return value[:visible_chars] + '*' * (len(value) - 2 * visible_chars) + value[-visible_chars:]
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'pid': self.pid,
            'process_name': self.process_name,
            'username': self.username,
            'cmdline': ' '.join(self.cmdline) if self.cmdline else "",
            'finding_type': self.finding_type,
            'matched_pattern': self.matched_pattern,
            'matched_value': self.matched_value,
            'timestamp': self.timestamp
        }
        
    def get_severity(self) -> str:
        """Determine the severity of the finding"""
        # Higher severity for certain credential types
        high_severity_types = ['aws_key', 'api_key', 'token']
        if self.finding_type in high_severity_types:
            return "HIGH"
        return "MEDIUM"
        
    def __str__(self) -> str:
        """String representation of finding"""
        return (f"Credential exposure in {self.process_name} (PID {self.pid}) "
                f"run by {self.username}: {self.finding_type} pattern matched")


    """Main detector class for credential harvesting detection"""
    
    def __init__(self, config: Dict[str, Dict[str, str]]):
        """Initialize with configuration"""
        self.config = config
        
        # Initialize with no monitoring scope (will be set by service if available)
        self.monitoring_scope = None
        
        # Get detection settings
        self.scan_cmdline = config['detection']['scan_cmdline'].lower() == 'true'
        self.scan_env_vars = config['detection']['scan_env_vars'].lower() == 'true'
        self.scan_memory = config['detection']['scan_memory'].lower() == 'true'
        self.memory_scan_threshold = int(config['detection']['memory_scan_threshold'])
        
        # ... rest of the code remains the same ...
        # Determine which patterns to check
        self.active_pattern_types = []
        for pattern_type in CREDENTIAL_PATTERNS.keys():
            if config['detection'].get(f'check_for_{pattern_type}', '').lower() == 'true':
                self.active_pattern_types.append(pattern_type)
        
        # Compile regex patterns
        self.patterns = self._compile_patterns()
        
        # Load whitelists
        self.whitelisted_users = set(u.strip() for u in config['whitelist']['users'].split(',') if u.strip())
        self.whitelisted_processes = set(p.strip() for p in config['whitelist']['processes'].split(',') if p.strip())
        self.whitelisted_paths = set(p.strip() for p in config['whitelist']['paths'].split(',') if p.strip())
        
        # Compile whitelist patterns
        self.whitelist_patterns = []
        for pattern in config['whitelist']['patterns'].split(','):
            if pattern.strip():
                try:
                    self.whitelist_patterns.append(re.compile(pattern.strip(), re.IGNORECASE))
                except re.error:
                    logger.error(f"Invalid whitelist regex pattern: {pattern}")
        
        # Get action settings
        self.terminate_processes = config['action']['terminate_processes'].lower() == 'true'
        self.exec_script = config['action']['exec_script']
        
        # Create report directory
        self.report_dir = Path(config['monitor']['report_dir'])
        self.report_dir.mkdir(exist_ok=True, parents=True)
        
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for credential detection"""
        compiled_patterns = {}
        
        # Compile built-in patterns
        for pattern_type, patterns in CREDENTIAL_PATTERNS.items():
            if pattern_type in self.active_pattern_types:
                compiled_patterns[pattern_type] = [
                    re.compile(pattern, re.IGNORECASE) for pattern in patterns
                ]
        
        # Add custom patterns if defined
        custom_patterns = self.config['detection']['custom_patterns']
        if custom_patterns:
            compiled_patterns['custom'] = []
            for pattern in custom_patterns.split(','):
                if pattern.strip():
                    try:
                        compiled_patterns['custom'].append(re.compile(pattern.strip(), re.IGNORECASE))
                    except re.error:
                        logger.error(f"Invalid custom regex pattern: {pattern}")
        
        return compiled_patterns
        
    def _is_whitelisted(self, proc: psutil.Process) -> bool:
        """Check if a process is whitelisted"""
        try:
            # Check by username
            if proc.username() in self.whitelisted_users:
                return True
                
            # Check by process name
            if proc.name() in self.whitelisted_processes:
                return True
                
            # Check by full path
            try:
                if proc.exe() in self.whitelisted_paths:
                    return True
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
            # Check command line against whitelist patterns
            if proc.cmdline():
                cmdline = ' '.join(proc.cmdline())
                for pattern in self.whitelist_patterns:
                    if pattern.search(cmdline):
                        return True
            
            return False
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return True  # Skip processes we can't access
    
    def _analyze_cmdline(self, pid: int, name: str, username: str, cmdline: List[str]) -> List[CredentialFinding]:
        """Analyze command line for credentials"""
        findings = []
        if not cmdline:
            return findings
            
        # Join command line arguments
        cmd_str = ' '.join(cmdline)
        
        # Check against all active patterns
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = pattern.findall(cmd_str)
                if matches:
                    # Different patterns might return tuples or strings
                    for match in matches:
                        # If match is a tuple (groups), take the most likely credential part
                        if isinstance(match, tuple):
                            for group in match:
                                if group and len(group) >= 4:  # Minimum credential length
                                    findings.append(
                                        CredentialFinding(
                                            pid=pid,
                                            process_name=name,
                                            username=username,
                                            cmdline=cmdline,
                                            finding_type=pattern_type,
                                            matched_pattern=pattern.pattern,
                                            matched_value=group,
                                            raw_command=cmd_str
                                        )
                                    )
                                    break
                        else:
                            findings.append(
                                CredentialFinding(
                                    pid=pid,
                                    process_name=name,
                                    username=username,
                                    cmdline=cmdline,
                                    finding_type=pattern_type,
                                    matched_pattern=pattern.pattern,
                                    matched_value=match,
                                    raw_command=cmd_str
                                )
                            )
                            
        return findings
        
    def _analyze_env_vars(self, pid: int, name: str, username: str) -> List[CredentialFinding]:
        """Analyze environment variables for credentials"""
        findings = []
        
        # Skip if not enabled
        if not self.scan_env_vars:
            return findings
            
        try:
            # Get process environment variables
            proc = psutil.Process(pid)
            env = proc.environ()
            
            # Look for sensitive environment variables
            sensitive_vars = ['PASSWORD', 'PASSWD', 'SECRET', 'TOKEN', 'API_KEY', 'APIKEY',
                             'ACCESS_KEY', 'AWS_SECRET', 'CREDENTIALS']
            
            for var, value in env.items():
                # Check for sensitive variable names
                for sensitive in sensitive_vars:
                    if sensitive in var.upper() and value and len(value) >= 4:
                        findings.append(
                            CredentialFinding(
                                pid=pid,
                                process_name=name,
                                username=username,
                                cmdline=proc.cmdline(),
                                finding_type='env_var',
                                matched_pattern=var,
                                matched_value=value
                            )
                        )
                        break
                        
            return findings
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return findings
            
    def _analyze_memory(self, pid: int, name: str, username: str) -> List[CredentialFinding]:
        """Analyze process memory for credentials"""
        findings = []
        
        # Skip if memory scanning is not enabled
        if not self.scan_memory:
            return findings
            
        try:
            # Get process memory info
            proc = psutil.Process(pid)
            mem_info = proc.memory_info()
            
            # Skip if process memory is larger than threshold (MB)
            if mem_info.rss > (self.memory_scan_threshold * 1024 * 1024):
                logger.debug(f"Skipping memory scan for PID {pid}, exceeds size threshold")
                return findings
                
            # This is a placeholder for memory scanning logic
            # Real memory scanning is complex and requires specialized tools or libraries
            # It may involve reading /proc/<pid>/mem or using ptrace
            logger.debug(f"Memory scanning for PID {pid} is not yet implemented")
            
            return findings
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return findings
    
    def set_monitoring_scope(self, monitoring_scope):
        """Set the monitoring scope for this detector"""
        self.monitoring_scope = monitoring_scope
        logger.debug("Monitoring scope set for credential harvesting detector")
    
    def scan_processes(self) -> List[CredentialFinding]:
        """Scan all processes for credential exposure"""
        findings = []
        scanned_count = 0
        skipped_count = 0
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'exe']):
            try:
                # Get basic process info
                pid = proc.info['pid']
                name = proc.info['name']
                username = proc.info['username']
                cmdline = proc.info['cmdline']
                exe_path = proc.info['exe'] if proc.info['exe'] else ''
                
                # Check if process is in monitoring scope (if scope is active)
                if self.monitoring_scope is not None:
                    should_monitor = self.monitoring_scope.should_monitor(exe_path)
                    if not should_monitor:
                        logger.debug(f"Skipping process {name} (PID: {pid}) - not in monitoring scope")
                        skipped_count += 1
                        continue
                
                # Skip whitelisted processes
                if self._is_whitelisted(proc):
                    skipped_count += 1
                    continue
                
                # Track scanned processes count
                scanned_count += 1
                
                # Analyze command line if enabled
                if self.scan_cmdline and cmdline:
                    cmd_findings = self._analyze_cmdline(pid, name, username, cmdline)
                    findings.extend(cmd_findings)
                
                # Analyze environment variables if enabled
                env_findings = self._analyze_env_vars(pid, name, username)
                findings.extend(env_findings)
                
                # Analyze process memory if enabled
                mem_findings = self._analyze_memory(pid, name, username)
                findings.extend(mem_findings)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Skip processes that are inaccessible
                skipped_count += 1
                continue
        
        # Log metrics about the scan
        logger.info(f"Scan completed: {scanned_count} processes scanned, {skipped_count} processes skipped, {len(findings)} findings")
        
        # Add metrics to findings object for reporting
        if hasattr(self, 'scan_metrics'):
            self.scan_metrics = {
                'scanned_processes': scanned_count,
                'skipped_processes': skipped_count,
                'total_findings': len(findings),
                'using_monitoring_scope': self.monitoring_scope is not None
            }
                
        return findings
        
    def generate_report(self, findings: List[CredentialFinding]) -> str:
        """Generate a report of credential findings"""
        if not findings:
            logger.info("No credential exposure detected")
            return ""
            
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        report_file = self.report_dir / f"report-{timestamp}.json"
        
        # Count findings by type
        findings_by_type = {}
        for finding in findings:
            if finding.finding_type not in findings_by_type:
                findings_by_type[finding.finding_type] = 0
            findings_by_type[finding.finding_type] += 1
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'findings': [finding.to_dict() for finding in findings],
            'summary': {
                'total_findings': len(findings),
                'by_type': findings_by_type
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Generated report: {report_file}")
        return str(report_file)
        
    def notify_admin(self, report_file: str, findings: List[CredentialFinding]):
        """Send notification to admin about credential findings"""
        if not self.notify_admin or not self.admin_email:
            return
            
        if not findings:
            return
            
        # Prepare email content
        subject = f"[SECURITY] Credential exposure detected on {socket.gethostname()}"
        
        # Group findings by type
        by_type = {}
        for finding in findings:
            if finding.finding_type not in by_type:
                by_type[finding.finding_type] = []
            by_type[finding.finding_type].append(finding)
            
        # Sort findings by severity
        sorted_findings = sorted(findings, key=lambda f: (0 if f.get_severity() == "HIGH" else 1, f.finding_type))
            
        body = f"""Credential Harvesting Detector has detected {len(findings)} potential credential exposures:
        
Summary by type:
"""
        
        for finding_type, count in by_type.items():
            body += f"- {finding_type}: {len(count)} findings\n"
            
        body += f"\nSee the full report at: {report_file}\n\n"
        body += "Most critical findings:\n\n"
        
        # Add details of the most critical findings
        for finding in sorted_findings[:5]:  # Show top 5 findings
            body += f"- PID {finding.pid} ({finding.process_name}) run by {finding.username}\n"
            body += f"  Type: {finding.finding_type}\n"
            body += f"  Pattern: {finding.matched_pattern}\n"
            body += f"  Matched value: {finding.matched_value}\n"
            if finding.cmdline:
                cmd_preview = ' '.join(finding.cmdline)
                if len(cmd_preview) > 100:
                    cmd_preview = cmd_preview[:97] + "..."
                body += f"  Command: {cmd_preview}\n"
            body += "\n"
            
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
            
    def _take_automated_action(self, findings: List[CredentialFinding]) -> bool:
        """Take automated action for findings
        
        Args:
            findings: List of credential findings
            
        Returns:
            bool: True if action was taken, False otherwise
        """
        # Execute custom script if configured
        if self.exec_script and os.path.exists(self.exec_script) and os.access(self.exec_script, os.X_OK):
            try:
                # Prepare data file for script
                report_file = self.report_dir / f"findings_{int(time.time())}.json"
                with open(report_file, 'w') as f:
                    json.dump([finding.to_dict() for finding in findings], f, indent=2)
                    
                # Execute script with report file as argument
                subprocess.run([self.exec_script, str(report_file)], check=True)
                logger.info(f"Executed custom script: {self.exec_script}")
                return True
            except subprocess.SubprocessError as e:
                logger.error(f"Failed to execute custom script: {str(e)}")
                
        # Terminate processes if configured
        if self.terminate_processes:
            terminated_count = 0
            for finding in findings:
                # Only terminate processes with high severity
                if finding.get_severity() == "HIGH":
                    try:
                        proc = psutil.Process(finding.pid)
                        proc.terminate()
                        terminated_count += 1
                        logger.warning(f"Terminated process {finding.process_name} (PID {finding.pid})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                        
            if terminated_count > 0:
                logger.info(f"Terminated {terminated_count} suspicious processes")
                return True
                
        return False

    def execute_response_script(self, report_file: str, findings: List[CredentialFinding]):
        """Execute response script with findings"""
        # Custom script execution is now handled in _take_automated_action method
        pass


class CredentialHarvestingDetectorService:
    """Service class for Credential Harvesting Detector"""
    
    def __init__(self, config_file=None):
        """Initialize the service with optional config file"""
        self.config_file = config_file
        self.config = self._load_config()
        self.interval = int(self.config['monitor']['interval'])
        self.pidfile = self.config['monitor']['pidfile']
        
        # Setup logging level
        log_level = self.config['monitor']['log_level'].upper()
        numeric_level = getattr(logging, log_level, None)
        if isinstance(numeric_level, int):
            logger.setLevel(numeric_level)
        
        # Initialize security and performance modules
        self._setup_security_and_performance()
            
        # Create detector instance
        self.detector = CredentialHarvestingDetector(self.config)
        
        # Control flag for main loop
        self.running = False
        
        # Handle signals
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _setup_security_and_performance(self):
        """Setup security and performance modules"""
        service_name = "credential_harvesting_detector"
        
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
                log_dir = Path("/var/log/credential_harvesting_detector")
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
                logger.info(f"Performance optimization enabled with static interval")
        else:
            self.perf_optimizer = None
            logger.info("Performance optimization disabled in configuration")
        
        # Initialize monitoring scope
        self.monitoring_scope = MonitoringScope(service_name)
        if 'monitoring_scope' in self.config:
            self.monitoring_scope.load_from_config(self.config['monitoring_scope'])
            logger.info("Monitoring scope configuration loaded")
        
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
        
    def _load_config(self):
        """Load configuration from file or use defaults"""
        config = configparser.ConfigParser()
        
        # Set defaults
        for section, items in DEFAULT_CONFIG.items():
            if not config.has_section(section):
                config.add_section(section)
            for key, value in items.items():
                config.set(section, key, value)
        
        # Override with file if provided
        if self.config_file and os.path.isfile(self.config_file):
            logger.info(f"Loading configuration from {self.config_file}")
            config.read(self.config_file)
        else:
            logger.info("Using default configuration")
            
        return config
        
    def _write_pid(self):
        """Write PID file"""
        with open(self.pidfile, 'w') as f:
            f.write(str(os.getpid()))
            
    def _remove_pid(self):
        """Remove PID file"""
        if os.path.isfile(self.pidfile):
            os.unlink(self.pidfile)
            
    def _handle_signal(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        
    def start(self):
        """Start the detector service"""
        self._write_pid()
        self.running = True
        logger.info("Starting Credential Harvesting Detector service")
        
        # Apply isolation if configured (must be done before dropping privileges)
        if self.isolation_mgr and self.config['isolation']['enabled'].lower() == 'true':
            try:
                self.isolation_mgr.apply_isolation()
                logger.info("Process isolation applied successfully")
            except Exception as e:
                logger.error(f"Failed to apply process isolation: {str(e)}")
        
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
            while self.running:
                # Check if we should be active
                is_active = True
                if self.service_activator:
                    is_active = self.service_activator.is_active
                
                # Run scan cycle if active
                if is_active:
                    self._run_scan_cycle()
                else:
                    # In inactive mode, just do minimal checks
                    self._run_minimal_scan()
                
                # Determine sleep interval
                if self.interval is None and self.perf_optimizer:
                    # Use adaptive interval
                    sleep_time = self.perf_optimizer.get_optimal_interval()
                else:
                    sleep_time = self.interval
                
                time.sleep(sleep_time)
        except Exception as e:
            logger.error(f"Error in main service loop: {str(e)}")
        finally:
            # Cleanup all resources
            logger.info("Shutting down and cleaning up resources...")
            
            # Clean up service activator
            if self.service_activator:
                self.service_activator.shutdown()
                logger.debug("Service activator shut down")
            
            # Clean up isolation resources if they exist
            if self.isolation_mgr:
                try:
                    self.isolation_mgr.cleanup_resources()
                    logger.debug("Isolation resources cleaned up")
                except Exception as e:
                    logger.error(f"Error cleaning up isolation resources: {str(e)}")
            
            # Clean up performance optimizer resources if they exist
            if hasattr(self, 'perf_optimizer') and self.perf_optimizer:
                try:
                    self.perf_optimizer.cleanup()
                    logger.debug("Performance optimizer cleaned up")
                except Exception as e:
                    logger.error(f"Error cleaning up performance optimizer: {str(e)}")
            
            self._remove_pid()
            logger.info("Credential Harvesting Detector service stopped successfully")
    
    def _run_minimal_scan(self):
        """Run a minimal scan when service is inactive"""
        # Just do basic system checks that might trigger reactivation
        try:
            # Check overall system CPU usage
            if self.perf_optimizer:
                cpu_usage = self.perf_optimizer.get_system_cpu_percent()
                
                # Update monitored value that might trigger activation
                if self.service_activator:
                    self.service_activator.update_monitored_value('system_cpu', cpu_usage)
                    
                    # Also check for any suspicious processes (simplified scan)
                    suspicious_count = self._count_suspicious_processes()
                    self.service_activator.update_monitored_value('suspicious_processes', suspicious_count)
        except Exception as e:
            logger.error(f"Error in minimal scan: {str(e)}")
    
    def _count_suspicious_processes(self):
        """Count suspicious processes for activation triggering"""
        suspicious_count = 0
        try:
            # Quick scan for obvious suspicious process names
            suspicious_keywords = ['miner', 'cryptominer', 'kworker', '.cache', '.tmp']
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    if proc.info['name'] in suspicious_keywords:
                        suspicious_count += 1
                        continue
                        
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        if any(keyword in cmdline.lower() for keyword in ['base64 -d', 'wget http', 'curl http']):
                            suspicious_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
            
        return suspicious_count
            
    def _run_scan_cycle(self):
        """Run a single scan cycle"""
        try:
            # Start performance monitoring for this cycle
            if self.perf_optimizer:
                self.perf_optimizer.start_operation("scan_cycle")
                
            logger.debug("Starting scan cycle")
            
            # Apply monitoring scope to the detector if configured
            use_monitoring_scope = False
            if self.monitoring_scope and self.monitoring_scope.is_configured():
                # Pass the monitoring scope to detector for this scan
                self.detector.set_monitoring_scope(self.monitoring_scope)
                use_monitoring_scope = True
                logger.debug("Using configured monitoring scope for this scan")
            
            # Temporarily restore privileges for scanning if needed
            if (self.priv_mgr and 
                self.config['privilege']['enabled'].lower() == 'true' and
                self.config['privilege']['restore_privileges_for_actions'].lower() == 'true'):
                with self.priv_mgr.temporarily_restore_privileges():
                    findings = self.detector.scan_processes()
            else:
                findings = self.detector.scan_processes()
            
            if findings:
                # Process findings
                logger.warning(f"Found {len(findings)} potential credential exposures")
                self.detector.handle_findings(findings)
                
                # Update service activator with finding count
                if self.service_activator:
                    self.service_activator.update_monitored_value('credential_findings', len(findings))
            else:
                logger.debug("No credential exposures detected in this scan cycle")
                
            # End performance monitoring for this cycle
            if self.perf_optimizer:
                self.perf_optimizer.end_operation("scan_cycle")
                
                # Get and log performance metrics
                scan_time = self.perf_optimizer.get_last_operation_duration("scan_cycle")
                cpu_usage = self.perf_optimizer.get_system_cpu_percent()
                memory_usage = self.perf_optimizer.get_memory_usage()
                
                # Update service activator with system metrics
                if self.service_activator:
                    self.service_activator.update_monitored_value('system_cpu', cpu_usage)
                    self.service_activator.update_monitored_value('system_memory', memory_usage)
                    self.service_activator.update_monitored_value('scan_time', scan_time)
                    
                logger.debug(f"Scan completed in {scan_time:.2f}s - System: CPU {cpu_usage}%, Memory {memory_usage}MB")
        except Exception as e:
            logger.error(f"Error in scan cycle: {str(e)}")


def main():
    """Main entry point"""
    # Parse command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Credential Harvesting Detector")
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument("-o", "--once", action="store_true", help="Run once and exit")
    parser.add_argument("-t", "--test", action="store_true", help="Test configuration and exit")
    args = parser.parse_args()
    
    if args.test:
        # Just test configuration and exit
        try:
            service = CredentialHarvestingDetectorService(args.config)
            print("Configuration test successful.")
            print(f"Using configuration from: {service.config_file if service.config_file else 'default'}")  
            return 0
        except Exception as e:
            print(f"Configuration test failed: {str(e)}")
            return 1
    
    # Create and start the service
    service = CredentialHarvestingDetectorService(args.config)
    
    if args.once:
        # Run once mode
        service._run_scan_cycle()
    else:
        # Run as a daemon
        service.start()
if __name__ == "__main__":
    main()