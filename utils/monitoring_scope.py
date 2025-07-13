#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acherus Project - Monitoring Scope Manager Module
Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import re
import logging
import fnmatch
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Pattern, Union

class MonitoringScope:
    """
    A utility class to manage fine-grained monitoring scope configuration for Acherus Project tools.
    Provides flexible targeting of specific paths, processes, ports, and services
    with include/exclude patterns and priorities.
    """
    
    def __init__(self, service_name: str):
        """
        Initialize the monitoring scope manager
        
        Args:
            service_name (str): Name of the service using this manager
        """
        self.service_name = service_name
        self.logger = logging.getLogger(f"{service_name}.scope")
        
        # Path monitoring
        self.path_includes: List[Dict[str, Any]] = []
        self.path_excludes: List[Dict[str, Any]] = []
        
        # Process monitoring
        self.process_includes: List[Dict[str, Any]] = []
        self.process_excludes: List[Dict[str, Any]] = []
        
        # Port monitoring
        self.port_includes: List[Dict[str, Any]] = []
        self.port_excludes: List[Dict[str, Any]] = []
        
        # Service monitoring
        self.service_includes: List[Dict[str, Any]] = []
        self.service_excludes: List[Dict[str, Any]] = []
        
    def add_path_include(self, pattern: str, priority: int = 100, recursive: bool = True, 
                        regex: bool = False) -> None:
        """
        Add a path pattern to include in monitoring
        
        Args:
            pattern (str): Path pattern to include
            priority (int): Priority level (higher numbers take precedence)
            recursive (bool): Whether to include subdirectories
            regex (bool): Whether the pattern is a regex (otherwise glob)
        """
        compiled_pattern = None
        if regex:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                return
        
        self.path_includes.append({
            'pattern': pattern,
            'compiled_pattern': compiled_pattern,
            'priority': priority,
            'recursive': recursive,
            'regex': regex
        })
        self.logger.debug(f"Added path include: pattern={pattern}, priority={priority}, " +
                         f"recursive={recursive}, regex={regex}")
        
    def add_path_exclude(self, pattern: str, priority: int = 100, recursive: bool = True, 
                        regex: bool = False) -> None:
        """
        Add a path pattern to exclude from monitoring
        
        Args:
            pattern (str): Path pattern to exclude
            priority (int): Priority level (higher numbers take precedence)
            recursive (bool): Whether to exclude subdirectories
            regex (bool): Whether the pattern is a regex (otherwise glob)
        """
        compiled_pattern = None
        if regex:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                return
        
        self.path_excludes.append({
            'pattern': pattern,
            'compiled_pattern': compiled_pattern,
            'priority': priority,
            'recursive': recursive,
            'regex': regex
        })
        self.logger.debug(f"Added path exclude: pattern={pattern}, priority={priority}, " +
                         f"recursive={recursive}, regex={regex}")
        
    def add_process_include(self, pattern: str, priority: int = 100, 
                           match_cmdline: bool = False, regex: bool = False) -> None:
        """
        Add a process pattern to include in monitoring
        
        Args:
            pattern (str): Process name pattern to include
            priority (int): Priority level (higher numbers take precedence)
            match_cmdline (bool): Whether to match against full command line
            regex (bool): Whether the pattern is a regex (otherwise exact match or substring)
        """
        compiled_pattern = None
        if regex:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                return
        
        self.process_includes.append({
            'pattern': pattern,
            'compiled_pattern': compiled_pattern,
            'priority': priority,
            'match_cmdline': match_cmdline,
            'regex': regex
        })
        self.logger.debug(f"Added process include: pattern={pattern}, priority={priority}, " +
                         f"match_cmdline={match_cmdline}, regex={regex}")
        
    def add_process_exclude(self, pattern: str, priority: int = 100, 
                           match_cmdline: bool = False, regex: bool = False) -> None:
        """
        Add a process pattern to exclude from monitoring
        
        Args:
            pattern (str): Process name pattern to exclude
            priority (int): Priority level (higher numbers take precedence)
            match_cmdline (bool): Whether to match against full command line
            regex (bool): Whether the pattern is a regex (otherwise exact match or substring)
        """
        compiled_pattern = None
        if regex:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                return
        
        self.process_excludes.append({
            'pattern': pattern,
            'compiled_pattern': compiled_pattern,
            'priority': priority,
            'match_cmdline': match_cmdline,
            'regex': regex
        })
        self.logger.debug(f"Added process exclude: pattern={pattern}, priority={priority}, " +
                         f"match_cmdline={match_cmdline}, regex={regex}")
    
    def add_port_include(self, port: Union[int, str], protocol: str = 'any', 
                        priority: int = 100) -> None:
        """
        Add a port to include in monitoring
        
        Args:
            port (int or str): Port number or range (e.g. '80' or '8000-9000')
            protocol (str): Protocol ('tcp', 'udp', or 'any')
            priority (int): Priority level (higher numbers take precedence)
        """
        if not self._validate_port_input(port, protocol):
            return
            
        self.port_includes.append({
            'port': port,
            'protocol': protocol.lower(),
            'priority': priority
        })
        self.logger.debug(f"Added port include: port={port}, protocol={protocol}, priority={priority}")
        
    def add_port_exclude(self, port: Union[int, str], protocol: str = 'any', 
                        priority: int = 100) -> None:
        """
        Add a port to exclude from monitoring
        
        Args:
            port (int or str): Port number or range (e.g. '80' or '8000-9000')
            protocol (str): Protocol ('tcp', 'udp', or 'any')
            priority (int): Priority level (higher numbers take precedence)
        """
        if not self._validate_port_input(port, protocol):
            return
            
        self.port_excludes.append({
            'port': port,
            'protocol': protocol.lower(),
            'priority': priority
        })
        self.logger.debug(f"Added port exclude: port={port}, protocol={protocol}, priority={priority}")
        
    def _validate_port_input(self, port: Union[int, str], protocol: str) -> bool:
        """Validate port and protocol inputs"""
        # Validate protocol
        if protocol.lower() not in ['tcp', 'udp', 'any']:
            self.logger.error(f"Invalid protocol '{protocol}'. Must be 'tcp', 'udp', or 'any'")
            return False
            
        # Validate port
        if isinstance(port, int):
            if port < 1 or port > 65535:
                self.logger.error(f"Invalid port number {port}. Must be between 1 and 65535")
                return False
        elif isinstance(port, str):
            # Check if it's a range (e.g. '8000-9000')
            if '-' in port:
                try:
                    start_port, end_port = map(int, port.split('-'))
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        self.logger.error(f"Invalid port range '{port}'. Must be between 1 and 65535")
                        return False
                except ValueError:
                    self.logger.error(f"Invalid port range format '{port}'. Must be 'start-end'")
                    return False
            else:
                # Try to convert to int
                try:
                    port_num = int(port)
                    if port_num < 1 or port_num > 65535:
                        self.logger.error(f"Invalid port number '{port}'. Must be between 1 and 65535")
                        return False
                except ValueError:
                    self.logger.error(f"Invalid port value '{port}'. Must be an integer or range")
                    return False
        else:
            self.logger.error(f"Invalid port type. Must be int or str, got {type(port)}")
            return False
            
        return True
        
    def add_service_include(self, pattern: str, priority: int = 100, regex: bool = False) -> None:
        """
        Add a service pattern to include in monitoring
        
        Args:
            pattern (str): Service name pattern to include
            priority (int): Priority level (higher numbers take precedence)
            regex (bool): Whether the pattern is a regex (otherwise exact match or substring)
        """
        compiled_pattern = None
        if regex:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                return
        
        self.service_includes.append({
            'pattern': pattern,
            'compiled_pattern': compiled_pattern,
            'priority': priority,
            'regex': regex
        })
        self.logger.debug(f"Added service include: pattern={pattern}, priority={priority}, regex={regex}")
        
    def add_service_exclude(self, pattern: str, priority: int = 100, regex: bool = False) -> None:
        """
        Add a service pattern to exclude from monitoring
        
        Args:
            pattern (str): Service name pattern to exclude
            priority (int): Priority level (higher numbers take precedence)
            regex (bool): Whether the pattern is a regex (otherwise exact match or substring)
        """
        compiled_pattern = None
        if regex:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
                return
        
        self.service_excludes.append({
            'pattern': pattern,
            'compiled_pattern': compiled_pattern,
            'priority': priority,
            'regex': regex
        })
        self.logger.debug(f"Added service exclude: pattern={pattern}, priority={priority}, regex={regex}")
    
    def should_monitor_path(self, path: str) -> bool:
        """
        Check if a path should be monitored according to configured rules
        
        Args:
            path (str): Path to check
            
        Returns:
            bool: True if path should be monitored, False otherwise
        """
        path = os.path.normpath(path)
        path_obj = Path(path)
        
        # Start with default: monitor if there are includes, don't if only excludes
        default_action = len(self.path_includes) > 0
        
        # Find matching rules
        matching_includes = []
        matching_excludes = []
        
        # Check includes
        for rule in self.path_includes:
            if self._path_matches_rule(path, path_obj, rule):
                matching_includes.append(rule)
                
        # Check excludes
        for rule in self.path_excludes:
            if self._path_matches_rule(path, path_obj, rule):
                matching_excludes.append(rule)
                
        # If no rules match, use default action
        if not matching_includes and not matching_excludes:
            return default_action
            
        # If only includes match, include
        if matching_includes and not matching_excludes:
            return True
            
        # If only excludes match, exclude
        if matching_excludes and not matching_includes:
            return False
            
        # Both match, use highest priority
        max_include_priority = max(rule['priority'] for rule in matching_includes)
        max_exclude_priority = max(rule['priority'] for rule in matching_excludes)
        
        # If priorities are equal, exclude wins
        return max_include_priority > max_exclude_priority
    
    def _path_matches_rule(self, path: str, path_obj: Path, rule: Dict[str, Any]) -> bool:
        """Check if a path matches a rule"""
        if rule['regex']:
            # Use regex pattern
            if rule['compiled_pattern']:
                return bool(rule['compiled_pattern'].search(path))
            return False
        else:
            # Use glob pattern
            if fnmatch.fnmatch(path, rule['pattern']):
                return True
            
            # Check if any parent directory matches (if recursive)
            if rule['recursive']:
                for parent in path_obj.parents:
                    if fnmatch.fnmatch(str(parent), rule['pattern']):
                        return True
            
            return False
    
    def should_monitor_process(self, process_name: str, cmdline: Optional[str] = None) -> bool:
        """
        Check if a process should be monitored according to configured rules
        
        Args:
            process_name (str): Process name to check
            cmdline (str, optional): Full command line of the process
            
        Returns:
            bool: True if process should be monitored, False otherwise
        """
        # Start with default: monitor if there are includes, don't if only excludes
        default_action = len(self.process_includes) > 0
        
        # Find matching rules
        matching_includes = []
        matching_excludes = []
        
        # Check includes
        for rule in self.process_includes:
            if self._process_matches_rule(process_name, cmdline, rule):
                matching_includes.append(rule)
                
        # Check excludes
        for rule in self.process_excludes:
            if self._process_matches_rule(process_name, cmdline, rule):
                matching_excludes.append(rule)
                
        # If no rules match, use default action
        if not matching_includes and not matching_excludes:
            return default_action
            
        # If only includes match, include
        if matching_includes and not matching_excludes:
            return True
            
        # If only excludes match, exclude
        if matching_excludes and not matching_includes:
            return False
            
        # Both match, use highest priority
        max_include_priority = max(rule['priority'] for rule in matching_includes)
        max_exclude_priority = max(rule['priority'] for rule in matching_excludes)
        
        # If priorities are equal, exclude wins
        return max_include_priority > max_exclude_priority
    
    def _process_matches_rule(self, process_name: str, cmdline: Optional[str], 
                              rule: Dict[str, Any]) -> bool:
        """Check if a process matches a rule"""
        # Determine what to match against
        match_target = cmdline if rule['match_cmdline'] and cmdline else process_name
        
        if not match_target:
            return False
            
        if rule['regex']:
            # Use regex pattern
            if rule['compiled_pattern']:
                return bool(rule['compiled_pattern'].search(match_target))
            return False
        else:
            # Use exact match or substring
            return rule['pattern'] == match_target or rule['pattern'] in match_target
    
    def should_monitor_port(self, port: int, protocol: str) -> bool:
        """
        Check if a port should be monitored according to configured rules
        
        Args:
            port (int): Port number to check
            protocol (str): Protocol ('tcp' or 'udp')
            
        Returns:
            bool: True if port should be monitored, False otherwise
        """
        protocol = protocol.lower()
        if protocol not in ['tcp', 'udp']:
            self.logger.warning(f"Invalid protocol '{protocol}'. Must be 'tcp' or 'udp'")
            return False
            
        # Start with default: monitor if there are includes, don't if only excludes
        default_action = len(self.port_includes) > 0
        
        # Find matching rules
        matching_includes = []
        matching_excludes = []
        
        # Check includes
        for rule in self.port_includes:
            if self._port_matches_rule(port, protocol, rule):
                matching_includes.append(rule)
                
        # Check excludes
        for rule in self.port_excludes:
            if self._port_matches_rule(port, protocol, rule):
                matching_excludes.append(rule)
                
        # If no rules match, use default action
        if not matching_includes and not matching_excludes:
            return default_action
            
        # If only includes match, include
        if matching_includes and not matching_excludes:
            return True
            
        # If only excludes match, exclude
        if matching_excludes and not matching_includes:
            return False
            
        # Both match, use highest priority
        max_include_priority = max(rule['priority'] for rule in matching_includes)
        max_exclude_priority = max(rule['priority'] for rule in matching_excludes)
        
        # If priorities are equal, exclude wins
        return max_include_priority > max_exclude_priority
    
    def _port_matches_rule(self, port: int, protocol: str, rule: Dict[str, Any]) -> bool:
        """Check if a port matches a rule"""
        # Check protocol match
        if rule['protocol'] != 'any' and rule['protocol'] != protocol:
            return False
            
        # Check port match
        rule_port = rule['port']
        
        if isinstance(rule_port, int):
            return port == rule_port
        elif isinstance(rule_port, str):
            if '-' in rule_port:
                # It's a range
                start_port, end_port = map(int, rule_port.split('-'))
                return start_port <= port <= end_port
            else:
                # Try to convert to int
                try:
                    return port == int(rule_port)
                except ValueError:
                    return False
        return False
    
    def should_monitor_service(self, service_name: str) -> bool:
        """
        Check if a service should be monitored according to configured rules
        
        Args:
            service_name (str): Service name to check
            
        Returns:
            bool: True if service should be monitored, False otherwise
        """
        # Start with default: monitor if there are includes, don't if only excludes
        default_action = len(self.service_includes) > 0
        
        # Find matching rules
        matching_includes = []
        matching_excludes = []
        
        # Check includes
        for rule in self.service_includes:
            if self._service_matches_rule(service_name, rule):
                matching_includes.append(rule)
                
        # Check excludes
        for rule in self.service_excludes:
            if self._service_matches_rule(service_name, rule):
                matching_excludes.append(rule)
                
        # If no rules match, use default action
        if not matching_includes and not matching_excludes:
            return default_action
            
        # If only includes match, include
        if matching_includes and not matching_excludes:
            return True
            
        # If only excludes match, exclude
        if matching_excludes and not matching_includes:
            return False
            
        # Both match, use highest priority
        max_include_priority = max(rule['priority'] for rule in matching_includes)
        max_exclude_priority = max(rule['priority'] for rule in matching_excludes)
        
        # If priorities are equal, exclude wins
        return max_include_priority > max_exclude_priority
    
    def _service_matches_rule(self, service_name: str, rule: Dict[str, Any]) -> bool:
        """Check if a service matches a rule"""
        if rule['regex']:
            # Use regex pattern
            if rule['compiled_pattern']:
                return bool(rule['compiled_pattern'].search(service_name))
            return False
        else:
            # Use exact match or substring
            return rule['pattern'] == service_name or rule['pattern'] in service_name
            
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """
        Load monitoring scope configuration from a dictionary
        
        Args:
            config (dict): Configuration dictionary
        """
        # Clear existing rules
        self.path_includes = []
        self.path_excludes = []
        self.process_includes = []
        self.process_excludes = []
        self.port_includes = []
        self.port_excludes = []
        self.service_includes = []
        self.service_excludes = []
        
        # Load path rules
        if 'paths' in config:
            if 'include' in config['paths']:
                for item in config['paths']['include']:
                    self.add_path_include(
                        pattern=item['pattern'],
                        priority=item.get('priority', 100),
                        recursive=item.get('recursive', True),
                        regex=item.get('regex', False)
                    )
            if 'exclude' in config['paths']:
                for item in config['paths']['exclude']:
                    self.add_path_exclude(
                        pattern=item['pattern'],
                        priority=item.get('priority', 100),
                        recursive=item.get('recursive', True),
                        regex=item.get('regex', False)
                    )
                    
        # Load process rules
        if 'processes' in config:
            if 'include' in config['processes']:
                for item in config['processes']['include']:
                    self.add_process_include(
                        pattern=item['pattern'],
                        priority=item.get('priority', 100),
                        match_cmdline=item.get('match_cmdline', False),
                        regex=item.get('regex', False)
                    )
            if 'exclude' in config['processes']:
                for item in config['processes']['exclude']:
                    self.add_process_exclude(
                        pattern=item['pattern'],
                        priority=item.get('priority', 100),
                        match_cmdline=item.get('match_cmdline', False),
                        regex=item.get('regex', False)
                    )
                    
        # Load port rules
        if 'ports' in config:
            if 'include' in config['ports']:
                for item in config['ports']['include']:
                    self.add_port_include(
                        port=item['port'],
                        protocol=item.get('protocol', 'any'),
                        priority=item.get('priority', 100)
                    )
            if 'exclude' in config['ports']:
                for item in config['ports']['exclude']:
                    self.add_port_exclude(
                        port=item['port'],
                        protocol=item.get('protocol', 'any'),
                        priority=item.get('priority', 100)
                    )
                    
        # Load service rules
        if 'services' in config:
            if 'include' in config['services']:
                for item in config['services']['include']:
                    self.add_service_include(
                        pattern=item['pattern'],
                        priority=item.get('priority', 100),
                        regex=item.get('regex', False)
                    )
            if 'exclude' in config['services']:
                for item in config['services']['exclude']:
                    self.add_service_exclude(
                        pattern=item['pattern'],
                        priority=item.get('priority', 100),
                        regex=item.get('regex', False)
                    )
                    
        self.logger.info("Loaded monitoring scope configuration")
        
    def get_config(self) -> Dict[str, Any]:
        """
        Get current monitoring scope configuration as a dictionary
        
        Returns:
            dict: Current configuration
        """
        config = {
            'paths': {
                'include': [
                    {k: v for k, v in rule.items() if k != 'compiled_pattern'}
                    for rule in self.path_includes
                ],
                'exclude': [
                    {k: v for k, v in rule.items() if k != 'compiled_pattern'}
                    for rule in self.path_excludes
                ]
            },
            'processes': {
                'include': [
                    {k: v for k, v in rule.items() if k != 'compiled_pattern'}
                    for rule in self.process_includes
                ],
                'exclude': [
                    {k: v for k, v in rule.items() if k != 'compiled_pattern'}
                    for rule in self.process_excludes
                ]
            },
            'ports': {
                'include': [rule for rule in self.port_includes],
                'exclude': [rule for rule in self.port_excludes]
            },
            'services': {
                'include': [
                    {k: v for k, v in rule.items() if k != 'compiled_pattern'}
                    for rule in self.service_includes
                ],
                'exclude': [
                    {k: v for k, v in rule.items() if k != 'compiled_pattern'}
                    for rule in self.service_excludes
                ]
            }
        }
        
        return config
