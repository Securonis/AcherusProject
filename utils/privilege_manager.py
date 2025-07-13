#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acherus Project - Privilege Management Module
Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import pwd
import grp
import subprocess
from pathlib import Path
import logging

class PrivilegeManager:
    """
    A utility class to handle privilege separation for Acherus Project tools.
    Allows services to drop privileges after initialization and use the
    principle of least privilege.
    """
    
    def __init__(self, service_name, config_user=None, config_group=None):
        """
        Initialize the privilege manager
        
        Args:
            service_name (str): Name of the service using this manager
            config_user (str): Optional username to switch to (defaults to 'acherus' if None)
            config_group (str): Optional group to switch to (defaults to 'acherus' if None)
        """
        self.logger = logging.getLogger(f"{service_name}.privileges")
        self.service_name = service_name
        self.target_user = config_user or 'acherus'
        self.target_group = config_group or 'acherus'
        self.privileged_ops = []  # Store operations requiring re-elevation
        self.original_uid = os.getuid()
        self.original_gid = os.getgid()
        self.current_euid = self.original_uid
        self.current_egid = self.original_gid

    def ensure_user_exists(self):
        """Ensure the target user and group exist, creating if necessary"""
        try:
            # Check if group exists
            grp.getgrnam(self.target_group)
            self.logger.debug(f"Group '{self.target_group}' already exists")
        except KeyError:
            # Create group if not exists
            try:
                self.logger.info(f"Creating group '{self.target_group}'")
                subprocess.run(['groupadd', '-r', self.target_group], check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to create group: {str(e)}")
                return False
                
        try:
            # Check if user exists
            pwd.getpwnam(self.target_user)
            self.logger.debug(f"User '{self.target_user}' already exists")
        except KeyError:
            # Create user if not exists
            try:
                self.logger.info(f"Creating user '{self.target_user}'")
                subprocess.run([
                    'useradd',
                    '-r',  # System account
                    '-g', self.target_group,  # Set primary group
                    '-s', '/sbin/nologin',  # No login shell
                    '-d', '/nonexistent',  # No home directory
                    '-c', f'Acherus {self.service_name} service user',
                    self.target_user
                ], check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to create user: {str(e)}")
                return False
        
        return True

    def drop_privileges(self):
        """
        Drop privileges to the target user and group.
        Should be called after initializing resources that need root.
        """
        if os.getuid() != 0:
            self.logger.warning("Not running as root, cannot drop privileges")
            return False
            
        try:
            # Get target user and group IDs
            target_uid = pwd.getpwnam(self.target_user).pw_uid
            target_gid = grp.getgrnam(self.target_group).gr_gid
            
            # Drop group privileges first
            os.setgroups([])  # Clear supplementary groups
            os.setgid(target_gid)
            
            # Drop user privileges
            os.setuid(target_uid)
            
            self.current_euid = os.geteuid()
            self.current_egid = os.getegid()
            
            # Verify privilege drop
            if os.getuid() != target_uid or os.getgid() != target_gid:
                self.logger.error("Failed to drop privileges, UIDs don't match expected values")
                return False
                
            self.logger.info(f"Successfully dropped privileges to {self.target_user}:{self.target_group}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error dropping privileges: {str(e)}")
            return False
    
    def prepare_directory(self, directory_path, mode=0o750):
        """
        Create and set proper permissions on a directory
        
        Args:
            directory_path (str): Path to directory
            mode (int): Permission mode (octal)
        """
        dir_path = Path(directory_path)
        
        # Ensure parent directory exists
        if not dir_path.parent.exists():
            self.logger.info(f"Creating parent directory: {dir_path.parent}")
            dir_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create directory if not exists
        if not dir_path.exists():
            self.logger.info(f"Creating directory: {dir_path}")
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Get target user and group IDs
        try:
            target_uid = pwd.getpwnam(self.target_user).pw_uid
            target_gid = grp.getgrnam(self.target_group).gr_gid
            
            # Set ownership and permissions
            os.chown(dir_path, target_uid, target_gid)
            os.chmod(dir_path, mode)
            
            self.logger.info(f"Set ownership {self.target_user}:{self.target_group} and mode {oct(mode)} on {dir_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to prepare directory {dir_path}: {str(e)}")
            return False
    
    def register_privileged_operation(self, operation_name, callback_function):
        """
        Register an operation that requires privileges
        
        Args:
            operation_name (str): Name of the operation
            callback_function (callable): Function to call with elevated privileges
        """
        self.privileged_ops.append((operation_name, callback_function))
        self.logger.debug(f"Registered privileged operation: {operation_name}")
    
    def execute_privileged(self, operation_name, *args, **kwargs):
        """
        Temporarily elevate privileges to execute a privileged operation
        
        Args:
            operation_name (str): Name of the registered operation
            *args, **kwargs: Arguments to pass to the operation function
            
        Returns:
            The return value from the operation function
        """
        # Find the operation
        operation = None
        for name, func in self.privileged_ops:
            if name == operation_name:
                operation = func
                break
                
        if not operation:
            self.logger.error(f"Unknown privileged operation: {operation_name}")
            return None
            
        # Save current effective uid/gid
        current_euid = os.geteuid()
        current_egid = os.getegid()
        
        result = None
        try:
            # Elevate privileges temporarily
            os.seteuid(0)
            os.setegid(0)
            
            # Execute operation with elevated privileges
            self.logger.debug(f"Executing privileged operation: {operation_name}")
            result = operation(*args, **kwargs)
            
        except Exception as e:
            self.logger.error(f"Error in privileged operation {operation_name}: {str(e)}")
        finally:
            # Restore previous privileges
            os.setegid(current_egid)
            os.seteuid(current_euid)
            
        return result
