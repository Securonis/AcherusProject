#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Service Manager module for the Acherus Project Management GUI
Handles interactions with systemd services

Copyright (C) 2025 root0emir

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import subprocess
import re
import os
import logging

class SystemdServiceManager:
    """Manages systemd services"""
    
    def __init__(self):
        """Initialize the service manager"""
        # Check if systemd is available
        if not self._is_systemd_available():
            logging.warning("systemd not detected or insufficient permissions. Some features may not work.")
    
    def _is_systemd_available(self):
        """Check if systemd is available"""
        try:
            result = subprocess.run(['systemctl', '--version'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _run_systemctl_command(self, command, service_name=None):
        """Run a systemctl command and return the result"""
        cmd = ['systemctl']
        
        if service_name and service_name.strip():
            cmd.extend(command.split())
            cmd.append(service_name)
        else:
            cmd.extend(command.split())
            
        # Try running with sudo if available
        if os.geteuid() != 0:  # Not running as root
            sudo_cmd = ['sudo', '-n']  # -n option for non-interactive
            sudo_cmd.extend(cmd)
            
            try:
                result = subprocess.run(sudo_cmd, 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE,
                                      text=True,
                                      check=True)
                return result
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fall back to regular command if sudo fails
                pass
        
        # Run command directly
        result = subprocess.run(cmd, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE,
                              text=True,
                              check=True)
        return result
    
    def is_service_active(self, service_name):
        """Check if a service is active"""
        try:
            result = self._run_systemctl_command('is-active', service_name)
            return result.stdout.strip() == 'active'
        except subprocess.CalledProcessError:
            return False
    
    def is_service_enabled(self, service_name):
        """Check if a service is enabled at boot"""
        try:
            result = self._run_systemctl_command('is-enabled', service_name)
            return result.stdout.strip() == 'enabled'
        except subprocess.CalledProcessError:
            return False
    
    def start_service(self, service_name):
        """Start a service"""
        return self._run_systemctl_command('start', service_name)
    
    def stop_service(self, service_name):
        """Stop a service"""
        return self._run_systemctl_command('stop', service_name)
    
    def restart_service(self, service_name):
        """Restart a service"""
        return self._run_systemctl_command('restart', service_name)
    
    def enable_service(self, service_name):
        """Enable a service at boot"""
        return self._run_systemctl_command('enable', service_name)
    
    def disable_service(self, service_name):
        """Disable a service at boot"""
        return self._run_systemctl_command('disable', service_name)
    
    def get_service_status(self, service_name):
        """Get detailed status information for a service"""
        try:
            result = self._run_systemctl_command('status', service_name)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return e.stdout  # Return output even if command failed
    
    def list_all_services(self):
        """List all systemd services"""
        try:
            result = self._run_systemctl_command('list-units --type=service')
            services = []
            
            for line in result.stdout.splitlines():
                if '.service' in line:
                    # Extract service name and status
                    parts = re.split(r'\s+', line.strip(), maxsplit=4)
                    if len(parts) >= 4:
                        service_name = parts[0]
                        load_status = parts[1]
                        active_status = parts[2]
                        sub_status = parts[3]
                        
                        services.append({
                            'name': service_name,
                            'load': load_status,
                            'active': active_status,
                            'sub': sub_status
                        })
            
            return services
        except subprocess.CalledProcessError:
            return []
