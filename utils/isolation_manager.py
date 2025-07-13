#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acherus Project - Service Isolation Manager Module
Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import subprocess
import logging
from pathlib import Path
import json

class IsolationManager:
    """
    A utility class to implement service isolation using Linux namespaces
    and cgroups for Acherus Project tools. Provides methods to create
    isolated environments for services.
    """
    
    def __init__(self, service_name):
        """
        Initialize the isolation manager
        
        Args:
            service_name (str): Name of the service using this manager
        """
        self.service_name = service_name
        self.logger = logging.getLogger(f"{service_name}.isolation")
        self.cgroup_path = f"/sys/fs/cgroup/acherus_{service_name}"
        self.namespace_enabled = False
        self.cgroup_enabled = False
        
    def setup_cgroup(self, cpu_limit=10, memory_limit_mb=100):
        """
        Set up cgroup resource limits for this service
        
        Args:
            cpu_limit (int): CPU usage limit in percentage
            memory_limit_mb (int): Memory usage limit in MB
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if we're running with sufficient privileges
        if os.geteuid() != 0:
            self.logger.error("Setting up cgroups requires root privileges")
            return False
        
        try:
            # Check if cgroup v2 unified hierarchy is available
            if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
                self.logger.warning("Cgroup v2 unified hierarchy not found. Using legacy cgroups.")
                return self._setup_legacy_cgroups(cpu_limit, memory_limit_mb)
            
            # Create cgroup for the service if it doesn't exist
            cgroup_path = Path(self.cgroup_path)
            if not cgroup_path.exists():
                self.logger.info(f"Creating cgroup at {self.cgroup_path}")
                cgroup_path.mkdir(parents=True, exist_ok=True)
            
            # Set CPU limit (in microseconds per period)
            with open(f"{self.cgroup_path}/cpu.max", "w") as f:
                # Convert percentage to quota/period
                # Default period is 100000 microseconds (100ms)
                period = 100000
                quota = int(period * cpu_limit / 100)
                f.write(f"{quota} {period}")
                
            # Set memory limit
            with open(f"{self.cgroup_path}/memory.max", "w") as f:
                # Convert MB to bytes
                memory_bytes = memory_limit_mb * 1024 * 1024
                f.write(str(memory_bytes))
                
            # Add current process to the cgroup
            with open(f"{self.cgroup_path}/cgroup.procs", "w") as f:
                f.write(str(os.getpid()))
                
            self.cgroup_enabled = True
            self.logger.info(f"Service {self.service_name} successfully placed in cgroup with CPU limit {cpu_limit}% and memory limit {memory_limit_mb}MB")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set up cgroup: {str(e)}")
            return False
    
    def _setup_legacy_cgroups(self, cpu_limit, memory_limit_mb):
        """
        Set up legacy cgroups (v1) for older systems
        
        Args:
            cpu_limit (int): CPU usage limit in percentage
            memory_limit_mb (int): Memory usage limit in MB
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if cpu and memory controllers exist
            if not os.path.exists("/sys/fs/cgroup/cpu") or not os.path.exists("/sys/fs/cgroup/memory"):
                self.logger.error("Required cgroup controllers not found")
                return False
            
            # Create cgroup in each controller
            cpu_cgroup = f"/sys/fs/cgroup/cpu/acherus_{self.service_name}"
            memory_cgroup = f"/sys/fs/cgroup/memory/acherus_{self.service_name}"
            
            os.makedirs(cpu_cgroup, exist_ok=True)
            os.makedirs(memory_cgroup, exist_ok=True)
            
            # Set CPU limit
            period = 100000
            quota = int(period * cpu_limit / 100)
            with open(f"{cpu_cgroup}/cpu.cfs_period_us", "w") as f:
                f.write(str(period))
            with open(f"{cpu_cgroup}/cpu.cfs_quota_us", "w") as f:
                f.write(str(quota))
                
            # Set memory limit
            memory_bytes = memory_limit_mb * 1024 * 1024
            with open(f"{memory_cgroup}/memory.limit_in_bytes", "w") as f:
                f.write(str(memory_bytes))
                
            # Add current process to the cgroups
            with open(f"{cpu_cgroup}/tasks", "w") as f:
                f.write(str(os.getpid()))
            with open(f"{memory_cgroup}/tasks", "w") as f:
                f.write(str(os.getpid()))
                
            self.cgroup_enabled = True
            self.logger.info(f"Service {self.service_name} successfully placed in legacy cgroups with CPU limit {cpu_limit}% and memory limit {memory_limit_mb}MB")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set up legacy cgroups: {str(e)}")
            return False
            
    def enable_namespace_isolation(self, use_network=True):
        """
        Enable Linux namespace isolation for the service
        
        Note: This must be called very early in the application,
        ideally before any threads are created.
        
        Args:
            use_network (bool): Whether the service needs network access
            
        Returns:
            bool: True if successful, False otherwise
        """
        # We need to use unshare which requires a subprocess call
        # as Python's os.unshare is limited
        
        if os.geteuid() != 0:
            self.logger.error("Setting up namespaces requires root privileges")
            return False
        
        try:
            # Prepare unshare command - isolate mount, UTS, IPC, and PID namespaces
            cmd = ["unshare", "--mount", "--uts", "--ipc"]
            
            # If no network access needed, isolate network too
            if not use_network:
                cmd.append("--net")
                
            # Create new PID namespace and fork
            cmd.append("--fork")
            
            # Get current program and args
            program = os.readlink(f"/proc/{os.getpid()}/exe")
            with open(f"/proc/{os.getpid()}/cmdline", "rb") as f:
                args = f.read().decode("utf-8").split("\0")[1:-1]  # Skip executable and empty last element
                
            # Add a special argument so we know we're in the namespace
            ns_arg = "--in-namespace=true"
            
            # If we're already in a namespace (re-executed), run normally
            if ns_arg in args:
                self.namespace_enabled = True
                self.logger.info(f"Already running in isolated namespace")
                return True
                
            # Add namespace marker and exec original command
            cmd.extend([program] + args + [ns_arg])
            
            # Log what we're doing
            self.logger.info(f"Enabling namespace isolation with command: {' '.join(cmd)}")
            
            # Execute the command (this will replace the current process)
            os.execvp(cmd[0], cmd)
            
            # We should never reach here as execvp replaces the current process
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set up namespaces: {str(e)}")
            return False
            
    def get_resource_usage(self):
        """
        Get current resource usage statistics from cgroup
        
        Returns:
            dict: Resource usage information or None if failed
        """
        if not self.cgroup_enabled:
            self.logger.warning("Cannot get resource usage: cgroup not enabled")
            return None
            
        try:
            usage = {}
            
            # Check if we're using cgroup v2 unified hierarchy
            if os.path.exists(f"{self.cgroup_path}/memory.current"):
                # cgroup v2
                with open(f"{self.cgroup_path}/memory.current", "r") as f:
                    usage["memory_bytes"] = int(f.read().strip())
                    usage["memory_mb"] = usage["memory_bytes"] / (1024 * 1024)
                    
                with open(f"{self.cgroup_path}/cpu.stat", "r") as f:
                    for line in f:
                        if "usage_usec" in line:
                            usage["cpu_usage_us"] = int(line.split()[1])
                            usage["cpu_usage_sec"] = usage["cpu_usage_us"] / 1000000
                            break
            else:
                # Legacy cgroup
                cpu_cgroup = f"/sys/fs/cgroup/cpu/acherus_{self.service_name}"
                memory_cgroup = f"/sys/fs/cgroup/memory/acherus_{self.service_name}"
                
                if os.path.exists(f"{memory_cgroup}/memory.usage_in_bytes"):
                    with open(f"{memory_cgroup}/memory.usage_in_bytes", "r") as f:
                        usage["memory_bytes"] = int(f.read().strip())
                        usage["memory_mb"] = usage["memory_bytes"] / (1024 * 1024)
                        
                if os.path.exists(f"{cpu_cgroup}/cpuacct.usage"):
                    with open(f"{cpu_cgroup}/cpuacct.usage", "r") as f:
                        usage["cpu_usage_ns"] = int(f.read().strip())
                        usage["cpu_usage_sec"] = usage["cpu_usage_ns"] / 1000000000
                        
            return usage
            
        except Exception as e:
            self.logger.error(f"Failed to get resource usage: {str(e)}")
            return None
            
    def cleanup(self):
        """
        Clean up cgroups when service is shutting down
        """
        if not self.cgroup_enabled:
            return
            
        try:
            # For cgroup v2
            if os.path.exists(self.cgroup_path):
                # Move processes to parent cgroup
                if os.path.exists(f"{self.cgroup_path}/cgroup.procs"):
                    with open(f"{self.cgroup_path}/cgroup.procs", "r") as f:
                        pids = f.read().strip().split("\n")
                        
                    parent_path = os.path.dirname(self.cgroup_path)
                    for pid in pids:
                        if pid:
                            try:
                                with open(f"{parent_path}/cgroup.procs", "w") as f:
                                    f.write(pid)
                            except:
                                pass
                
                # Remove cgroup
                try:
                    os.rmdir(self.cgroup_path)
                except:
                    pass
                    
            # For legacy cgroups
            cpu_cgroup = f"/sys/fs/cgroup/cpu/acherus_{self.service_name}"
            memory_cgroup = f"/sys/fs/cgroup/memory/acherus_{self.service_name}"
            
            for cg_path in [cpu_cgroup, memory_cgroup]:
                if os.path.exists(cg_path):
                    try:
                        os.rmdir(cg_path)
                    except:
                        pass
                        
            self.logger.info(f"Cleaned up cgroups for {self.service_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to clean up cgroups: {str(e)}")
