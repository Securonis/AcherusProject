#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acherus Project - Performance Optimizer Module
Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import time
import logging
import psutil
import threading
import gc
from functools import wraps
from typing import Dict, List, Optional, Any, Callable

class PerformanceOptimizer:
    """
    A utility class to optimize resource usage and performance for Acherus Project tools.
    Provides adaptive monitoring frequency, resource usage tracking, and performance tuning.
    """
    
    def __init__(self, service_name: str):
        """
        Initialize the performance optimizer
        
        Args:
            service_name (str): Name of the service using this optimizer
        """
        self.service_name = service_name
        self.logger = logging.getLogger(f"{service_name}.performance")
        self.process = psutil.Process(os.getpid())
        
        # Default resource thresholds
        self.cpu_threshold = 70.0  # percent
        self.memory_threshold = 200.0  # MB
        self.io_threshold = 10.0  # MB/s
        
        # Performance tracking
        self.monitoring_interval = 5.0  # seconds
        self.resource_history: List[Dict[str, float]] = []
        self.history_max_size = 60  # Keep history for 5 minutes with 5-second interval
        
        # Adaptive monitoring
        self.adaptive_enabled = True
        self.min_interval = 1.0  # seconds
        self.max_interval = 30.0  # seconds
        
        # Task throttling
        self.throttling_enabled = False
        self.throttle_level = 0  # 0=none, 1=light, 2=moderate, 3=heavy
        
        # Performance metrics
        self.metrics: Dict[str, Dict[str, Any]] = {}
        
        # Initialize metrics for key operations
        self.register_metric("scan_cycle")
        self.register_metric("file_read")
        self.register_metric("process_check")
        self.register_metric("alert_generation")
        
        # Start monitoring thread
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._resource_monitor, daemon=True)
        self.monitor_thread.start()
        
    def register_metric(self, operation_name: str) -> None:
        """
        Register a new performance metric
        
        Args:
            operation_name (str): Name of the operation to track
        """
        self.metrics[operation_name] = {
            "calls": 0,
            "total_time": 0.0,
            "min_time": float("inf"),
            "max_time": 0.0,
            "avg_time": 0.0,
            "last_time": 0.0
        }
    
    def measure_time(self, operation_name: str) -> Callable:
        """
        Decorator to measure execution time of a function
        
        Args:
            operation_name (str): Name of the operation being measured
            
        Returns:
            Callable: Decorated function
        """
        if operation_name not in self.metrics:
            self.register_metric(operation_name)
            
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                
                # Update metrics
                self.metrics[operation_name]["calls"] += 1
                self.metrics[operation_name]["total_time"] += elapsed
                self.metrics[operation_name]["min_time"] = min(
                    self.metrics[operation_name]["min_time"], 
                    elapsed
                )
                self.metrics[operation_name]["max_time"] = max(
                    self.metrics[operation_name]["max_time"], 
                    elapsed
                )
                self.metrics[operation_name]["avg_time"] = (
                    self.metrics[operation_name]["total_time"] / 
                    self.metrics[operation_name]["calls"]
                )
                self.metrics[operation_name]["last_time"] = elapsed
                
                # Log slow operations
                if elapsed > 1.0:  # More than 1 second
                    self.logger.debug(f"Slow operation: {operation_name} took {elapsed:.2f}s")
                    
                return result
            return wrapper
        return decorator
    
    def _resource_monitor(self) -> None:
        """Background thread to monitor resource usage"""
        while self.monitoring_active:
            try:
                # Collect resource usage
                cpu_percent = self.process.cpu_percent(interval=0.1)
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                # Get disk I/O if available
                io_counters = self.process.io_counters() if hasattr(self.process, 'io_counters') else None
                io_mb_s = 0.0
                if io_counters:
                    # Calculate I/O rate from last measurement if we have history
                    if self.resource_history:
                        last_entry = self.resource_history[-1]
                        if 'io_read' in last_entry and 'io_write' in last_entry:
                            io_read_diff = (io_counters.read_bytes - last_entry['io_read']) / 1024 / 1024
                            io_write_diff = (io_counters.write_bytes - last_entry['io_write']) / 1024 / 1024
                            time_diff = time.time() - last_entry['timestamp']
                            if time_diff > 0:
                                io_mb_s = (io_read_diff + io_write_diff) / time_diff
                
                # Save current data
                data = {
                    'timestamp': time.time(),
                    'cpu_percent': cpu_percent,
                    'memory_mb': memory_mb,
                    'io_mb_s': io_mb_s
                }
                
                # Add IO counters if available
                if io_counters:
                    data['io_read'] = io_counters.read_bytes
                    data['io_write'] = io_counters.write_bytes
                
                # Add to history, maintain fixed size
                self.resource_history.append(data)
                if len(self.resource_history) > self.history_max_size:
                    self.resource_history.pop(0)
                
                # Check thresholds and adjust if needed
                self._check_resource_thresholds(cpu_percent, memory_mb, io_mb_s)
                
                # Adjust monitoring interval if adaptive monitoring is enabled
                if self.adaptive_enabled:
                    self._adjust_monitoring_interval()
                
                # Sleep until next check
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in resource monitoring: {str(e)}")
                time.sleep(self.monitoring_interval)
    
    def _check_resource_thresholds(self, cpu_percent: float, memory_mb: float, io_mb_s: float) -> None:
        """Check if resource usage exceeds thresholds and adjust throttling"""
        throttle_needed = False
        
        # Check CPU usage
        if cpu_percent > self.cpu_threshold:
            self.logger.warning(f"High CPU usage: {cpu_percent:.1f}% (threshold: {self.cpu_threshold:.1f}%)")
            throttle_needed = True
            
        # Check memory usage
        if memory_mb > self.memory_threshold:
            self.logger.warning(f"High memory usage: {memory_mb:.1f}MB (threshold: {self.memory_threshold:.1f}MB)")
            throttle_needed = True
            
        # Check I/O usage
        if io_mb_s > self.io_threshold:
            self.logger.warning(f"High I/O usage: {io_mb_s:.1f}MB/s (threshold: {self.io_threshold:.1f}MB/s)")
            throttle_needed = True
            
        # Apply throttling if needed and enabled
        if throttle_needed and self.throttling_enabled:
            if self.throttle_level < 3:
                self.throttle_level += 1
                self.logger.info(f"Increasing throttle level to {self.throttle_level}")
                self._apply_throttling()
        elif self.throttling_enabled and self.throttle_level > 0:
            # Gradually reduce throttling when resource usage is normal
            if self.throttle_level > 0 and cpu_percent < (self.cpu_threshold * 0.7) and \
               memory_mb < (self.memory_threshold * 0.7) and io_mb_s < (self.io_threshold * 0.7):
                self.throttle_level -= 1
                self.logger.info(f"Decreasing throttle level to {self.throttle_level}")
                self._apply_throttling()
    
    def _apply_throttling(self) -> None:
        """Apply the current throttling level to conserve resources"""
        if self.throttle_level == 0:
            # No throttling
            self.logger.debug("Throttling disabled")
            return
            
        # Run garbage collection
        gc.collect()
        
        if self.throttle_level >= 2:
            # More aggressive throttling - reduce memory usage
            self.logger.debug("Applying moderate throttling: clearing caches")
            # Clear any internal caches in your application here
            
        if self.throttle_level >= 3:
            # Most aggressive throttling
            self.logger.debug("Applying heavy throttling: sleep delay")
            time.sleep(0.1)  # Add small delay to reduce CPU usage
    
    def _adjust_monitoring_interval(self) -> None:
        """Adjust monitoring interval based on recent resource usage trends"""
        if not self.resource_history or len(self.resource_history) < 5:
            return
        
        # Get the average CPU and memory usage from recent history
        recent = self.resource_history[-5:]  # Last 5 readings
        avg_cpu = sum(entry['cpu_percent'] for entry in recent) / len(recent)
        avg_memory = sum(entry['memory_mb'] for entry in recent) / len(recent)
        
        # If resources are high, monitor more frequently
        if avg_cpu > (self.cpu_threshold * 0.8) or avg_memory > (self.memory_threshold * 0.8):
            new_interval = max(self.min_interval, self.monitoring_interval / 1.5)
            if new_interval != self.monitoring_interval:
                self.monitoring_interval = new_interval
                self.logger.debug(f"Increased monitoring frequency: interval={new_interval:.1f}s")
        # If resources are consistently low, reduce monitoring frequency
        elif avg_cpu < (self.cpu_threshold * 0.3) and avg_memory < (self.memory_threshold * 0.3):
            new_interval = min(self.max_interval, self.monitoring_interval * 1.5)
            if new_interval != self.monitoring_interval:
                self.monitoring_interval = new_interval
                self.logger.debug(f"Reduced monitoring frequency: interval={new_interval:.1f}s")
    
    def configure(self, 
                  cpu_threshold: Optional[float] = None, 
                  memory_threshold: Optional[float] = None,
                  io_threshold: Optional[float] = None,
                  adaptive_monitoring: Optional[bool] = None,
                  enable_throttling: Optional[bool] = None,
                  min_interval: Optional[float] = None,
                  max_interval: Optional[float] = None) -> None:
        """
        Configure performance optimizer settings
        
        Args:
            cpu_threshold (float, optional): CPU usage threshold percentage
            memory_threshold (float, optional): Memory usage threshold in MB
            io_threshold (float, optional): I/O usage threshold in MB/s
            adaptive_monitoring (bool, optional): Enable/disable adaptive monitoring
            enable_throttling (bool, optional): Enable/disable throttling
            min_interval (float, optional): Minimum monitoring interval in seconds
            max_interval (float, optional): Maximum monitoring interval in seconds
        """
        if cpu_threshold is not None:
            self.cpu_threshold = max(10.0, min(95.0, cpu_threshold))
        if memory_threshold is not None:
            self.memory_threshold = max(50.0, memory_threshold)
        if io_threshold is not None:
            self.io_threshold = max(1.0, io_threshold)
        if adaptive_monitoring is not None:
            self.adaptive_enabled = adaptive_monitoring
        if enable_throttling is not None:
            self.throttling_enabled = enable_throttling
        if min_interval is not None:
            self.min_interval = max(0.5, min(10.0, min_interval))
        if max_interval is not None:
            self.max_interval = max(5.0, min(300.0, max_interval))
            
        self.logger.info("Performance optimizer configured: " + 
                        f"CPU threshold={self.cpu_threshold}%, " +
                        f"memory threshold={self.memory_threshold}MB, " +
                        f"I/O threshold={self.io_threshold}MB/s, " +
                        f"adaptive={self.adaptive_enabled}, " +
                        f"throttling={self.throttling_enabled}")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get a comprehensive performance report
        
        Returns:
            dict: Performance metrics and resource usage history
        """
        # Calculate averages from history
        if self.resource_history:
            avg_cpu = sum(entry['cpu_percent'] for entry in self.resource_history) / len(self.resource_history)
            avg_memory = sum(entry['memory_mb'] for entry in self.resource_history) / len(self.resource_history)
            avg_io = sum(entry['io_mb_s'] for entry in self.resource_history) / len(self.resource_history) \
                     if all('io_mb_s' in entry for entry in self.resource_history) else 0
        else:
            avg_cpu = avg_memory = avg_io = 0
            
        # Current snapshot
        current_cpu = self.process.cpu_percent(interval=0.1)
        current_memory = self.process.memory_info().rss / (1024 * 1024)
        
        return {
            'metrics': self.metrics,
            'resources': {
                'current': {
                    'cpu_percent': current_cpu,
                    'memory_mb': current_memory
                },
                'average': {
                    'cpu_percent': avg_cpu,
                    'memory_mb': avg_memory,
                    'io_mb_s': avg_io
                },
                'thresholds': {
                    'cpu_percent': self.cpu_threshold,
                    'memory_mb': self.memory_threshold,
                    'io_mb_s': self.io_threshold
                },
                'throttling': {
                    'enabled': self.throttling_enabled,
                    'level': self.throttle_level
                },
                'monitoring': {
                    'adaptive': self.adaptive_enabled,
                    'interval': self.monitoring_interval,
                    'min_interval': self.min_interval,
                    'max_interval': self.max_interval
                }
            }
        }
    
    def optimize_memory_usage(self) -> None:
        """
        Optimize memory usage by clearing caches and running garbage collection
        """
        # Force a complete garbage collection
        gc.collect()
        
        # Reset metrics to free some memory
        for metric_name in self.metrics:
            # Keep the structure but reset some data
            self.metrics[metric_name]["min_time"] = min(
                self.metrics[metric_name]["min_time"],
                self.metrics[metric_name]["avg_time"]
            )
        
        # Trim resource history if it's very large
        if len(self.resource_history) > self.history_max_size:
            # Keep only half the history
            half_size = self.history_max_size // 2
            self.resource_history = self.resource_history[-half_size:]
            
        self.logger.info("Memory usage optimized")
        
    def shutdown(self) -> None:
        """
        Shut down the optimizer and its monitoring thread
        """
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
        self.logger.info("Performance optimizer shut down")
