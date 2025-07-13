#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acherus Project - Service Activator Module
Copyright (C) 2025 root0emir
License: GNU GPL version 3 or later; see LICENSE file for details

PROTOTYPE STATUS: This is a prototype tool with limited testing.
Use at your own risk and test thoroughly before deploying in production.
"""

import os
import time
import logging
import threading
import subprocess
from typing import Dict, List, Optional, Any, Callable, Set

class ServiceActivator:
    """
    A utility class to manage on-demand service activation for Acherus Project tools.
    Allows services to be activated only when needed based on configurable triggers
    and conditions, saving system resources.
    """
    
    def __init__(self, service_name: str):
        """
        Initialize the service activator
        
        Args:
            service_name (str): Name of the service using this activator
        """
        self.service_name = service_name
        self.logger = logging.getLogger(f"{service_name}.activator")
        
        # Trigger settings
        self.activation_enabled = False
        self.activation_mode = 'manual'  # 'manual', 'scheduled', 'event', 'threshold'
        self.activation_schedule = []  # List of time specifications for scheduled activation
        self.event_triggers: Dict[str, Dict[str, Any]] = {}  # Event-based triggers
        self.threshold_triggers: Dict[str, Dict[str, Any]] = {}  # Threshold-based triggers
        
        # Active/inactive settings
        self.active_duration = 3600  # How long to stay active after triggered (seconds)
        self.inactive_functions: List[Callable] = []  # Functions to call when inactive
        self.active_functions: List[Callable] = []  # Functions to call when active
        
        # Current state
        self.is_active = False
        self.last_activation_time = 0
        self.activation_count = 0
        self.monitored_values: Dict[str, Any] = {}
        
        # Activation thread
        self.activation_thread = None
        self.activation_thread_running = False
        
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the service activator from a dictionary
        
        Args:
            config (dict): Configuration dictionary
        """
        if 'enabled' in config:
            self.activation_enabled = bool(config['enabled'])
            
        if 'mode' in config:
            mode = config['mode']
            if mode in ('manual', 'scheduled', 'event', 'threshold'):
                self.activation_mode = mode
            else:
                self.logger.warning(f"Invalid activation mode '{mode}', using 'manual'")
                self.activation_mode = 'manual'
                
        if 'active_duration' in config:
            try:
                self.active_duration = int(config['active_duration'])
            except (ValueError, TypeError):
                self.logger.warning(f"Invalid active_duration '{config['active_duration']}', using 3600 seconds")
                
        if 'schedule' in config and isinstance(config['schedule'], list):
            self.activation_schedule = config['schedule']
            
        if 'event_triggers' in config and isinstance(config['event_triggers'], dict):
            self.event_triggers = config['event_triggers']
            
        if 'threshold_triggers' in config and isinstance(config['threshold_triggers'], dict):
            self.threshold_triggers = config['threshold_triggers']
            
        self.logger.info(f"Configured service activator: mode={self.activation_mode}, enabled={self.activation_enabled}")
        
        # Start activation thread if needed
        if self.activation_enabled and not self.activation_thread_running:
            self._start_activation_thread()
    
    def register_inactive_function(self, func: Callable) -> None:
        """
        Register a function to be called when service becomes inactive
        
        Args:
            func (callable): Function to call when inactive
        """
        self.inactive_functions.append(func)
        self.logger.debug(f"Registered inactive function: {func.__name__}")
    
    def register_active_function(self, func: Callable) -> None:
        """
        Register a function to be called when service becomes active
        
        Args:
            func (callable): Function to call when active
        """
        self.active_functions.append(func)
        self.logger.debug(f"Registered active function: {func.__name__}")
    
    def activate(self, reason: str = "manual") -> bool:
        """
        Activate the service
        
        Args:
            reason (str): Reason for activation
            
        Returns:
            bool: True if activated, False otherwise
        """
        if not self.activation_enabled:
            self.logger.info(f"Activation requested but not enabled: {reason}")
            return False
            
        self.is_active = True
        self.last_activation_time = time.time()
        self.activation_count += 1
        self.logger.info(f"Service activated: {reason}")
        
        # Call active functions
        for func in self.active_functions:
            try:
                func()
            except Exception as e:
                self.logger.error(f"Error in active function {func.__name__}: {str(e)}")
                
        return True
    
    def deactivate(self, reason: str = "manual") -> bool:
        """
        Deactivate the service
        
        Args:
            reason (str): Reason for deactivation
            
        Returns:
            bool: True if deactivated, False otherwise
        """
        if not self.is_active:
            return False
            
        self.is_active = False
        self.logger.info(f"Service deactivated: {reason}")
        
        # Call inactive functions
        for func in self.inactive_functions:
            try:
                func()
            except Exception as e:
                self.logger.error(f"Error in inactive function {func.__name__}: {str(e)}")
                
        return True
    
    def update_monitored_value(self, name: str, value: Any) -> None:
        """
        Update a monitored value that may trigger activation
        
        Args:
            name (str): Name of the value
            value (any): New value
        """
        self.monitored_values[name] = value
        
        # Check if this should trigger activation
        if self.activation_enabled and self.activation_mode == 'threshold':
            self._check_threshold_triggers()
    
    def trigger_event(self, event_name: str, event_data: Any = None) -> bool:
        """
        Trigger an event that may activate the service
        
        Args:
            event_name (str): Name of the event
            event_data (any): Event data
            
        Returns:
            bool: True if event triggered activation, False otherwise
        """
        if not self.activation_enabled:
            return False
            
        if self.activation_mode != 'event':
            self.logger.debug(f"Event '{event_name}' ignored: activation mode is not 'event'")
            return False
            
        # Check if this event should trigger activation
        if event_name in self.event_triggers:
            trigger_config = self.event_triggers[event_name]
            
            # Check if the trigger is enabled
            if not trigger_config.get('enabled', True):
                return False
                
            # Check any conditions if specified
            if 'condition' in trigger_config and callable(trigger_config['condition']):
                if not trigger_config['condition'](event_data):
                    return False
                    
            # Trigger activation
            return self.activate(f"event:{event_name}")
            
        return False
    
    def _check_threshold_triggers(self) -> bool:
        """
        Check all threshold triggers against current monitored values
        
        Returns:
            bool: True if any trigger activated the service, False otherwise
        """
        for name, trigger in self.threshold_triggers.items():
            # Skip disabled triggers
            if not trigger.get('enabled', True):
                continue
                
            # Check if the monitored value exists
            if trigger['value_name'] not in self.monitored_values:
                continue
                
            current_value = self.monitored_values[trigger['value_name']]
            threshold = trigger['threshold']
            operator = trigger.get('operator', '>')
            
            # Compare using the specified operator
            trigger_activated = False
            
            if operator == '>' and current_value > threshold:
                trigger_activated = True
            elif operator == '>=' and current_value >= threshold:
                trigger_activated = True
            elif operator == '<' and current_value < threshold:
                trigger_activated = True
            elif operator == '<=' and current_value <= threshold:
                trigger_activated = True
            elif operator == '==' and current_value == threshold:
                trigger_activated = True
            elif operator == '!=' and current_value != threshold:
                trigger_activated = True
                
            if trigger_activated:
                return self.activate(f"threshold:{name}")
                
        return False
    
    def _check_scheduled_activation(self) -> bool:
        """
        Check if service should be activated based on schedule
        
        Returns:
            bool: True if schedule triggered activation, False otherwise
        """
        if not self.activation_schedule:
            return False
            
        import datetime
        
        now = datetime.datetime.now()
        current_time = now.strftime("%H:%M")
        current_day = now.strftime("%A").lower()
        current_date = now.strftime("%Y-%m-%d")
        
        for schedule in self.activation_schedule:
            # Skip disabled schedules
            if not schedule.get('enabled', True):
                continue
                
            # Check time
            if 'time' in schedule and schedule['time'] != current_time:
                continue
                
            # Check day of week
            if 'day' in schedule and schedule['day'].lower() != current_day:
                continue
                
            # Check date
            if 'date' in schedule and schedule['date'] != current_date:
                continue
                
            # All conditions met
            return self.activate(f"schedule:{schedule.get('name', 'unnamed')}")
            
        return False
    
    def _start_activation_thread(self) -> None:
        """Start the background thread for monitoring activation conditions"""
        if self.activation_thread_running:
            return
            
        self.activation_thread_running = True
        self.activation_thread = threading.Thread(target=self._activation_monitor, daemon=True)
        self.activation_thread.start()
        self.logger.debug("Started activation monitoring thread")
    
    def _activation_monitor(self) -> None:
        """Background thread to monitor activation conditions"""
        check_interval = 60  # Check schedule every minute
        
        while self.activation_thread_running:
            try:
                # Check if service should be activated based on mode
                if self.activation_enabled and not self.is_active:
                    if self.activation_mode == 'scheduled':
                        self._check_scheduled_activation()
                        
                # Check if service should stay active
                if self.is_active:
                    # Check if active duration has elapsed
                    elapsed = time.time() - self.last_activation_time
                    if elapsed > self.active_duration:
                        self.deactivate("duration expired")
                        
                # Sleep for a bit
                time.sleep(check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in activation monitor: {str(e)}")
                time.sleep(check_interval)
    
    def shutdown(self) -> None:
        """Shut down the activator and its monitoring thread"""
        self.activation_thread_running = False
        if self.is_active:
            self.deactivate("shutdown")
        if self.activation_thread and self.activation_thread.is_alive():
            self.activation_thread.join(timeout=2.0)
        self.logger.info("Service activator shut down")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the service activator
        
        Returns:
            dict: Current status
        """
        return {
            'enabled': self.activation_enabled,
            'mode': self.activation_mode,
            'is_active': self.is_active,
            'last_activation_time': self.last_activation_time,
            'activation_count': self.activation_count,
            'active_duration': self.active_duration,
            'time_remaining': int(self.active_duration - (time.time() - self.last_activation_time))
                             if self.is_active else 0
        }
