#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tool Status Monitor module for the Acherus Project Management GUI
Monitors and reports the status of security tools
"""

import os
import psutil
import subprocess
import time
from datetime import datetime, timedelta

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtGui import QColor
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer

class ToolStatusThread(QThread):
    """Thread for monitoring tool statuses in the background"""
    update_signal = pyqtSignal(dict)
    
    def __init__(self, tool_info):
        super().__init__()
        self.tool_info = tool_info
        self.running = True
        self.interval = 5  # Check every 5 seconds
    
    def run(self):
        """Run the monitoring thread"""
        while self.running:
            statuses = {}
            
            for tool_id, info in self.tool_info.items():
                status = self.check_tool_status(tool_id, info)
                statuses[tool_id] = status
            
            self.update_signal.emit(statuses)
            time.sleep(self.interval)
    
    def check_tool_status(self, tool_id, info):
        """Check the status of a single tool"""
        status = {
            'active': False,
            'enabled': False,
            'memory': 0,
            'cpu': 0.0,
            'uptime': '',
            'last_log': None
        }
        
        # Check service status using systemctl
        try:
            # Check if active
            active_result = subprocess.run(
                ['systemctl', 'is-active', info['service']],
                capture_output=True,
                text=True
            )
            status['active'] = active_result.stdout.strip() == 'active'
            
            # Check if enabled
            enabled_result = subprocess.run(
                ['systemctl', 'is-enabled', info['service']],
                capture_output=True,
                text=True
            )
            status['enabled'] = enabled_result.stdout.strip() == 'enabled'
            
        except Exception:
            # Might be running on a non-systemd system or without permissions
            pass
        
        # Find process and get resources
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info', 'create_time']):
                cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                if (tool_id in cmdline.lower() or 
                    (info['service'].replace('.service', '') in cmdline.lower())):
                    
                    # Get memory usage in MB
                    mem = proc.info['memory_info'].rss / (1024 * 1024)
                    status['memory'] = round(mem, 1)
                    
                    # Get CPU usage
                    status['cpu'] = round(proc.info['cpu_percent'], 1)
                    
                    # Get uptime
                    create_time = datetime.fromtimestamp(proc.info['create_time'])
                    uptime = datetime.now() - create_time
                    days, remainder = divmod(uptime.total_seconds(), 86400)
                    hours, remainder = divmod(remainder, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    
                    if days > 0:
                        status['uptime'] = f"{int(days)}d {int(hours)}h"
                    elif hours > 0:
                        status['uptime'] = f"{int(hours)}h {int(minutes)}m"
                    else:
                        status['uptime'] = f"{int(minutes)}m {int(seconds)}s"
                    
                    break
        except Exception:
            # Process information might not be accessible
            pass
        
        # Check last log entry
        log_dir = info.get('log_dir')
        if log_dir and os.path.exists(log_dir):
            try:
                # Find the most recent log file
                log_files = []
                for root, dirs, files in os.walk(log_dir):
                    for file in files:
                        if file.endswith(('.log', '.txt')):
                            file_path = os.path.join(root, file)
                            log_files.append((file_path, os.path.getmtime(file_path)))
                
                if log_files:
                    # Sort by modification time (newest first)
                    log_files.sort(key=lambda x: x[1], reverse=True)
                    newest_log = log_files[0][0]
                    
                    # Get the last line of the file
                    last_line = ""
                    with open(newest_log, 'rb') as f:
                        try:
                            f.seek(-2, os.SEEK_END)
                            while f.read(1) != b'\n':
                                f.seek(-2, os.SEEK_CUR)
                            last_line = f.readline().decode('utf-8', errors='replace')
                        except OSError:
                            # File is too small or other issues
                            f.seek(0)
                            last_line = f.readline().decode('utf-8', errors='replace')
                    
                    status['last_log'] = last_line.strip()
            except Exception:
                pass
        
        return status
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        self.wait()

class ToolStatusMonitor(QWidget):
    """Widget for monitoring tool status"""
    
    def __init__(self, tool_info):
        super().__init__()
        
        self.tool_info = tool_info
        self.monitor_thread = None
        
        self.init_ui()
        self.start_monitoring()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Status table
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(6)
        self.status_table.setHorizontalHeaderLabels(["Tool", "Status", "Memory", "CPU", "Uptime", "Last Log"])
        self.status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        
        self.status_table.setRowCount(len(self.tool_info))
        
        # Initialize rows
        row = 0
        for tool_id, info in self.tool_info.items():
            # Tool name
            name_item = QTableWidgetItem(info["name"])
            self.status_table.setItem(row, 0, name_item)
            
            # Status placeholder
            status_item = QTableWidgetItem("Loading...")
            self.status_table.setItem(row, 1, status_item)
            
            # Memory usage placeholder
            memory_item = QTableWidgetItem("--")
            self.status_table.setItem(row, 2, memory_item)
            
            # CPU usage placeholder
            cpu_item = QTableWidgetItem("--")
            self.status_table.setItem(row, 3, cpu_item)
            
            # Uptime placeholder
            uptime_item = QTableWidgetItem("--")
            self.status_table.setItem(row, 4, uptime_item)
            
            # Last log placeholder
            log_item = QTableWidgetItem("--")
            self.status_table.setItem(row, 5, log_item)
            
            row += 1
            
        layout.addWidget(self.status_table)
    
    def start_monitoring(self):
        """Start monitoring thread"""
        self.monitor_thread = ToolStatusThread(self.tool_info)
        self.monitor_thread.update_signal.connect(self.update_status)
        self.monitor_thread.start()
    
    def update_status(self, status_dict):
        """Update the status table with new data"""
        row = 0
        for tool_id, info in self.tool_info.items():
            status = status_dict.get(tool_id, {})
            
            # Update status
            status_text = "Active" if status.get('active', False) else "Inactive"
            if status.get('enabled', False):
                status_text += " (Enabled)"
            else:
                status_text += " (Disabled)"
            
            status_item = self.status_table.item(row, 1)
            status_item.setText(status_text)
            
            # Set color based on status
            if status.get('active', False):
                status_item.setForeground(QColor(0, 128, 0))  # Green
            else:
                status_item.setForeground(QColor(255, 0, 0))  # Red
            
            # Update memory usage
            memory = status.get('memory', 0)
            memory_item = self.status_table.item(row, 2)
            memory_item.setText(f"{memory} MB" if memory > 0 else "--")
            
            # Update CPU usage
            cpu = status.get('cpu', 0)
            cpu_item = self.status_table.item(row, 3)
            cpu_item.setText(f"{cpu}%" if cpu > 0 else "--")
            
            # Update uptime
            uptime = status.get('uptime', '')
            uptime_item = self.status_table.item(row, 4)
            uptime_item.setText(uptime if uptime else "--")
            
            # Update last log
            last_log = status.get('last_log', '')
            log_item = self.status_table.item(row, 5)
            log_item.setText(last_log if last_log else "--")
            
            row += 1
    
    def closeEvent(self, event):
        """Handle closing of the widget"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.stop()
        super().closeEvent(event)
