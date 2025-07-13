#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Log Viewer module for the Acherus Project Management GUI
Provides functionality to view and monitor log files
"""

import os
import glob
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTextEdit, QComboBox, QCheckBox, QGroupBox, QSplitter,
    QFileDialog, QMessageBox, QDialog, QDialogButtonBox
)
from PyQt5.QtGui import QFont, QTextCursor, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

class LogMonitorThread(QThread):
    """Thread for monitoring log file changes"""
    update_signal = pyqtSignal(str)
    
    def __init__(self, log_file):
        super().__init__()
        self.log_file = log_file
        self.running = True
        self.position = 0
    
    def run(self):
        """Run the monitoring loop"""
        try:
            # Initial position
            if os.path.exists(self.log_file):
                self.position = os.path.getsize(self.log_file)
            
            while self.running:
                if not os.path.exists(self.log_file):
                    self.msleep(1000)  # Wait for log file to appear
                    continue
                
                current_size = os.path.getsize(self.log_file)
                
                if current_size > self.position:
                    # Read new data
                    with open(self.log_file, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(self.position)
                        new_data = f.read()
                        if new_data:
                            self.update_signal.emit(new_data)
                    
                    self.position = current_size
                
                self.msleep(500)  # Check every 500ms
                
        except Exception as e:
            self.update_signal.emit(f"[Log Monitoring Error] {str(e)}")
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        self.wait()

class LogViewer(QWidget):
    """Widget for viewing log files"""
    
    def __init__(self, log_dir):
        super().__init__()
        
        self.log_dir = log_dir
        self.current_log_file = None
        self.monitor_thread = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        # Log file selector
        self.log_selector = QComboBox()
        self.log_selector.setMinimumWidth(300)
        self.log_selector.currentIndexChanged.connect(self.change_log_file)
        controls_layout.addWidget(QLabel("Log File:"))
        controls_layout.addWidget(self.log_selector)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_logs)
        controls_layout.addWidget(refresh_btn)
        
        # Live monitoring toggle
        self.live_monitoring = QCheckBox("Live Monitoring")
        self.live_monitoring.setChecked(True)
        self.live_monitoring.stateChanged.connect(self.toggle_monitoring)
        controls_layout.addWidget(self.live_monitoring)
        
        # Clear button
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_log_view)
        controls_layout.addWidget(clear_btn)
        
        # Export button
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_log)
        controls_layout.addWidget(export_btn)
        
        layout.addLayout(controls_layout)
        
        # Log viewer
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        font = QFont("Courier New", 10)
        self.log_text.setFont(font)
        layout.addWidget(self.log_text)
        
        # Status bar
        self.status_label = QLabel("No log file selected")
        layout.addWidget(self.status_label)
        
        # Populate log files
        self.populate_log_files()
    
    def populate_log_files(self):
        """Populate the log file selector with available log files"""
        self.log_selector.clear()
        
        if not os.path.exists(self.log_dir):
            self.status_label.setText(f"Log directory does not exist: {self.log_dir}")
            return
        
        # Find all log files in the directory
        log_files = []
        for extension in ['*.log', '*.txt']:
            log_files.extend(glob.glob(os.path.join(self.log_dir, extension)))
        
        # Add subdirectories
        for subdir in os.listdir(self.log_dir):
            subdir_path = os.path.join(self.log_dir, subdir)
            if os.path.isdir(subdir_path):
                for extension in ['*.log', '*.txt']:
                    log_files.extend(glob.glob(os.path.join(subdir_path, extension)))
        
        # Sort by modification time (newest first)
        log_files.sort(key=os.path.getmtime, reverse=True)
        
        # Add to selector
        for log_file in log_files:
            self.log_selector.addItem(os.path.basename(log_file), log_file)
        
        if log_files:
            self.status_label.setText(f"Found {len(log_files)} log files")
        else:
            self.status_label.setText(f"No log files found in {self.log_dir}")
    
    def change_log_file(self):
        """Change the currently displayed log file"""
        # Stop any existing monitoring thread
        self.stop_monitoring()
        
        # Get the selected log file
        index = self.log_selector.currentIndex()
        if index >= 0:
            self.current_log_file = self.log_selector.itemData(index)
            self.load_log_file()
            
            # Start monitoring if enabled
            if self.live_monitoring.isChecked():
                self.start_monitoring()
    
    def load_log_file(self):
        """Load the current log file into the viewer"""
        if not self.current_log_file or not os.path.exists(self.current_log_file):
            self.log_text.clear()
            self.status_label.setText("Log file does not exist")
            return
        
        try:
            # For large log files, only load the last 500 lines
            if os.path.getsize(self.current_log_file) > 1024 * 1024:  # > 1MB
                # Use tail command if available
                try:
                    result = subprocess.run(
                        ['tail', '-n', '500', self.current_log_file],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    content = result.stdout
                    self.log_text.setText(content)
                    self.status_label.setText(f"Loaded last 500 lines of {os.path.basename(self.current_log_file)}")
                except:
                    # Fall back to Python implementation
                    with open(self.current_log_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.readlines()
                        if len(content) > 500:
                            content = content[-500:]
                        self.log_text.setText(''.join(content))
                        self.status_label.setText(
                            f"Loaded last {min(500, len(content))} lines of {os.path.basename(self.current_log_file)}")
            else:
                # For smaller files, load everything
                with open(self.current_log_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                    self.log_text.setText(content)
                    self.status_label.setText(f"Loaded {os.path.basename(self.current_log_file)}")
            
            # Move cursor to the end
            cursor = self.log_text.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.log_text.setTextCursor(cursor)
            
        except Exception as e:
            self.log_text.setText(f"Error loading log file: {str(e)}")
            self.status_label.setText(f"Error loading {os.path.basename(self.current_log_file)}")
    
    def start_monitoring(self):
        """Start monitoring the current log file for changes"""
        if not self.current_log_file:
            return
        
        self.monitor_thread = LogMonitorThread(self.current_log_file)
        self.monitor_thread.update_signal.connect(self.append_log)
        self.monitor_thread.start()
        
        self.status_label.setText(f"Monitoring {os.path.basename(self.current_log_file)}")
    
    def stop_monitoring(self):
        """Stop monitoring the log file"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.stop()
            self.monitor_thread = None
    
    def toggle_monitoring(self, state):
        """Toggle log monitoring on/off"""
        if state == Qt.Checked:
            self.start_monitoring()
        else:
            self.stop_monitoring()
            self.status_label.setText(f"Monitoring stopped for {os.path.basename(self.current_log_file)}")
    
    def append_log(self, text):
        """Append new text to the log viewer"""
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)
        self.log_text.insertPlainText(text)
        self.log_text.ensureCursorVisible()
    
    def refresh_logs(self):
        """Refresh the log file list and current log"""
        self.populate_log_files()
        
        if self.current_log_file:
            # Find the index of the current log file
            for i in range(self.log_selector.count()):
                if self.log_selector.itemData(i) == self.current_log_file:
                    self.log_selector.setCurrentIndex(i)
                    break
            
            # Reload the current log file
            self.load_log_file()
    
    def clear_log_view(self):
        """Clear the log viewer"""
        self.log_text.clear()
    
    def export_log(self):
        """Export the current log to a file"""
        if not self.current_log_file:
            QMessageBox.warning(self, "Export Error", "No log file selected")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Log",
            f"{os.path.basename(self.current_log_file)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "Log Files (*.log);;Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(self.current_log_file, 'r', encoding='utf-8', errors='replace') as src:
                    with open(filename, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                
                QMessageBox.information(self, "Export Successful", f"Log exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export log: {str(e)}")
    
    def closeEvent(self, event):
        """Handle closing of the widget"""
        self.stop_monitoring()
        super().closeEvent(event)
