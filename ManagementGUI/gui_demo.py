#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GUI Demo for Acherus Project Management GUI
This file creates mockups of the GUI for demonstration purposes
"""

import sys
import os
import random
from datetime import datetime, timedelta

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, 
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTextEdit, QComboBox, QCheckBox, QGroupBox, 
    QFormLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QFileDialog, QMessageBox, QAction, QToolBar,
    QStatusBar
)
from PyQt5.QtGui import QFont, QIcon, QPixmap, QTextCursor, QColor, QPalette
from PyQt5.QtCore import Qt, QSize, QTimer

class DemoWindow(QMainWindow):
    """Demo window for Acherus Project Management GUI"""
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Acherus Project Management (DEMO)")
        self.resize(1200, 800)
        
        # Define available security tools and their properties
        self.security_tools = {
            "zombie_hunter": {
                "name": "Zombie Hunter",
                "service": "zombie-hunter.service",
                "config": "/etc/zombie_hunter.conf",
                "log_dir": "/var/log/zombie_hunter",
                "description": "Detects and terminates zombie processes that may indicate compromised applications.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/ZombieHunter",
                "status": "Active",
                "enabled": True,
                "memory": 45.2,
                "cpu": 1.2,
                "uptime": "2d 5h"
            },
            "dynamic_cron_hunter": {
                "name": "Dynamic Cron Hunter",
                "service": "dynamic-cron-hunter.service",
                "config": "/etc/dynamic_cron_hunter.conf",
                "log_dir": "/var/log/dynamic_cron_hunter",
                "description": "Monitors crontab and systemd timer units for suspicious changes.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/DynamicCronHunter",
                "status": "Active",
                "enabled": True,
                "memory": 32.7,
                "cpu": 0.8,
                "uptime": "1d 12h"
            },
            "anomaly_cpu_mem_hunter": {
                "name": "Anomaly CPU/Mem Hunter",
                "service": "anomaly-hunter.service",
                "config": "/etc/anomaly_hunter.conf",
                "log_dir": "/var/log/anomaly_cpu_mem_hunter",
                "description": "Monitors processes for CPU and memory usage anomalies.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/AnomalyCPUMemHunter",
                "status": "Inactive",
                "enabled": False,
                "memory": 0,
                "cpu": 0,
                "uptime": ""
            },
            "binary_integrity_monitor": {
                "name": "Binary Integrity Monitor",
                "service": "binary-integrity-monitor.service",
                "config": "/etc/binary_integrity_monitor.conf",
                "log_dir": "/var/log/binary_integrity_monitor",
                "description": "Monitors critical system binaries for unauthorized modifications.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/BinaryIntegrityMonitor",
                "status": "Active",
                "enabled": True,
                "memory": 58.3,
                "cpu": 1.5,
                "uptime": "5d 7h"
            },
            "seccomp_profile_monitor": {
                "name": "Seccomp Profile Monitor",
                "service": "seccomp-profile-monitor.service",
                "config": "/etc/seccomp_profile_monitor.conf",
                "log_dir": "/var/log/seccomp_profile_monitor",
                "description": "Monitors processes for seccomp profile violations.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/SeccompProfileMonitor",
                "status": "Active",
                "enabled": True,
                "memory": 42.1,
                "cpu": 1.1,
                "uptime": "3d 9h"
            },
            "credential_harvesting_detector": {
                "name": "Credential Harvesting Detector",
                "service": "credential-harvesting-detector.service",
                "config": "/etc/credential_harvesting_detector.conf",
                "log_dir": "/var/log/credential_harvesting_detector",
                "description": "Detects potential credential harvesting in process memory and command lines.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/CredentialHarvestingDetector",
                "status": "Active",
                "enabled": True,
                "memory": 38.6,
                "cpu": 0.9,
                "uptime": "4d 3h"
            },
            "reverse_shell_detector": {
                "name": "Reverse Shell Detector",
                "service": "reverse-shell-detector.service",
                "config": "/etc/reverse_shell_detector.conf",
                "log_dir": "/var/log/reverse_shell_detector",
                "description": "Detects suspicious outbound connections that may indicate reverse shells.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/ReverseShellDetector",
                "status": "Active",
                "enabled": True,
                "memory": 36.2,
                "cpu": 1.3,
                "uptime": "2d 17h"
            },
            "live_config_scanner": {
                "name": "Live Config Scanner",
                "service": "live-config-scanner.service",
                "config": "/etc/live_config_scanner.conf",
                "log_dir": "/var/log/live_config_scanner",
                "description": "Monitors critical configuration files for unauthorized changes.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/LiveConfigScanner",
                "status": "Inactive",
                "enabled": False,
                "memory": 0,
                "cpu": 0,
                "uptime": ""
            }
        }
        
        # Initialize the UI
        self.init_ui()
        
        # Initialize demo data
        self.init_demo_data()
    
    def init_ui(self):
        """Initialize the user interface"""
        # Create central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(self.central_widget)
        
        # Create toolbar
        self.create_toolbar()
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Demo mode - Not connected to real services")
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create dashboard tab
        self.create_dashboard_tab()
        
        # Create individual tool tabs
        for tool_id, tool_info in self.security_tools.items():
            self.create_tool_tab(tool_id, tool_info)
            
        # Create about tab
        self.create_about_tab()
            
    def create_toolbar(self):
        """Create the application toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(32, 32))
        self.addToolBar(Qt.TopToolBarArea, toolbar)
        
        # Refresh status action
        refresh_action = QAction("⟳ Refresh Status", self)
        refresh_action.triggered.connect(self.update_demo_data)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        # Start all services action
        start_all_action = QAction("▶ Start All Services", self)
        start_all_action.triggered.connect(lambda: QMessageBox.information(self, "Demo", "In a real deployment, this would start all services"))
        toolbar.addAction(start_all_action)
        
        # Stop all services action
        stop_all_action = QAction("⏹ Stop All Services", self)
        stop_all_action.triggered.connect(lambda: QMessageBox.information(self, "Demo", "In a real deployment, this would stop all services"))
        toolbar.addAction(stop_all_action)
        
        toolbar.addSeparator()
        
        # Documentation action
        doc_action = QAction("📚 Project Documentation", self)
        doc_action.triggered.connect(lambda: QMessageBox.information(self, "Demo", "In a real deployment, this would open project documentation"))
        toolbar.addAction(doc_action)
        
    def create_dashboard_tab(self):
        """Create the dashboard tab with overview of all tools"""
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_tab)
        
        # Header
        header_label = QLabel("Acherus Security Tools Dashboard")
        header_label.setAlignment(Qt.AlignCenter)
        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        header_label.setFont(font)
        dashboard_layout.addWidget(header_label)
        
        # Status table
        status_table = QTableWidget()
        status_table.setColumnCount(6)
        status_table.setHorizontalHeaderLabels(["Tool", "Status", "Service", "Memory", "CPU", "Actions"])
        status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        status_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        status_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        status_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        status_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        status_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        status_table.setRowCount(len(self.security_tools))
        
        row = 0
        for tool_id, tool_info in self.security_tools.items():
            # Tool name
            name_item = QTableWidgetItem(tool_info["name"])
            status_table.setItem(row, 0, name_item)
            
            # Status placeholder
            status_text = f"{tool_info['status']} ({'Enabled' if tool_info['enabled'] else 'Disabled'})"
            status_item = QTableWidgetItem(status_text)
            if tool_info["status"] == "Active":
                status_item.setForeground(QColor(0, 128, 0))  # Green
            else:
                status_item.setForeground(QColor(255, 0, 0))  # Red
            status_table.setItem(row, 1, status_item)
            
            # Service name
            service_item = QTableWidgetItem(tool_info["service"])
            status_table.setItem(row, 2, service_item)
            
            # Memory usage
            memory_item = QTableWidgetItem(f"{tool_info['memory']} MB" if tool_info['memory'] > 0 else "--")
            status_table.setItem(row, 3, memory_item)
            
            # CPU usage
            cpu_item = QTableWidgetItem(f"{tool_info['cpu']}%" if tool_info['cpu'] > 0 else "--")
            status_table.setItem(row, 4, cpu_item)
            
            # Actions widget
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            
            view_btn = QPushButton("View")
            view_btn.clicked.connect(lambda checked, t=tool_id: self.tab_widget.setCurrentIndex(
                [i for i in range(self.tab_widget.count()) 
                 if self.tab_widget.tabText(i) == self.security_tools[t]["name"]][0]
            ))
            
            actions_layout.addWidget(view_btn)
            status_table.setCellWidget(row, 5, actions_widget)
            
            row += 1
            
        self.status_table = status_table
        dashboard_layout.addWidget(status_table)
        
        self.tab_widget.addTab(dashboard_tab, "Dashboard")
        
    def create_tool_tab(self, tool_id, tool_info):
        """Create a tab for an individual security tool"""
        tool_tab = QWidget()
        tool_layout = QVBoxLayout(tool_tab)
        
        # Header with tool name and description
        header_box = QGroupBox(tool_info["name"])
        header_layout = QVBoxLayout(header_box)
        description_label = QLabel(tool_info["description"])
        description_label.setWordWrap(True)
        header_layout.addWidget(description_label)
        tool_layout.addWidget(header_box)
        
        # Main content area with splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Control panel
        control_panel = QWidget()
        control_layout = QVBoxLayout(control_panel)
        
        # Service control
        service_group = QGroupBox("Service Control")
        service_layout = QVBoxLayout(service_group)
        
        status_text = f"Status: {tool_info['status']} ({'Enabled' if tool_info['enabled'] else 'Disabled'} at boot)"
        status_label = QLabel(status_text)
        service_layout.addWidget(status_label)
        
        button_layout = QHBoxLayout()
        start_btn = QPushButton("Start Service")
        start_btn.clicked.connect(lambda: QMessageBox.information(self, "Demo", f"In a real deployment, this would start {tool_info['service']}"))
        
        stop_btn = QPushButton("Stop Service")
        stop_btn.clicked.connect(lambda: QMessageBox.information(self, "Demo", f"In a real deployment, this would stop {tool_info['service']}"))
        
        restart_btn = QPushButton("Restart Service")
        restart_btn.clicked.connect(lambda: QMessageBox.information(self, "Demo", f"In a real deployment, this would restart {tool_info['service']}"))
        
        button_layout.addWidget(start_btn)
        button_layout.addWidget(stop_btn)
        button_layout.addWidget(restart_btn)
        service_layout.addLayout(button_layout)
        
        enable_layout = QHBoxLayout()
        enable_service = QCheckBox("Enable at Boot")
        enable_service.setChecked(tool_info['enabled'])
        enable_layout.addWidget(enable_service)
        service_layout.addLayout(enable_layout)
        
        control_layout.addWidget(service_group)
        
        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout(config_group)
        
        edit_config_btn = QPushButton("Edit Configuration File")
        edit_config_btn.clicked.connect(lambda: QMessageBox.information(self, "Demo", f"In a real deployment, this would open {tool_info['config']} for editing"))
        config_layout.addWidget(edit_config_btn)
        
        control_layout.addWidget(config_group)
        
        # Documentation
        doc_group = QGroupBox("Documentation")
        doc_layout = QVBoxLayout(doc_group)
        
        view_doc_btn = QPushButton("View Documentation")
        view_doc_btn.clicked.connect(lambda: QMessageBox.information(self, "Demo", f"In a real deployment, this would open {tool_info['doc_url']}"))
        doc_layout.addWidget(view_doc_btn)
        
        doc_layout.addWidget(QLabel("Local path:"))
        local_doc_path = QLabel(f"{tool_id}/README.md")
        local_doc_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        doc_layout.addWidget(local_doc_path)
        
        control_layout.addWidget(doc_group)
        
        # Add stretch to push everything to the top
        control_layout.addStretch()
        
        # Right side: Log viewer
        log_viewer = QWidget()
        log_layout = QVBoxLayout(log_viewer)
        
        # Log controls
        log_controls = QHBoxLayout()
        log_controls.addWidget(QLabel("Log File:"))
        
        log_selector = QComboBox()
        log_selector.addItems([
            f"{tool_id}.log", 
            f"{tool_id}_error.log", 
            f"{tool_id}_debug.log"
        ])
        log_controls.addWidget(log_selector)
        
        refresh_btn = QPushButton("Refresh")
        log_controls.addWidget(refresh_btn)
        
        live_monitoring = QCheckBox("Live Monitoring")
        live_monitoring.setChecked(True)
        log_controls.addWidget(live_monitoring)
        
        clear_btn = QPushButton("Clear")
        log_controls.addWidget(clear_btn)
        
        export_btn = QPushButton("Export")
        log_controls.addWidget(export_btn)
        
        log_layout.addLayout(log_controls)
        
        # Log content
        log_content = QTextEdit()
        log_content.setReadOnly(True)
        font = QFont("Courier New", 10)
        log_content.setFont(font)
        
        # Add some sample log content
        sample_logs = self.generate_sample_logs(tool_id)
        log_content.setText(sample_logs)
        
        log_layout.addWidget(log_content)
        
        # Add to splitter
        splitter.addWidget(control_panel)
        splitter.addWidget(log_viewer)
        
        # Set the initial sizes of the splitter
        splitter.setSizes([300, 700])
        
        tool_layout.addWidget(splitter)
        
        self.tab_widget.addTab(tool_tab, tool_info["name"])
    
    def create_about_tab(self):
        """Create the about tab with project information"""
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        
        # Title
        title_label = QLabel("Acherus Hardening Project")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(title_label)
        
        # Description
        description = QLabel(
            "A comprehensive suite of security monitoring and hardening tools "
            "for Linux environments, specifically designed for Securonis Linux."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(description)
        
        # Author and license
        author_label = QLabel("Author: root0emir")
        author_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(author_label)
        
        license_label = QLabel("License: GNU General Public License v3.0 (GPL-3.0)")
        license_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(license_label)
        
        # Prototype notice
        prototype_label = QLabel("PROTOTYPE NOTICE: This is a prototype implementation that has not been thoroughly tested.")
        prototype_label.setAlignment(Qt.AlignCenter)
        prototype_label.setStyleSheet("color: red; font-weight: bold;")
        about_layout.addWidget(prototype_label)
        
        # Links
        links_group = QGroupBox("Project Links")
        links_layout = QVBoxLayout(links_group)
        
        github_btn = QPushButton("GitHub Repository")
        links_layout.addWidget(github_btn)
        
        about_layout.addWidget(links_group)
        
        # Add stretch at the end
        about_layout.addStretch()
        
        self.tab_widget.addTab(about_tab, "About")
    
    def init_demo_data(self):
        """Initialize demo data for the GUI"""
        # Start a timer to periodically update demo data
        self.demo_timer = QTimer()
        self.demo_timer.timeout.connect(self.update_demo_data)
        self.demo_timer.start(5000)  # Update every 5 seconds
    
    def update_demo_data(self):
        """Update the demo data with new random values"""
        # Update status table on dashboard
        for row in range(self.status_table.rowCount()):
            tool_name = self.status_table.item(row, 0).text()
            tool_id = next(
                (tid for tid, info in self.security_tools.items() if info["name"] == tool_name),
                None
            )
            
            if tool_id and self.security_tools[tool_id]["status"] == "Active":
                # Update CPU usage with small random fluctuations
                cpu = self.security_tools[tool_id]["cpu"] + random.uniform(-0.3, 0.3)
                cpu = max(0.1, min(10.0, cpu))  # Keep within reasonable bounds
                self.security_tools[tool_id]["cpu"] = round(cpu, 1)
                
                # Update memory usage with small random fluctuations
                memory = self.security_tools[tool_id]["memory"] + random.uniform(-1.0, 1.0)
                memory = max(1.0, min(100.0, memory))  # Keep within reasonable bounds
                self.security_tools[tool_id]["memory"] = round(memory, 1)
                
                # Update table items
                memory_item = self.status_table.item(row, 3)
                memory_item.setText(f"{self.security_tools[tool_id]['memory']} MB")
                
                cpu_item = self.status_table.item(row, 4)
                cpu_item.setText(f"{self.security_tools[tool_id]['cpu']}%")
        
        # Update status bar timestamp
        self.statusBar.showMessage(f"Demo mode - Last update: {datetime.now().strftime('%H:%M:%S')}")
    
    def generate_sample_logs(self, tool_id):
        """Generate sample log entries for a tool"""
        logs = []
        
        # Current time for log timestamps
        now = datetime.now()
        
        # Different log entries based on the tool
        if tool_id == "zombie_hunter":
            log_entries = [
                "Starting zombie process detection service",
                "Scanning for zombie processes",
                "Found 0 zombie processes",
                "Monitoring process state changes",
                "Process 1234 (bash) exited normally",
                "Process 2345 (python) exited normally",
                "Process 3456 (httpd) detected as potential zombie",
                "Sending SIGTERM to process 3456 (httpd)",
                "Process 3456 (httpd) terminated successfully",
                "Found 0 zombie processes"
            ]
        elif tool_id == "dynamic_cron_hunter":
            log_entries = [
                "Starting cron and timer monitoring service",
                "Checking crontab for all users",
                "Checking /etc/cron.d directory",
                "Checking systemd timer units",
                "Found new cron job: root /usr/local/bin/backup.sh",
                "Analyzing backup.sh for suspicious patterns",
                "No suspicious patterns found in backup.sh",
                "Timer unit apt-daily.timer modified",
                "Changes to apt-daily.timer verified as legitimate",
                "Monitoring cron and timer changes"
            ]
        elif tool_id == "binary_integrity_monitor":
            log_entries = [
                "Starting binary integrity monitoring service",
                "Loading list of critical system binaries",
                "Computing baseline hashes for 143 binaries",
                "Baseline hashes stored in /var/lib/binary_integrity/baseline.db",
                "Checking integrity of /usr/bin/sudo",
                "All monitored binaries verified successfully",
                "Found modification in /usr/bin/ls",
                "Verified modification is from legitimate system update",
                "Updating baseline for /usr/bin/ls",
                "Continuing binary integrity monitoring"
            ]
        elif tool_id == "seccomp_profile_monitor":
            log_entries = [
                "Starting seccomp profile monitoring service",
                "Loading seccomp profiles",
                "Monitoring seccomp violations",
                "Process 5678 (firefox) attempted syscall outside profile",
                "Analyzing syscall pattern for process 5678",
                "Syscall pattern matches known browser behavior",
                "Adding exception to profile for process 5678",
                "Process 6789 (nginx) attempted syscall outside profile",
                "WARNING: Syscall pattern matches potential exploit attempt",
                "Alerting administrators about potential seccomp violation"
            ]
        else:
            log_entries = [
                f"Starting {tool_id} service",
                f"Loading configuration from /etc/{tool_id}.conf",
                f"Initializing monitoring for {tool_id}",
                f"Detected potential security issue in {tool_id}",
                f"Analyzing data for {tool_id}",
                f"False positive detected, resuming normal operation",
                f"Service {tool_id} running normally",
                f"Periodic status update for {tool_id}",
                f"Memory usage: {random.randint(20, 60)} MB",
                f"CPU usage: {random.uniform(0.5, 2.5):.1f}%"
            ]
        
        # Generate timestamps and format logs
        for i, entry in enumerate(log_entries):
            timestamp = (now - timedelta(minutes=10-i)).strftime("%Y-%m-%d %H:%M:%S")
            logs.append(f"{timestamp} [{tool_id}] {entry}")
        
        return "\n".join(logs)

def create_dark_palette():
    """Create a dark color palette for the application"""
    dark_palette = QPalette()
    
    # Set colors
    dark_color = QColor(45, 45, 45)
    disabled_color = QColor(127, 127, 127)
    text_color = QColor(255, 255, 255)
    highlight_color = QColor(42, 130, 218)
    highlight_text_color = QColor(0, 0, 0)
    link_color = QColor(42, 130, 218)
    
    # Base colors
    dark_palette.setColor(QPalette.Window, dark_color)
    dark_palette.setColor(QPalette.WindowText, text_color)
    dark_palette.setColor(QPalette.Base, QColor(18, 18, 18))
    dark_palette.setColor(QPalette.AlternateBase, dark_color)
    dark_palette.setColor(QPalette.ToolTipBase, text_color)
    dark_palette.setColor(QPalette.ToolTipText, text_color)
    dark_palette.setColor(QPalette.Text, text_color)
    dark_palette.setColor(QPalette.Disabled, QPalette.Text, disabled_color)
    dark_palette.setColor(QPalette.Button, dark_color)
    dark_palette.setColor(QPalette.ButtonText, text_color)
    dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_color)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, link_color)
    dark_palette.setColor(QPalette.Highlight, highlight_color)
    dark_palette.setColor(QPalette.HighlightedText, highlight_text_color)
    
    return dark_palette

def main():
    """Main entry point for the demo application"""
    app = QApplication(sys.argv)
    
    # Apply dark theme style
    app.setStyle("Fusion")
    app.setPalette(create_dark_palette())
    
    # Additional stylesheet for fine-tuning
    app.setStyleSheet("""
    QToolTip { color: #ffffff; background-color: #2a2a2a; border: 1px solid #767676; }
    QTableView { gridline-color: #353535; }
    QTabWidget::pane { border: 1px solid #444; }
    QTabBar::tab { background: #2d2d2d; color: #b1b1b1; padding: 5px; }
    QTabBar::tab:selected { background: #444; color: white; }
    QHeaderView::section { background-color: #2d2d2d; color: white; padding: 5px; }
    QGroupBox { border: 1px solid #444; margin-top: 1.1em; }
    QGroupBox::title { background-color: #2d2d2d; color: white; }
    """)
    
    # Create and show the demo window
    window = DemoWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
