#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acherus Project Management GUI
A central management interface for all Acherus Project security tools

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

import sys
import os
import subprocess
import json
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, 
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTextEdit, QComboBox, QCheckBox, QGroupBox, 
    QFormLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QFileDialog, QMessageBox, QAction, QToolBar,
    QStatusBar, QDialog, QDialogButtonBox, QLineEdit, QScrollArea
)
from PyQt5.QtGui import QFont, QIcon, QPixmap, QTextCursor, QColor, QPalette
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtWebEngineWidgets import QWebEngineView

# Local imports
from service_manager import SystemdServiceManager
from log_viewer import LogViewer
from config_editor import ConfigEditor
from tool_status import ToolStatusMonitor

class AcherusManager(QMainWindow):
    """Main application window for Acherus Project Management"""
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Acherus Project Management")
        self.resize(1200, 800)
        
        # Define available security tools and their properties
        self.security_tools = {
            "zombie_hunter": {
                "name": "Zombie Hunter",
                "service": "zombie-hunter.service",
                "config": "/etc/zombie_hunter.conf",
                "log_dir": "/var/log/zombie_hunter",
                "description": "Detects and terminates zombie processes that may indicate compromised applications.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/ZombieHunter"
            },
            "dynamic_cron_hunter": {
                "name": "Dynamic Cron Hunter",
                "service": "dynamic-cron-hunter.service",
                "config": "/etc/dynamic_cron_hunter.conf",
                "log_dir": "/var/log/dynamic_cron_hunter",
                "description": "Monitors crontab and systemd timer units for suspicious changes.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/DynamicCronHunter"
            },
            "anomaly_cpu_mem_hunter": {
                "name": "Anomaly CPU/Mem Hunter",
                "service": "anomaly-hunter.service",
                "config": "/etc/anomaly_hunter.conf",
                "log_dir": "/var/log/anomaly_cpu_mem_hunter",
                "description": "Monitors processes for CPU and memory usage anomalies.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/AnomalyCPUMemHunter"
            },
            "binary_integrity_monitor": {
                "name": "Binary Integrity Monitor",
                "service": "binary-integrity-monitor.service",
                "config": "/etc/binary_integrity_monitor.conf",
                "log_dir": "/var/log/binary_integrity_monitor",
                "description": "Monitors critical system binaries for unauthorized modifications.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/BinaryIntegrityMonitor"
            },
            "seccomp_profile_monitor": {
                "name": "Seccomp Profile Monitor",
                "service": "seccomp-profile-monitor.service",
                "config": "/etc/seccomp_profile_monitor.conf",
                "log_dir": "/var/log/seccomp_profile_monitor",
                "description": "Monitors processes for seccomp profile violations.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/SeccompProfileMonitor"
            },
            "credential_harvesting_detector": {
                "name": "Credential Harvesting Detector",
                "service": "credential-harvesting-detector.service",
                "config": "/etc/credential_harvesting_detector.conf",
                "log_dir": "/var/log/credential_harvesting_detector",
                "description": "Detects potential credential harvesting in process memory and command lines.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/CredentialHarvestingDetector"
            },
            "reverse_shell_detector": {
                "name": "Reverse Shell Detector",
                "service": "reverse-shell-detector.service",
                "config": "/etc/reverse_shell_detector.conf",
                "log_dir": "/var/log/reverse_shell_detector",
                "description": "Detects suspicious outbound connections that may indicate reverse shells.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/ReverseShellDetector"
            },
            "live_config_scanner": {
                "name": "Live Config Scanner",
                "service": "live-config-scanner.service",
                "config": "/etc/live_config_scanner.conf",
                "log_dir": "/var/log/live_config_scanner",
                "description": "Monitors critical configuration files for unauthorized changes.",
                "doc_url": "https://github.com/Securonis/AcherusProject/tree/main/LiveConfigScanner"
            }
        }
        
        # Initialize service manager
        self.service_manager = SystemdServiceManager()
        
        # Initialize the UI
        self.init_ui()
        
        # Set up timer for periodic status updates
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_all_tool_status)
        self.status_timer.start(10000)  # Update every 10 seconds
        
        # Initial status update
        self.update_all_tool_status()
    
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
        self.statusBar.showMessage("Welcome to Acherus Project Management")
        
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
        refresh_action = QAction(QIcon.fromTheme("view-refresh"), "Refresh Status", self)
        refresh_action.triggered.connect(self.update_all_tool_status)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        # Start all services action
        start_all_action = QAction(QIcon.fromTheme("media-playback-start"), "Start All Services", self)
        start_all_action.triggered.connect(self.start_all_services)
        toolbar.addAction(start_all_action)
        
        # Stop all services action
        stop_all_action = QAction(QIcon.fromTheme("media-playback-stop"), "Stop All Services", self)
        stop_all_action.triggered.connect(self.stop_all_services)
        toolbar.addAction(stop_all_action)
        
        toolbar.addSeparator()
        
        # Documentation action
        doc_action = QAction(QIcon.fromTheme("help-browser"), "Project Documentation", self)
        doc_action.triggered.connect(lambda: self.open_documentation("https://github.com/Securonis/AcherusProject"))
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
        status_table.setColumnCount(4)
        status_table.setHorizontalHeaderLabels(["Tool", "Status", "Service", "Actions"])
        status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        status_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        status_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        status_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        status_table.setRowCount(len(self.security_tools))
        
        row = 0
        for tool_id, tool_info in self.security_tools.items():
            # Tool name
            name_item = QTableWidgetItem(tool_info["name"])
            status_table.setItem(row, 0, name_item)
            
            # Status placeholder
            status_item = QTableWidgetItem("Loading...")
            status_table.setItem(row, 1, status_item)
            
            # Service name
            service_item = QTableWidgetItem(tool_info["service"])
            status_table.setItem(row, 2, service_item)
            
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
            status_table.setCellWidget(row, 3, actions_widget)
            
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
        
        status_label = QLabel("Status: Loading...")
        service_layout.addWidget(status_label)
        
        button_layout = QHBoxLayout()
        start_btn = QPushButton("Start Service")
        start_btn.clicked.connect(lambda: self.toggle_service(tool_id, "start"))
        
        stop_btn = QPushButton("Stop Service")
        stop_btn.clicked.connect(lambda: self.toggle_service(tool_id, "stop"))
        
        restart_btn = QPushButton("Restart Service")
        restart_btn.clicked.connect(lambda: self.toggle_service(tool_id, "restart"))
        
        button_layout.addWidget(start_btn)
        button_layout.addWidget(stop_btn)
        button_layout.addWidget(restart_btn)
        service_layout.addLayout(button_layout)
        
        enable_layout = QHBoxLayout()
        enable_service = QCheckBox("Enable at Boot")
        enable_service.stateChanged.connect(
            lambda state, t=tool_id: self.toggle_service_enable(t, state == Qt.Checked)
        )
        enable_layout.addWidget(enable_service)
        service_layout.addLayout(enable_layout)
        
        control_layout.addWidget(service_group)
        
        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout(config_group)
        
        edit_config_btn = QPushButton("Edit Configuration File")
        edit_config_btn.clicked.connect(lambda: self.edit_config_file(tool_id))
        config_layout.addWidget(edit_config_btn)
        
        control_layout.addWidget(config_group)
        
        # Documentation
        doc_group = QGroupBox("Documentation")
        doc_layout = QVBoxLayout(doc_group)
        
        view_doc_btn = QPushButton("View Documentation")
        view_doc_btn.clicked.connect(lambda: self.open_documentation(tool_info["doc_url"]))
        doc_layout.addWidget(view_doc_btn)
        
        doc_layout.addWidget(QLabel("Local path:"))
        local_doc_path = QLabel(f"{tool_id}/README.md")
        local_doc_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        doc_layout.addWidget(local_doc_path)
        
        control_layout.addWidget(doc_group)
        
        # Add stretch to push everything to the top
        control_layout.addStretch()
        
        # Right side: Log viewer
        log_viewer = LogViewer(tool_info["log_dir"])
        
        # Add to splitter
        splitter.addWidget(control_panel)
        splitter.addWidget(log_viewer)
        
        # Set the initial sizes of the splitter
        splitter.setSizes([300, 700])
        
        tool_layout.addWidget(splitter)
        
        # Store important widgets for later access
        tool_tab.status_label = status_label
        tool_tab.enable_checkbox = enable_service
        tool_tab.log_viewer = log_viewer
        
        self.tab_widget.addTab(tool_tab, tool_info["name"])
    
    def create_about_tab(self):
        """Create the about tab with project information"""
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        
        # Create scrollable area for content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        about_layout.addWidget(scroll_area)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Title
        title_label = QLabel("Acherus Hardening Project")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        scroll_layout.addWidget(title_label)
        
        # Description
        description = QLabel(
            "A comprehensive suite of security monitoring and hardening tools "
            "for Linux environments, specifically designed for Securonis Linux."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        scroll_layout.addWidget(description)
        
        # Links
        links_group = QGroupBox("Project Links")
        links_layout = QVBoxLayout(links_group)
        
        github_btn = QPushButton("GitHub Repository")
        github_btn.clicked.connect(lambda: self.open_documentation("https://github.com/Securonis/AcherusProject"))
        links_layout.addWidget(github_btn)
        
        scroll_layout.addWidget(links_group)
        
        # Tool overview
        tools_group = QGroupBox("Security Tools Overview")
        tools_layout = QVBoxLayout(tools_group)
        
        for tool_id, tool_info in self.security_tools.items():
            tool_box = QGroupBox(tool_info["name"])
            tool_box_layout = QVBoxLayout(tool_box)
            
            desc_label = QLabel(tool_info["description"])
            desc_label.setWordWrap(True)
            tool_box_layout.addWidget(desc_label)
            
            link_btn = QPushButton("View Documentation")
            link_btn.clicked.connect(lambda checked, url=tool_info["doc_url"]: self.open_documentation(url))
            tool_box_layout.addWidget(link_btn)
            
            tools_layout.addWidget(tool_box)
        
        scroll_layout.addWidget(tools_group)
        
        # Add stretch at the end
        scroll_layout.addStretch()
        
        # Set the scroll content
        scroll_area.setWidget(scroll_content)
        
        self.tab_widget.addTab(about_tab, "About")
        
    def update_all_tool_status(self):
        """Update the status of all tools"""
        # Update dashboard
        for row in range(self.status_table.rowCount()):
            tool_name = self.status_table.item(row, 0).text()
            tool_id = next(
                (tid for tid, info in self.security_tools.items() if info["name"] == tool_name),
                None
            )
            
            if tool_id:
                service_name = self.security_tools[tool_id]["service"]
                active = self.service_manager.is_service_active(service_name)
                enabled = self.service_manager.is_service_enabled(service_name)
                
                status_text = "Active" if active else "Inactive"
                if enabled:
                    status_text += " (Enabled)"
                else:
                    status_text += " (Disabled)"
                
                status_item = self.status_table.item(row, 1)
                status_item.setText(status_text)
                
                # Set color based on status
                if active:
                    status_item.setForeground(QColor(0, 128, 0))  # Green
                else:
                    status_item.setForeground(QColor(255, 0, 0))  # Red
        
        # Update individual tool tabs
        for i in range(1, self.tab_widget.count() - 1):  # Skip dashboard and about tabs
            tab = self.tab_widget.widget(i)
            tool_name = self.tab_widget.tabText(i)
            tool_id = next(
                (tid for tid, info in self.security_tools.items() if info["name"] == tool_name),
                None
            )
            
            if tool_id and hasattr(tab, "status_label"):
                service_name = self.security_tools[tool_id]["service"]
                active = self.service_manager.is_service_active(service_name)
                enabled = self.service_manager.is_service_enabled(service_name)
                
                status_text = f"Status: {'Active' if active else 'Inactive'} "
                status_text += f"({'Enabled' if enabled else 'Disabled'} at boot)"
                
                tab.status_label.setText(status_text)
                
                if hasattr(tab, "enable_checkbox"):
                    tab.enable_checkbox.setChecked(enabled)
                    
        self.statusBar.showMessage(f"Status updated at {QTime.currentTime().toString('hh:mm:ss')}")
    
    def toggle_service(self, tool_id, action):
        """Toggle the service status (start/stop/restart)"""
        if tool_id in self.security_tools:
            service_name = self.security_tools[tool_id]["service"]
            
            try:
                if action == "start":
                    self.service_manager.start_service(service_name)
                    QMessageBox.information(self, "Service Control", f"Service {service_name} started successfully")
                elif action == "stop":
                    self.service_manager.stop_service(service_name)
                    QMessageBox.information(self, "Service Control", f"Service {service_name} stopped successfully")
                elif action == "restart":
                    self.service_manager.restart_service(service_name)
                    QMessageBox.information(self, "Service Control", f"Service {service_name} restarted successfully")
                
                # Update status after a short delay to allow service to change state
                QTimer.singleShot(1000, self.update_all_tool_status)
                
            except Exception as e:
                QMessageBox.critical(self, "Service Control Error", f"Failed to {action} {service_name}: {str(e)}")
    
    def toggle_service_enable(self, tool_id, enable):
        """Enable or disable service at boot"""
        if tool_id in self.security_tools:
            service_name = self.security_tools[tool_id]["service"]
            
            try:
                if enable:
                    self.service_manager.enable_service(service_name)
                    QMessageBox.information(self, "Service Control", f"Service {service_name} enabled at boot")
                else:
                    self.service_manager.disable_service(service_name)
                    QMessageBox.information(self, "Service Control", f"Service {service_name} disabled at boot")
                
                self.update_all_tool_status()
                
            except Exception as e:
                QMessageBox.critical(self, "Service Control Error", 
                                    f"Failed to {'enable' if enable else 'disable'} {service_name}: {str(e)}")
    
    def edit_config_file(self, tool_id):
        """Open the configuration file for editing"""
        if tool_id in self.security_tools:
            config_path = self.security_tools[tool_id]["config"]
            
            try:
                config_editor = ConfigEditor(config_path, self.security_tools[tool_id]["name"])
                config_editor.exec_()
                
            except Exception as e:
                QMessageBox.critical(self, "Configuration Edit Error", f"Failed to open configuration: {str(e)}")
    
    def open_documentation(self, url):
        """Open documentation in a web browser window"""
        try:
            # Create a dialog with web view
            doc_dialog = QDialog(self)
            doc_dialog.setWindowTitle("Documentation Viewer")
            doc_dialog.resize(900, 700)
            
            layout = QVBoxLayout(doc_dialog)
            
            # Web view for documentation
            web_view = QWebEngineView()
            web_view.load(QUrl(url))
            layout.addWidget(web_view)
            
            # Buttons
            button_box = QDialogButtonBox(QDialogButtonBox.Close)
            button_box.rejected.connect(doc_dialog.reject)
            layout.addWidget(button_box)
            
            doc_dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self, "Documentation Error", f"Failed to open documentation: {str(e)}")
    
    def start_all_services(self):
        """Start all security tool services"""
        for tool_id, tool_info in self.security_tools.items():
            try:
                self.service_manager.start_service(tool_info["service"])
            except Exception as e:
                QMessageBox.warning(self, "Service Control Warning", 
                                   f"Failed to start {tool_info['name']}: {str(e)}")
        
        # Update status after a short delay
        QTimer.singleShot(1000, self.update_all_tool_status)
        QMessageBox.information(self, "Service Control", "Started all services")
    
    def stop_all_services(self):
        """Stop all security tool services"""
        # Ask for confirmation
        reply = QMessageBox.question(
            self, "Confirm Action",
            "Are you sure you want to stop all security services?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            for tool_id, tool_info in self.security_tools.items():
                try:
                    self.service_manager.stop_service(tool_info["service"])
                except Exception as e:
                    QMessageBox.warning(self, "Service Control Warning", 
                                      f"Failed to stop {tool_info['name']}: {str(e)}")

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
    """Main entry point for the application"""
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
    QTextEdit { background-color: #1e1e1e; color: #e0e0e0; }
    QPlainTextEdit { background-color: #1e1e1e; color: #e0e0e0; }
    """)
    
    # Create and show the main window
    window = AcherusManager()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
