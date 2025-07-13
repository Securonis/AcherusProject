#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration Editor module for the Acherus Project Management GUI
Provides functionality to view and edit configuration files
"""

import os
import shutil
import tempfile
import subprocess
from datetime import datetime

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTextEdit, QDialogButtonBox, QMessageBox, QCheckBox,
    QFileDialog, QSplitter
)
from PyQt5.QtGui import QFont, QTextCursor, QSyntaxHighlighter, QColor, QTextCharFormat
from PyQt5.QtCore import Qt, QRegExp

class ConfigSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for configuration files"""
    
    def __init__(self, document):
        super().__init__(document)
        
        # Syntax highlighting rules
        self.highlighting_rules = []
        
        # Section headers [section]
        section_format = QTextCharFormat()
        section_format.setForeground(QColor(0, 128, 0))  # Green
        section_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp("\\[.*\\]"), section_format))
        
        # Keys (before =)
        key_format = QTextCharFormat()
        key_format.setForeground(QColor(0, 0, 128))  # Dark blue
        key_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp("^[\\w_]+(?=\\s*=)"), key_format))
        
        # Values (after =)
        value_format = QTextCharFormat()
        value_format.setForeground(QColor(128, 0, 0))  # Dark red
        self.highlighting_rules.append((QRegExp("=\\s*.*$"), value_format))
        
        # Comments (starting with # or ;)
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(128, 128, 128))  # Gray
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((QRegExp("#.*$|;.*$"), comment_format))
        
        # Boolean values
        boolean_format = QTextCharFormat()
        boolean_format.setForeground(QColor(153, 0, 153))  # Purple
        boolean_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp("\\b(true|false|yes|no|on|off)\\b", 
                                              Qt.CaseInsensitive), boolean_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(0, 102, 204))  # Blue
        self.highlighting_rules.append((QRegExp("\\b\\d+\\b"), number_format))
        
    def highlightBlock(self, text):
        """Apply highlighting to the given block of text"""
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

class ConfigEditor(QDialog):
    """Dialog for editing configuration files"""
    
    def __init__(self, config_path, tool_name):
        super().__init__()
        
        self.config_path = config_path
        self.tool_name = tool_name
        self.original_content = ""
        self.has_changes = False
        
        self.setWindowTitle(f"Edit Configuration - {tool_name}")
        self.resize(800, 600)
        
        self.init_ui()
        self.load_config()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel(f"Editing: {os.path.basename(self.config_path)}")
        header_layout.addWidget(header_label)
        
        # Help button
        help_btn = QPushButton("?")
        help_btn.setMaximumWidth(30)
        help_btn.clicked.connect(self.show_help)
        header_layout.addWidget(help_btn)
        
        layout.addLayout(header_layout)
        
        # Editor
        self.editor = QTextEdit()
        font = QFont("Courier New", 10)
        self.editor.setFont(font)
        self.editor.textChanged.connect(self.content_changed)
        
        # Add syntax highlighter
        self.highlighter = ConfigSyntaxHighlighter(self.editor.document())
        
        layout.addWidget(self.editor)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.backup_checkbox = QCheckBox("Create backup before saving")
        self.backup_checkbox.setChecked(True)
        options_layout.addWidget(self.backup_checkbox)
        
        # Add a stretch to push buttons to the right
        options_layout.addStretch()
        
        # Reload button
        reload_btn = QPushButton("Reload")
        reload_btn.clicked.connect(self.reload_config)
        options_layout.addWidget(reload_btn)
        
        layout.addLayout(options_layout)
        
        # Button box
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_config)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Add status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
    
    def load_config(self):
        """Load the configuration file into the editor"""
        try:
            if not os.path.exists(self.config_path):
                self.editor.setText(f"# Configuration file for {self.tool_name}\n# File does not exist: {self.config_path}")
                self.status_label.setText("Warning: Configuration file does not exist")
                return
            
            with open(self.config_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                self.original_content = content
                self.editor.setText(content)
                self.has_changes = False
                self.status_label.setText(f"Loaded configuration from {self.config_path}")
                
        except Exception as e:
            error_msg = f"Error loading configuration: {str(e)}"
            self.editor.setText(f"# ERROR: {error_msg}")
            self.status_label.setText(error_msg)
    
    def save_config(self):
        """Save the edited configuration file"""
        try:
            content = self.editor.toPlainText()
            
            # Check if we actually have changes
            if not self.has_changes:
                self.accept()
                return
            
            # Check if directory exists
            config_dir = os.path.dirname(self.config_path)
            if not os.path.exists(config_dir):
                reply = QMessageBox.question(
                    self,
                    "Directory Not Found",
                    f"The directory {config_dir} does not exist. Would you like to create it?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    os.makedirs(config_dir, exist_ok=True)
                else:
                    return
            
            # Create backup if requested
            if self.backup_checkbox.isChecked() and os.path.exists(self.config_path):
                backup_path = f"{self.config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(self.config_path, backup_path)
                self.status_label.setText(f"Created backup at {backup_path}")
            
            # Write to file
            with open(self.config_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Confirm save
            QMessageBox.information(self, "Configuration Saved", f"Configuration saved to {self.config_path}")
            self.has_changes = False
            self.original_content = content
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save configuration: {str(e)}")
    
    def reload_config(self):
        """Reload the configuration from disk"""
        if self.has_changes:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "You have unsaved changes. Are you sure you want to reload and lose these changes?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.No:
                return
        
        self.load_config()
    
    def content_changed(self):
        """Handle content changes in the editor"""
        current_content = self.editor.toPlainText()
        self.has_changes = current_content != self.original_content
        
        # Update status label
        if self.has_changes:
            self.status_label.setText("Unsaved changes")
        else:
            self.status_label.setText("No changes")
    
    def show_help(self):
        """Show help information for configuration editing"""
        help_text = (
            "<h3>Configuration File Format</h3>"
            "<p>Configuration files use a simple INI-like format with sections and key-value pairs:</p>"
            "<pre>"
            "# This is a comment\n"
            "\n"
            "[section_name]\n"
            "key1 = value1\n"
            "key2 = value2\n"
            "</pre>"
            "<p><b>Syntax Highlighting:</b></p>"
            "<ul>"
            "<li><span style='color: green; font-weight: bold;'>[Sections]</span> - Group related settings</li>"
            "<li><span style='color: navy; font-weight: bold;'>Keys</span> - Configuration parameter names</li>"
            "<li><span style='color: maroon;'>Values</span> - Parameter values</li>"
            "<li><span style='color: gray; font-style: italic;'># Comments</span> - Explanatory notes</li>"
            "<li><span style='color: purple; font-weight: bold;'>true/false</span> - Boolean values</li>"
            "<li><span style='color: blue;'>123</span> - Numeric values</li>"
            "</ul>"
            "<p><b>Tips:</b></p>"
            "<ul>"
            "<li>Don't change section names unless you know what you're doing</li>"
            "<li>Comments start with # or ;</li>"
            "<li>Spaces around the = sign are optional</li>"
            "<li>Boolean values can be true/false, yes/no, or on/off</li>"
            "</ul>"
        )
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Configuration Help")
        msg_box.setText(help_text)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.exec_()
