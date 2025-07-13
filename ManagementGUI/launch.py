#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Launch script for Acherus Project Management GUI
"""

import sys
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('acherus_manager.log')
    ]
)

try:
    from PyQt5.QtWidgets import QApplication
    from acherus_manager import AcherusManager
except ImportError:
    logging.error("Required packages not found. Please run: pip install -r requirements.txt")
    print("ERROR: Required packages not found. Please run: pip install -r requirements.txt")
    sys.exit(1)

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import psutil
        from PyQt5.QtWebEngineWidgets import QWebEngineView
        return True
    except ImportError as e:
        logging.error(f"Missing dependency: {str(e)}")
        print(f"ERROR: Missing dependency: {str(e)}")
        print("Please run: pip install -r requirements.txt")
        return False

def main():
    """Main entry point for the application"""
    logging.info("Starting Acherus Project Management GUI")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create Qt application
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Create and show main window
    window = AcherusManager()
    window.show()
    
    # Run application
    exit_code = app.exec_()
    logging.info(f"Application exited with code {exit_code}")
    sys.exit(exit_code)

if __name__ == "__main__":
    # Add script directory to path to ensure imports work
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, script_dir)
    
    main()
