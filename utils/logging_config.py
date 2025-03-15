"""
Logging configuration for the threat intelligence application.
With automatic log rotation to control file size.
"""
import logging
from logging.handlers import RotatingFileHandler
from colorama import init

def setup_logging(log_level=logging.INFO, log_file="threat_intel.log", max_size_mb=10, backup_count=5):
    """
    Configure logging for the application with log rotation.
    
    Args:
        log_level: The logging level (default: INFO)
        log_file: The log file name (default: "threat_intel.log")
        max_size_mb: Maximum size of the log file in megabytes before rotation (default: 10)
        backup_count: Number of backup files to keep (default: 5)
    """
    # Initialize colorama for colored terminal output
    init()

    # Calculate max bytes (convert MB to bytes)
    max_bytes = max_size_mb * 1024 * 1024
    
    # Configure logging with a rotating file handler
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(
                filename=log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            ),
            logging.StreamHandler()
        ]
    )
    
    # Reduce logging level for some noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)