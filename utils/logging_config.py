"""
Logging configuration for the threat intelligence application.
"""
import logging
from colorama import init

def setup_logging(log_level=logging.INFO, log_file="threat_intel.log"):
    """
    Configure logging for the application.
    
    Args:
        log_level: The logging level (default: INFO)
        log_file: The log file name (default: "threat_intel.log")
    """
    # Initialize colorama for colored terminal output
    init()

    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    # Reduce logging level for some noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)