"""
Formatting utilities for the threat intelligence application.
"""
import logging

logger = logging.getLogger(__name__)

def format_time_period(seconds):
    """
    Formats seconds into a readable time period.
    
    Args:
        seconds: Number of seconds
        
    Returns:
        str: Formatted time period
    """
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        return f"{seconds // 60} minutes"
    elif seconds < 86400:
        return f"{seconds // 3600} hours"
    else:
        return f"{seconds // 86400} days"