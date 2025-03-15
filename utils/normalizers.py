"""
Normalization utilities for threat intelligence indicators.
"""
import logging

logger = logging.getLogger(__name__)

def normalize_value(threat_type, value):
    """
    Normalizes threat values to prevent duplicates with different formatting.
    
    Args:
        threat_type: The type of threat ("url", "domain", "ip", "ip_port", "cidr")
        value: The value to normalize
        
    Returns:
        str: The normalized value
    """
    normalized = value.strip()
    
    if threat_type == "url":
        # Normalize URLs
        normalized = normalized.lower()
        # Remove trailing slashes
        if normalized.endswith('/'):
            normalized = normalized[:-1]
        # Ensure http:// prefix for consistency
        if not normalized.startswith(('http://', 'https://')):
            normalized = 'http://' + normalized
    
    elif threat_type == "domain":
        # Normalize domains
        normalized = normalized.lower()
        # Remove any trailing dots
        if normalized.endswith('.'):
            normalized = normalized[:-1]
        # Remove any www. prefix
        if normalized.startswith('www.'):
            normalized = normalized[4:]
    
    elif threat_type == "ip" or threat_type == "ip_port":
        # For IPs, just strip and lowercase
        normalized = normalized.lower()
    
    elif threat_type == "cidr":
        # Normalize CIDR notation
        normalized = normalized.lower()
        
    return normalized