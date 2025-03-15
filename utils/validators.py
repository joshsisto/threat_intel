"""
Validation utilities for threat intelligence indicators.
"""
import re
import logging

logger = logging.getLogger(__name__)

def validate_ip(ip):
    """
    Validate if a string is a proper IP address.
    
    Args:
        ip: The IP address to validate
        
    Returns:
        bool: True if the IP is valid, False otherwise
    """
    try:
        # Basic pattern match first
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return False
        
        # Check each octet
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    except (ValueError, AttributeError):
        return False
        
def validate_domain(domain):
    """
    Validate if a string is a proper domain name.
    
    Args:
        domain: The domain name to validate
        
    Returns:
        bool: True if the domain is valid, False otherwise
    """
    try:
        # Basic domain validation
        if not domain or len(domain) > 255:
            return False
            
        # Check for at least one dot and valid characters
        if "." not in domain:
            return False
            
        # Domain should not be an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            return False
            
        # Check for invalid characters
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return False
            
        return True
    except Exception:
        return False
        
def validate_cidr(cidr):
    """
    Validate if a string is a proper CIDR notation.
    
    Args:
        cidr: The CIDR notation to validate
        
    Returns:
        bool: True if the CIDR notation is valid, False otherwise
    """
    try:
        if not cidr or '/' not in cidr:
            return False
            
        ip_part, prefix_part = cidr.split('/')
        
        # Validate IP part
        if not validate_ip(ip_part):
            return False
            
        # Validate prefix part (must be 0-32)
        prefix = int(prefix_part)
        if prefix < 0 or prefix > 32:
            return False
            
        return True
    except (ValueError, AttributeError):
        return False

def validate_url(url):
    """
    Validate if a string is a proper URL.
    
    Args:
        url: The URL to validate
        
    Returns:
        bool: True if the URL is valid, False otherwise
    """
    try:
        if not url:
            return False
            
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return False
            
        # More specific validation could be added here
        
        return True
    except Exception:
        return False