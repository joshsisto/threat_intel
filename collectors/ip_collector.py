"""
IP and CIDR-specific collector for threat intelligence data.
"""
import re
import logging
from colorama import Fore, Style

from collectors.base_collector import BaseCollector
from utils.validators import validate_ip, validate_cidr

logger = logging.getLogger(__name__)

class IpCollector(BaseCollector):
    """Collector for IP and CIDR-based threat feeds."""
    
    def _clean_and_extract(self, source_name, raw_data):
        """
        Extract IP and CIDR threats from raw data.
        
        Args:
            source_name: Name of the source
            raw_data: Raw data to extract threats from
            
        Returns:
            list: List of tuples (threat_type, threat_value)
        """
        threats = []
        
        # IP feeds
        if source_name in ["feodotracker_ipblocklist", "binarydefense", "emergingthreats", 
                          "cinsscore", "elliotech", "stamparm", "mirai"]:
            # Process various IP blocklists (one IP per line)
            for line in raw_data.splitlines():
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith(('#', '//', ';')):
                    continue
                
                # Extract the first IP from the line
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if ip_match:
                    ip = ip_match.group(1)
                    if validate_ip(ip):
                        threats.append(("ip", ip))
        
        # IP CIDR feeds
        elif source_name in ["spamhaus_drop", "dshield", "firehol"]:
            # Process CIDR notation lists
            for line in raw_data.splitlines():
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith(('#', '//', ';')):
                    continue
                
                # Match CIDR notation (e.g., 192.168.1.0/24)
                cidr_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line)
                if cidr_match:
                    cidr = cidr_match.group(1)
                    if validate_cidr(cidr):
                        threats.append(("cidr", cidr))
        
        # Log extraction results
        if threats:
            count_by_type = {}
            for t_type, _ in threats:
                count_by_type[t_type] = count_by_type.get(t_type, 0) + 1
                
            type_summary = ", ".join([f"{t_type}: {count}" for t_type, count in count_by_type.items()])
            logger.info(f"Extracted {len(threats)} indicators from {source_name} ({type_summary})")
        else:
            logger.warning(f"No IP/CIDR threats extracted from {source_name}")
            
        return threats