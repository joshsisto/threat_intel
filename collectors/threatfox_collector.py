"""
ThreatFox-specific collector for threat intelligence data.
"""
import re
import logging
import traceback
from colorama import Fore, Style

from collectors.base_collector import BaseCollector
from utils.validators import validate_ip, validate_domain

logger = logging.getLogger(__name__)

class ThreatfoxCollector(BaseCollector):
    """Collector for ThreatFox feeds."""
    
    def _clean_and_extract(self, source_name, raw_data):
        """
        Extract ThreatFox threats from raw data.
        
        Args:
            source_name: Name of the source
            raw_data: Raw data to extract threats from
            
        Returns:
            list: List of tuples (threat_type, threat_value)
        """
        threats = []
        
        try:
            # Manual CSV parsing for better control
            lines = raw_data.strip().split('\n')
            logger.debug(f"Found {len(lines)} lines in {source_name}")
            
            # Log a few sample lines for debugging
            if lines:
                sample_count = min(3, len(lines))
                logger.debug(f"Sample lines from {source_name}:")
                for i in range(sample_count):
                    logger.debug(f"  Line {i+1}: {lines[i][:100]}...")
            
            for line in lines:
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Manual parsing to handle quoted CSV properly
                fields = []
                current_field = ""
                in_quotes = False
                
                for char in line:
                    if char == '"':
                        in_quotes = not in_quotes
                    elif char == ',' and not in_quotes:
                        fields.append(current_field.strip(' "'))
                        current_field = ""
                    else:
                        current_field += char
                
                # Don't forget the last field
                if current_field:
                    fields.append(current_field.strip(' "'))
                
                # Skip if we don't have enough fields
                if len(fields) < 3:
                    logger.warning(f"Skipping line with insufficient fields: {line[:50]}...")
                    continue
                
                # Extract the indicator (3rd field)
                indicator = fields[2].strip()
                
                if source_name == "threatfox_urls":
                    if indicator and indicator.startswith(('http://', 'https://')):
                        threats.append(("url", indicator))
                
                elif source_name == "threatfox_domains":
                    if indicator and validate_domain(indicator):
                        threats.append(("domain", indicator))
                
                elif source_name == "threatfox_ip_port":
                    if indicator and ":" in indicator:
                        ip_part = indicator.split(":")[0]
                        if validate_ip(ip_part):
                            threats.append(("ip_port", indicator))
                            threats.append(("ip", ip_part))
            
        except Exception as e:
            logger.error(f"Error parsing {source_name} data: {str(e)}")
            logger.error(f"Exception details: {type(e).__name__}")
            logger.error(traceback.format_exc())
    
        # Log extraction results
        if threats:
            count_by_type = {}
            for t_type, _ in threats:
                count_by_type[t_type] = count_by_type.get(t_type, 0) + 1
                
            type_summary = ", ".join([f"{t_type}: {count}" for t_type, count in count_by_type.items()])
            logger.info(f"Extracted {len(threats)} indicators from {source_name} ({type_summary})")
        else:
            logger.warning(f"No threats extracted from {source_name}")
            
        return threats