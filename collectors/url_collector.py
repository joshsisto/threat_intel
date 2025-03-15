"""
URL-specific collector for threat intelligence data.
"""
import re
import logging
from colorama import Fore, Style

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)

class UrlCollector(BaseCollector):
    """Collector for URL-based threat feeds."""
    
    def _clean_and_extract(self, source_name, raw_data):
        """
        Extract URL threats from raw data.
        
        Args:
            source_name: Name of the source
            raw_data: Raw data to extract threats from
            
        Returns:
            list: List of tuples (threat_type, threat_value)
        """
        threats = []
        
        if source_name == "urlhaus_text":
            # Process URLhaus text format (contains URLs)
            for match in re.finditer(r"^(https?://\S+)", raw_data, re.MULTILINE):
                url = match.group(1).strip()
                if url:
                    threats.append(("url", url))
                    
        elif source_name == "openphish":
            # Process OpenPhish feed (one URL per line)
            for line in raw_data.splitlines():
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    threats.append(("url", url))
                    
        elif source_name == "vxvault":
            # Process VXVault URL list
            for line in raw_data.splitlines():
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    threats.append(("url", url))
        
        # Log extraction results
        if threats:
            logger.info(f"Extracted {len(threats)} URL indicators from {source_name}")
        else:
            logger.warning(f"No URL threats extracted from {source_name}")
            
        return threats