"""
Base collector class for the threat intelligence application.
"""
import time
import hashlib
import requests
import logging
from colorama import Fore, Style

from utils.normalizers import normalize_value

logger = logging.getLogger(__name__)

class BaseCollector:
    """Base class for all collectors."""
    
    @staticmethod
    def create_collector(source_name):
        """Factory method to create the appropriate collector for a source."""
        # Import here to avoid circular imports
        from collectors.url_collector import UrlCollector
        from collectors.ip_collector import IpCollector
        from collectors.threatfox_collector import ThreatfoxCollector
        
        # URL collectors
        if source_name in ["urlhaus_text", "openphish", "vxvault"]:
            return UrlCollector()
        
        # IP collectors
        elif source_name in ["feodotracker_ipblocklist", "binarydefense", "emergingthreats", 
                           "cinsscore", "elliotech", "stamparm", "mirai"]:
            return IpCollector()
            
        # CIDR collectors (use IpCollector since the processing is similar)
        elif source_name in ["spamhaus_drop", "dshield", "firehol"]:
            return IpCollector()
            
        # ThreatFox collectors
        elif source_name in ["threatfox_urls", "threatfox_domains", "threatfox_ip_port"]:
            return ThreatfoxCollector()
            
        # Default collector if no specific one matches
        return BaseCollector()
    
    def process(self, db_manager, source_id, name, url):
        """
        Process a source.
        
        Args:
            db_manager: Database manager instance
            source_id: ID of the source
            name: Name of the source
            url: URL of the source
            
        Returns:
            int: Number of processed threats, or None if error occurred
        """
        raw_data = self._download_data(url)
        if raw_data is None:
            return None

        data_hash = self._calculate_hash(raw_data)

        # Store raw data, return if it's a duplicate
        is_new_data = db_manager.store_raw_data(source_id, raw_data, data_hash)
        if not is_new_data:
            # Update the last_scan time even if data hasn't changed
            db_manager.update_last_scan(source_id)
            logger.info(f"Finished processing {name} (no changes)")
            return 0

        extraction_start = time.time()
        threats = self._clean_and_extract(name, raw_data)
        extraction_time = time.time() - extraction_start
        logger.info(f"Threat extraction completed in {extraction_time:.2f} seconds")

        # Process and normalize threats
        normalized_threats = []
        for threat_type, threat_value in threats:
            normalized_value = normalize_value(threat_type, threat_value)
            normalized_threats.append((threat_type, normalized_value))

        # Store threats
        processed_count = db_manager.store_threats(normalized_threats, source_id)
        
        # Update last scan time
        db_manager.update_last_scan(source_id)
        
        return processed_count

    def _download_data(self, url):
        """
        Downloads data from a given URL.
        
        Args:
            url: URL to download data from
            
        Returns:
            str: Downloaded data, or None if error occurred
        """
        start_time = time.time()
        try:
            logger.info(f"Downloading data from {url}")
            
            # For ThreatFox CSV downloads, we need to add a User-Agent header
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0',
            }
            
            # Increased timeout for larger files
            response = requests.get(url, timeout=60, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes
            elapsed = time.time() - start_time
            
            # Check the content type to handle CSV files properly
            content_type = response.headers.get('Content-Type', '')
            if 'csv' in content_type or url.endswith('.csv'):
                logger.info(f"Downloaded CSV data - Content-Type: {content_type}")
                # Log first 200 chars of response for debugging
                logger.debug(f"First 200 chars of response: {response.text[:200]}")
            
            logger.info(f"Download completed in {elapsed:.2f} seconds - Size: {len(response.text) // 1024} KB")
            return response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"{Fore.RED}Error downloading data from {url}: {e}{Style.RESET_ALL}")
            return None

    def _calculate_hash(self, data):
        """
        Calculates the SHA-256 hash of the given data.
        
        Args:
            data: Data to hash
            
        Returns:
            str: SHA-256 hash of the data
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _clean_and_extract(self, source_name, raw_data):
        """
        Clean and extract threat data from raw data.
        This is a base implementation that should be overridden by subclasses.
        
        Args:
            source_name: Name of the source
            raw_data: Raw data to extract threats from
            
        Returns:
            list: List of tuples (threat_type, threat_value)
        """
        logger.warning(f"Base _clean_and_extract called for {source_name}. This should be overridden.")
        return []