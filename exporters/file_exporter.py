"""
File exporter for threat intelligence data.
"""
import os
import logging
import datetime
import fnmatch
from colorama import Fore, Style

logger = logging.getLogger(__name__)

class FileExporter:
    """Handles exporting threat data to files."""
    
    def __init__(self, db_manager, export_dir="exports", max_backups=5):
        """
        Initialize the file exporter.
        
        Args:
            db_manager: Database manager instance
            export_dir: Directory for export files
            max_backups: Maximum number of backup files to keep
        """
        self.db_manager = db_manager
        self.export_dir = export_dir
        self.max_backups = max_backups
        
        # Create exports directory if it doesn't exist
        if not os.path.exists(self.export_dir):
            os.makedirs(self.export_dir)
            logger.info(f"Created exports directory: {self.export_dir}")
    
    def export_threat_data(self):
        """
        Exports threat data to master files based on threat type.
        Creates one file each for URLs, domains, IPs, and CIDR ranges,
        with a timestamp header.
        
        Returns:
            dict: Count of threats by type
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create fixed file paths for master files
        url_file = os.path.join(self.export_dir, "urls_master.txt")
        domain_file = os.path.join(self.export_dir, "domains_master.txt")
        ip_file = os.path.join(self.export_dir, "ips_master.txt")
        cidr_file = os.path.join(self.export_dir, "cidrs_master.txt")
        
        # Create a backup of the current master files before overwriting them
        self._create_backups([url_file, domain_file, ip_file, cidr_file])
        
        # Dictionary to track counts
        counts = {
            "url": 0,
            "domain": 0,
            "ip": 0,
            "cidr": 0
        }
        
        # Common header with timestamp and information
        header_template = """# Threat Intelligence Export - {threat_type}
# Generated on: {timestamp}
# Total Count: {count}
# ----------------------------------------------------------
"""
        
        # Export URLs
        urls = self.db_manager.get_threats_by_type("url")
        counts["url"] = len(urls)
        with open(url_file, 'w') as f:
            f.write(header_template.format(
                threat_type="URLs",
                timestamp=timestamp,
                count=counts["url"]
            ))
            for row in urls:
                f.write(f"{row[0]}\n")
        
        # Export domains
        domains = self.db_manager.get_threats_by_type("domain")
        counts["domain"] = len(domains)
        with open(domain_file, 'w') as f:
            f.write(header_template.format(
                threat_type="Domains",
                timestamp=timestamp,
                count=counts["domain"]
            ))
            for row in domains:
                f.write(f"{row[0]}\n")
        
        # Export IPs
        ips = self.db_manager.get_threats_by_type("ip")
        counts["ip"] = len(ips)
        with open(ip_file, 'w') as f:
            f.write(header_template.format(
                threat_type="IP Addresses",
                timestamp=timestamp,
                count=counts["ip"]
            ))
            for row in ips:
                f.write(f"{row[0]}\n")
        
        # Export CIDRs
        cidrs = self.db_manager.get_threats_by_type("cidr")
        counts["cidr"] = len(cidrs)
        with open(cidr_file, 'w') as f:
            f.write(header_template.format(
                threat_type="CIDR Ranges",
                timestamp=timestamp,
                count=counts["cidr"]
            ))
            for row in cidrs:
                f.write(f"{row[0]}\n")
        
        # Log export results
        logger.info(f"{Fore.GREEN}Threat data exported successfully{Style.RESET_ALL}")
        logger.info(f"URLs: {counts['url']} exported to {url_file}")
        logger.info(f"Domains: {counts['domain']} exported to {domain_file}")
        logger.info(f"IPs: {counts['ip']} exported to {ip_file}")
        logger.info(f"CIDRs: {counts['cidr']} exported to {cidr_file}")
        
        return counts

    def _create_backups(self, files):
        """
        Creates backup copies of existing master files before they are overwritten.
        
        Args:
            files: List of file paths to back up
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for file_path in files:
            if not os.path.exists(file_path):
                continue
                
            # Create backup filename
            backup_file = f"{file_path}.{timestamp}.bak"
            
            try:
                # Copy the file
                with open(file_path, 'r') as src:
                    with open(backup_file, 'w') as dst:
                        dst.write(src.read())
                logger.debug(f"Created backup: {backup_file}")
            except Exception as e:
                logger.error(f"Error creating backup of {file_path}: {e}")
        
        # Cleanup old backups
        for file_path in files:
            base_name = os.path.basename(file_path)
            dir_name = os.path.dirname(file_path)
            
            # Find all backup files for this master file
            backup_pattern = f"{base_name}.*.bak"
            backups = []
            
            for filename in os.listdir(dir_name):
                if fnmatch.fnmatch(filename, backup_pattern):
                    full_path = os.path.join(dir_name, filename)
                    backups.append((full_path, os.path.getmtime(full_path)))
            
            # Sort by modification time (newest first)
            backups.sort(key=lambda x: x[1], reverse=True)
            
            # Remove older backups beyond the keep limit
            for backup_path, _ in backups[self.max_backups:]:
                try:
                    os.remove(backup_path)
                    logger.debug(f"Removed old backup: {backup_path}")
                except OSError as e:
                    logger.error(f"Error removing old backup {backup_path}: {e}")