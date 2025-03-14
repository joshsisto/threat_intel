import requests
import time
import sqlite3
import schedule
import datetime
import hashlib
import re
import logging
import csv
import traceback
import os
from io import StringIO
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("threat_intel.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IntelligenceFeedApp:

    def __init__(self, db_name="threat_intel.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.conn.execute("PRAGMA journal_mode=WAL;")  # Enable WAL mode
        self.conn.execute("PRAGMA synchronous=NORMAL;")  # Slightly faster operation while maintaining data integrity
        
        # Configure logging level
        logging.getLogger().setLevel(logging.DEBUG)  # Set to DEBUG for more verbose logging
        
        # Create exports directory if it doesn't exist
        self.export_dir = "exports"
        if not os.path.exists(self.export_dir):
            os.makedirs(self.export_dir)
            logger.info(f"Created exports directory: {self.export_dir}")
        
        self.create_tables()
        
        # Run deduplication on startup
        self.deduplicate_threats()
        
        self.start_time = datetime.datetime.now()
        logger.info(f"{Fore.GREEN}Threat Intelligence Feed Application started{Style.RESET_ALL}")
        logger.info(f"Database initialized: {self.db_name}")


    def create_tables(self):
        """Creates the necessary database tables."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                url TEXT,
                frequency INTEGER,  -- Scan frequency in seconds
                last_scan TIMESTAMP
            )
        """)

        # Modified threat table definition with proper uniqueness constraint
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                threat_type TEXT,  -- e.g., "url", "domain", "ip", "ip_port", "cidr"
                value TEXT,      -- The actual threat data (URL, domain, IP, IP:port, CIDR)
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                UNIQUE(threat_type, value) ON CONFLICT REPLACE,  -- Changed from IGNORE to REPLACE
                FOREIGN KEY (source_id) REFERENCES sources (id)
            )
        """)

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                raw_content TEXT,
                hash TEXT UNIQUE,  -- Hash of the raw content to prevent duplicate raw data entries
                timestamp TIMESTAMP,
                FOREIGN KEY (source_id) REFERENCES sources(id)
            )
        """)
        # --- Add Indexes ---
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_source_type_value ON threats (source_id, threat_type, value)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_value ON threats (value)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_data_hash ON raw_data (hash)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_type ON threats (threat_type)")

        self.conn.commit()
        logger.info("Database tables created or verified")

    def deduplicate_threats(self):
        """Removes duplicate entries from the threats table by keeping only the most recent entry."""
        logger.info(f"{Fore.YELLOW}Starting deduplication of threats table...{Style.RESET_ALL}")
        
        # Create a temporary table to store unique threat entries
        self.cursor.execute("""
            CREATE TEMPORARY TABLE threats_dedup AS
            SELECT MAX(id) as id, threat_type, value, MAX(last_seen) as last_seen
            FROM threats
            GROUP BY threat_type, value
        """)
        
        # Count how many duplicates will be removed
        self.cursor.execute("""
            SELECT COUNT(*) FROM threats
            WHERE id NOT IN (SELECT id FROM threats_dedup)
        """)
        duplicate_count = self.cursor.fetchone()[0]
        
        if duplicate_count > 0:
            logger.info(f"{Fore.GREEN}Found {duplicate_count} duplicate threat entries to remove{Style.RESET_ALL}")
            
            # Delete duplicates
            self.cursor.execute("""
                DELETE FROM threats
                WHERE id NOT IN (SELECT id FROM threats_dedup)
            """)
            
            self.conn.commit()
            logger.info(f"{Fore.GREEN}Successfully removed {duplicate_count} duplicate threat entries{Style.RESET_ALL}")
        else:
            logger.info("No duplicate threats found")
        
        # Drop the temporary table
        self.cursor.execute("DROP TABLE threats_dedup")
        self.conn.commit()

    def add_source(self, name, url, frequency):
        """Adds a new intelligence source to the database."""
        try:
            self.cursor.execute("""
                INSERT INTO sources (name, url, frequency, last_scan)
                VALUES (?, ?, ?, ?)
            """, (name, url, frequency, None))  # Initialize last_scan to None
            self.conn.commit()
            logger.info(f"Added source: {Fore.CYAN}{name}{Style.RESET_ALL} - Frequency: {self._format_time_period(frequency)}")
        except sqlite3.IntegrityError:
            logger.warning(f"Source '{name}' already exists - skipping")

    def _format_time_period(self, seconds):
        """Formats seconds into a readable time period."""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            return f"{seconds // 60} minutes"
        elif seconds < 86400:
            return f"{seconds // 3600} hours"
        else:
            return f"{seconds // 86400} days"

    def _download_data(self, url):
        """Downloads data from a given URL."""
        start_time = time.time()
        try:
            logger.info(f"Downloading data from {url}")
            
            # For ThreatFox CSV downloads, we need to add a User-Agent header
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0',
            }
            
            # Some ThreatFox endpoints might need authentication in the future
            response = requests.get(url, timeout=60, headers=headers)  # Increased timeout for larger files
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
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
        """Calculates the SHA-256 hash of the given data."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _clean_and_extract(self, source_name, raw_data):
        """Cleans and extracts threat data based on the source, optimized."""
        threats = []
        
        # URL feeds
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

        # IP feeds
        elif source_name == "feodotracker_ipblocklist" or \
             source_name == "binarydefense" or \
             source_name == "emergingthreats" or \
             source_name == "cinsscore" or \
             source_name == "elliotech" or \
             source_name == "stamparm" or \
             source_name == "mirai":
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
                    if self._validate_ip(ip):
                        threats.append(("ip", ip))
        
        # IP CIDR feeds
        elif source_name == "spamhaus_drop" or \
             source_name == "dshield" or \
             source_name == "firehol":
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
                    if self._validate_cidr(cidr):
                        threats.append(("cidr", cidr))
                
        # ThreatFox feeds
        elif source_name == "threatfox_urls" or source_name == "threatfox_domains" or source_name == "threatfox_ip_port":
            # Process ThreatFox CSV data (all types use similar format)
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
                        if indicator and self._validate_domain(indicator):
                            threats.append(("domain", indicator))
                    
                    elif source_name == "threatfox_ip_port":
                        if indicator and ":" in indicator:
                            ip_part = indicator.split(":")[0]
                            if self._validate_ip(ip_part):
                                threats.append(("ip_port", indicator))
                                threats.append(("ip", ip_part))
                
            except Exception as e:
                logger.error(f"Error parsing {source_name} data: {str(e)}")
                logger.error(f"Exception details: {type(e).__name__}")
                logger.error(traceback.format_exc())
        
        # Log extraction results
        if threats:
            threat_types = {}
            for t_type, _ in threats:
                threat_types[t_type] = threat_types.get(t_type, 0) + 1
            
            type_counts = ", ".join([f"{t_type}: {count}" for t_type, count in threat_types.items()])
            logger.info(f"Extracted {len(threats)} indicators from {source_name} ({type_counts})")
        else:
            logger.warning(f"No threats extracted from {source_name}")
            
        return threats
        
    def _validate_ip(self, ip):
        """Validate if a string is a proper IP address."""
        try:
            # Basic pattern match first
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                return False
            
            # Check each octet
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        except (ValueError, AttributeError):
            return False
            
    def _validate_domain(self, domain):
        """Validate if a string is a proper domain name."""
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
            
    def _validate_cidr(self, cidr):
        """Validate if a string is a proper CIDR notation."""
        try:
            if not cidr or '/' not in cidr:
                return False
                
            ip_part, prefix_part = cidr.split('/')
            
            # Validate IP part
            if not self._validate_ip(ip_part):
                return False
                
            # Validate prefix part (must be 0-32)
            prefix = int(prefix_part)
            if prefix < 0 or prefix > 32:
                return False
                
            return True
        except (ValueError, AttributeError):
            return False

    def process_source(self, source_id, name, url, frequency):
        """Downloads, processes, and stores data from a single source."""
        logger.info(f"{Fore.YELLOW}Processing source: {name}{Style.RESET_ALL}")
        process_start = time.time()
        
        raw_data = self._download_data(url)
        if raw_data is None:
            return

        data_hash = self._calculate_hash(raw_data)

        try:
            self.cursor.execute("INSERT INTO raw_data (source_id, raw_content, hash, timestamp) VALUES (?, ?, ?, ?)",
                                (source_id, raw_data, data_hash, datetime.datetime.now()))
            self.conn.commit()
        except sqlite3.IntegrityError:
            logger.info(f"  Skipping duplicate raw data for {name} (unchanged since last scan)")
            
            # Update the last_scan time even if data hasn't changed
            self.cursor.execute("UPDATE sources SET last_scan = ? WHERE id = ?", 
                            (datetime.datetime.now(), source_id))
            self.conn.commit()
            
            elapsed = time.time() - process_start
            logger.info(f"Finished processing {name} in {elapsed:.2f} seconds (no changes)")
            return

        extraction_start = time.time()
        threats = self._clean_and_extract(name, raw_data)
        extraction_time = time.time() - extraction_start
        logger.info(f"Threat extraction completed in {extraction_time:.2f} seconds")

        # --- Process threats with better deduplication ---
        db_start = time.time()
        now = datetime.datetime.now()
        processed_count = 0
        
        # Use a transaction for better performance
        self.conn.execute("BEGIN TRANSACTION")
        
        for threat_type, threat_value in threats:
            # Get normalized value to avoid duplicates with different formatting
            normalized_value = self._normalize_value(threat_type, threat_value)
            
            # Use REPLACE conflict resolution strategy to update existing records
            self.cursor.execute("""
                INSERT OR REPLACE INTO threats (source_id, threat_type, value, first_seen, last_seen)
                VALUES (
                    ?, ?, ?, 
                    COALESCE((SELECT first_seen FROM threats WHERE threat_type = ? AND value = ?), ?),
                    ?
                )
            """, (source_id, threat_type, normalized_value, threat_type, normalized_value, now, now))
            processed_count += 1

        # Commit the transaction
        self.conn.commit()
        
        logger.info(f"  {Fore.GREEN}Processed {processed_count} threats from {name}{Style.RESET_ALL}")

        self.cursor.execute("UPDATE sources SET last_scan = ? WHERE id = ?", (now, source_id))
        self.conn.commit()
        
        db_time = time.time() - db_start
        elapsed = time.time() - process_start
        logger.info(f"Database operations completed in {db_time:.2f} seconds")
        logger.info(f"{Fore.GREEN}Finished processing {name} in {elapsed:.2f} seconds{Style.RESET_ALL}")

    def _normalize_value(self, threat_type, value):
        """Normalizes threat values to prevent duplicates with different formatting."""
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

    def scan_sources(self):
        """Scans all sources based on their defined frequency."""
        now = datetime.datetime.now()
        uptime = now - self.start_time
        logger.info(f"Running scheduled scan check (uptime: {uptime})")
        
        self.cursor.execute("SELECT id, name, url, frequency, last_scan FROM sources")
        sources = self.cursor.fetchall()

        scan_count = 0
        total_sources = len(sources)
        sources_checked = 0
        
        for source_id, name, url, frequency, last_scan in sources:
            next_scan_due = None
            sources_checked += 1
            
            if last_scan is None:
                # First time scanning this source
                logger.info(f"{name}: Initial scan needed")
                self.process_source(source_id, name, url, frequency)
                scan_count += 1
            else:
                # Convert last_scan from string to datetime if needed
                if isinstance(last_scan, str):
                    last_scan_time = datetime.datetime.strptime(last_scan, "%Y-%m-%d %H:%M:%S.%f")
                else:
                    last_scan_time = last_scan
                    
                time_since_last_scan = (now - last_scan_time).total_seconds()
                next_scan_due = last_scan_time + datetime.timedelta(seconds=frequency)
                
                if time_since_last_scan >= frequency:
                    logger.info(f"{name}: Scan due - {time_since_last_scan:.0f} seconds since last scan (frequency: {frequency})")
                    self.process_source(source_id, name, url, frequency)
                    scan_count += 1
                else:
                    time_until_next = frequency - time_since_last_scan
                    logger.info(f"{name}: Next scan in {time_until_next:.0f} seconds")
        
        if scan_count == 0:
            logger.info("No sources due for scanning")
        else:
            logger.info(f"Completed scanning {scan_count} sources")
            
        # Check if this is the final source and if any scans were performed
        if sources_checked == total_sources and scan_count > 0:
            logger.info("All sources checked. Running auto-export...")
            self.export_threat_data()
            
        # Display database statistics every hour
        hour_passed = int(uptime.total_seconds()) % 3600 < 60  # Check if we just passed an hour mark
        if hour_passed:
            self._display_stats()

    def _display_stats(self):
        """Displays database statistics."""
        logger.info(f"{Fore.CYAN}--- Database Statistics ---{Style.RESET_ALL}")
        
        self.cursor.execute("SELECT COUNT(*) FROM threats")
        threat_count = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type")
        threat_types = self.cursor.fetchall()
        
        self.cursor.execute("SELECT s.name, s.last_scan, COUNT(t.id) as count FROM sources s LEFT JOIN threats t ON s.id = t.source_id GROUP BY s.id")
        sources = self.cursor.fetchall()
        
        logger.info(f"Total threats: {threat_count}")
        for threat_type, count in threat_types:
            logger.info(f"  {threat_type}: {count}")
            
        logger.info("Source statistics:")
        for name, last_scan, count in sources:
            if last_scan:
                logger.info(f"  {name}: {count} indicators, last scan: {last_scan}")
            else:
                logger.info(f"  {name}: {count} indicators, not yet scanned")
        
        logger.info(f"{Fore.CYAN}------------------------{Style.RESET_ALL}")

    def export_threat_data(self):
        """
        Exports threat data to master files based on threat type.
        Creates one file each for URLs, domains, IPs, and CIDR ranges,
        with a timestamp header.
        """
        export_dir = "exports"
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
            logger.info(f"Created exports directory: {export_dir}")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create fixed file paths for master files
        url_file = os.path.join(export_dir, "urls_master.txt")
        domain_file = os.path.join(export_dir, "domains_master.txt")
        ip_file = os.path.join(export_dir, "ips_master.txt")
        cidr_file = os.path.join(export_dir, "cidrs_master.txt")
        
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
        self.cursor.execute("SELECT value FROM threats WHERE threat_type = 'url' ORDER BY value")
        urls = self.cursor.fetchall()
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
        self.cursor.execute("SELECT value FROM threats WHERE threat_type = 'domain' ORDER BY value")
        domains = self.cursor.fetchall()
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
        self.cursor.execute("SELECT value FROM threats WHERE threat_type = 'ip' ORDER BY value")
        ips = self.cursor.fetchall()
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
        self.cursor.execute("SELECT value FROM threats WHERE threat_type = 'cidr' ORDER BY value")
        cidrs = self.cursor.fetchall()
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

    def _create_backups(self, files, max_backups=5):
        """
        Creates backup copies of existing master files before they are overwritten.
        
        Args:
            files: List of file paths to back up
            max_backups: Maximum number of backup files to keep
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
            for backup_path, _ in backups[max_backups:]:
                try:
                    os.remove(backup_path)
                    logger.debug(f"Removed old backup: {backup_path}")
                except OSError as e:
                    logger.error(f"Error removing old backup {backup_path}: {e}")

    def close_connection(self):
        """Closes the database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            logger.info(f"{Fore.GREEN}Database connection closed, application shutting down{Style.RESET_ALL}")

    def __del__(self):
        """Destructor to ensure database connection is closed properly."""
        self.close_connection()
        
    def run_scheduler(self):
        """Sets up and runs the scheduler for periodic scanning."""
        logger.info("Setting up scheduler to check sources every minute")
        schedule.every(1).minutes.do(self.scan_sources)
        
        # Schedule daily export at midnight
        schedule.every().day.at("00:00").do(self.export_threat_data)
        logger.info("Scheduled automatic daily export at midnight")
        
        # Run an initial scan immediately
        logger.info("Running initial scan...")
        self.scan_sources()

        try:
            while True:
                schedule.run_pending()
                time.sleep(1)  # Check every second
        except KeyboardInterrupt:
            logger.info(f"{Fore.YELLOW}Keyboard interrupt received, shutting down...{Style.RESET_ALL}")
            self.close_connection()

if __name__ == "__main__":
    # Import missing modules
    import fnmatch
    import signal
    
    print(f"{Fore.GREEN}Starting Threat Intelligence Feed Application{Style.RESET_ALL}")
    print("Press Ctrl+C to exit")
    
    app = IntelligenceFeedApp()

    # Define check frequencies for different categories
    # These can be easily modified to your preferred values
    FREQUENCY = {
        "QUICK": 300,       # 5 minutes - for rapidly changing feeds
        "STANDARD": 600,    # 10 minutes - default for most feeds
        "SLOW": 1800,       # 30 minutes - for slower-changing feeds
        "DAILY": 86400      # 24 hours - for feeds that update once per day
    }

    # URL Feeds - typically update more frequently
    app.add_source("urlhaus_text", "https://urlhaus.abuse.ch/downloads/text/", FREQUENCY["STANDARD"])
    app.add_source("openphish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", FREQUENCY["STANDARD"])
    app.add_source("vxvault", "http://vxvault.net/URL_List.php", FREQUENCY["STANDARD"])
    
    # IP Feeds - typically update less frequently
    app.add_source("feodotracker_ipblocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", FREQUENCY["STANDARD"])
    app.add_source("binarydefense", "https://www.binarydefense.com/banlist.txt", FREQUENCY["STANDARD"])
    app.add_source("emergingthreats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", FREQUENCY["STANDARD"])
    app.add_source("cinsscore", "https://cinsscore.com/list/ci-badguys.txt", FREQUENCY["STANDARD"])
    app.add_source("elliotech", "https://cdn.ellio.tech/community-feed", FREQUENCY["SLOW"])
    app.add_source("stamparm", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt", FREQUENCY["SLOW"])
    app.add_source("mirai", "https://mirai.security.gives/data/ip_list.txt", FREQUENCY["STANDARD"])
    
    # IP CIDR Feeds - typically update less frequently
    app.add_source("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt", FREQUENCY["SLOW"])
    app.add_source("dshield", "https://dshield.org/block.txt", FREQUENCY["STANDARD"])
    app.add_source("firehol", "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset", FREQUENCY["DAILY"])
    
    # ThreatFox Feeds - contain recent threats, check frequently
    app.add_source("threatfox_urls", "https://threatfox.abuse.ch/export/csv/urls/recent/", FREQUENCY["STANDARD"])
    app.add_source("threatfox_domains", "https://threatfox.abuse.ch/export/csv/domains/recent/", FREQUENCY["STANDARD"])
    app.add_source("threatfox_ip_port", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", FREQUENCY["STANDARD"])

    # Set up signal handler for graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Received signal {sig}, shutting down gracefully...{Style.RESET_ALL}")
        app.close_connection()
        sys.exit(0)
        
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Start the scheduler
        app.run_scheduler()
    except KeyboardInterrupt:
        # This is handled by the signal handler now
        pass
    except Exception as e:
        logger.error(f"{Fore.RED}Unhandled exception: {e}{Style.RESET_ALL}")
        logger.error(traceback.format_exc())
    finally:
        app.close_connection()