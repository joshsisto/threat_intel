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
        
        # Configure logging level
        logging.getLogger().setLevel(logging.DEBUG)  # Set to DEBUG for more verbose logging
        
        self.create_tables()
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

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                threat_type TEXT,  -- e.g., "url", "domain", "ip", "ip_port", "cidr"
                value TEXT,      -- The actual threat data (URL, domain, IP, IP:port, CIDR)
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                UNIQUE(threat_type, value) ON CONFLICT IGNORE,
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
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_value ON threats (value)")  # Add this if you query by value alone
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_data_hash ON raw_data (hash)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_type ON threats (threat_type)")  # Add index for querying by threat type

        self.conn.commit()
        logger.info("Database tables created or verified")

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

        # --- Bulk Insert Optimization ---
        db_start = time.time()
        now = datetime.datetime.now()
        bulk_insert_data = []  # List to accumulate data for bulk insert
        bulk_update_data = []
        
        for threat_type, threat_value in threats:
            self.cursor.execute("""
                SELECT id FROM threats
                WHERE source_id = ? AND threat_type = ? AND value = ?
            """, (source_id, threat_type, threat_value))

            existing_threat = self.cursor.fetchone()

            if existing_threat:
               # Prepare for bulk update
               bulk_update_data.append((now, existing_threat[0]))
            else:
                # Prepare for bulk insert
                bulk_insert_data.append((source_id, threat_type, threat_value, now, now))

        # Perform bulk insert
        if bulk_insert_data:
            self.cursor.executemany("""
                INSERT INTO threats (source_id, threat_type, value, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, bulk_insert_data)
            logger.info(f"  {Fore.GREEN}Added {len(bulk_insert_data)} new threats for {name}{Style.RESET_ALL}")


        if bulk_update_data:
            self.cursor.executemany("UPDATE threats SET last_seen = ? WHERE id = ?", bulk_update_data)
            logger.info(f"  {Fore.BLUE}Updated {len(bulk_update_data)} existing threats for {name}{Style.RESET_ALL}")

        self.cursor.execute("UPDATE sources SET last_scan = ? WHERE id = ?", (now, source_id))
        self.conn.commit() #commit all the changes
        
        db_time = time.time() - db_start
        elapsed = time.time() - process_start
        logger.info(f"Database operations completed in {db_time:.2f} seconds")
        logger.info(f"{Fore.GREEN}Finished processing {name} in {elapsed:.2f} seconds{Style.RESET_ALL}")

    def scan_sources(self):
        """Scans all sources based on their defined frequency."""
        now = datetime.datetime.now()
        uptime = now - self.start_time
        logger.info(f"Running scheduled scan check (uptime: {uptime})")
        
        self.cursor.execute("SELECT id, name, url, frequency, last_scan FROM sources")
        sources = self.cursor.fetchall()

        scan_count = 0
        for source_id, name, url, frequency, last_scan in sources:
            next_scan_due = None
            
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

    def run_scheduler(self):
        """Sets up and runs the scheduler for periodic scanning."""
        logger.info("Setting up scheduler to check sources every minute")
        schedule.every(1).minutes.do(self.scan_sources)
        
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

    def close_connection(self):
        """Closes the database connection."""
        self.conn.close()
        logger.info(f"{Fore.GREEN}Database connection closed, application shutting down{Style.RESET_ALL}")

    def query_threats(self, query):
        """Executes an arbitrary SQL query against the threats table and prints the results."""
        logger.info(f"Executing query: {query}")
        try:
            start_time = time.time()
            self.cursor.execute(query)
            results = self.cursor.fetchall()
            query_time = time.time() - start_time
            
            logger.info(f"Query returned {len(results)} results in {query_time:.2f} seconds")

            # Print column headers (if available)
            if self.cursor.description:
                headers = [col[0] for col in self.cursor.description]
                header_row = "| " + " | ".join(headers) + " |"
                separator = "|" + "---|" * len(headers)
                
                print(header_row)
                print(separator)

            # Print the results
            for row in results:
                formatted_row = [str(item).replace("\n", "\\n") for item in row]  # Handle newlines
                print("| " + " | ".join(formatted_row) + " |")

        except sqlite3.Error as e:
            logger.error(f"{Fore.RED}Database error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
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

    # Start the scheduler
    app.run_scheduler()
    app.close_connection()
