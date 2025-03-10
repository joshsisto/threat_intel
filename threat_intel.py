import requests
import time
import sqlite3
import schedule
import datetime
import hashlib
import re
import logging
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
                threat_type TEXT,  -- e.g., "malware_host", "malware_url", "ip_blocklist"
                value TEXT,      -- The actual threat data (host, URL, IP)
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
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
            response = requests.get(url, timeout=30)  # Added timeout
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            elapsed = time.time() - start_time
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
        if source_name == "urlhaus_hosts":
            # Optimized regex for urlhaus_hosts
            for match in re.finditer(r"^\s*[^#\s]+\s+([^#\s]+)", raw_data, re.MULTILINE):
                threats.append(("malware_host", match.group(1)))

        elif source_name == "urlhaus_text":
            # Optimized regex for urlhaus_text (extract URLs)
            for match in re.finditer(r"^(https?://\S+)", raw_data, re.MULTILINE):
                threats.append(("malware_url", match.group(1)))

        elif source_name == "feodotracker_ipblocklist":
             # Optimized regex for feodotracker (extract IPs)
            for match in re.finditer(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_data, re.MULTILINE):
                threats.append(("ip_blocklist", match.group(1)))
        
        logger.info(f"Extracted {len(threats)} potential threats from {source_name}")
        return threats

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
        
        self.cursor.execute("SELECT name, last_scan FROM sources")
        sources = self.cursor.fetchall()
        
        logger.info(f"Total threats: {threat_count}")
        for threat_type, count in threat_types:
            logger.info(f"  {threat_type}: {count}")
            
        logger.info("Source last scan times:")
        for name, last_scan in sources:
            logger.info(f"  {name}: {last_scan}")
        
        logger.info(f"{Fore.CYAN}------------------------{Style.RESET_ALL}")

    def run_scheduler(self):
        """Sets up and runs the scheduler for periodic scanning."""
        # Schedule the scan_sources function to run every minute.  This is more frequent than
        # any of our scheduled tasks, but it allows us to check if *any* task needs to run.
        logger.info("Setting up scheduler to check sources every minute")
        schedule.every(1).minutes.do(self.scan_sources)

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

    # Add the intelligence sources
    app.add_source("urlhaus_hosts", "https://urlhaus.abuse.ch/downloads/hostfile/", 3600)  # 1 hour
    app.add_source("urlhaus_text", "https://urlhaus.abuse.ch/downloads/text/", 1800)  # 30 minutes
    app.add_source("feodotracker_ipblocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 86400)  # 1 day

    # Start the scheduler
    app.run_scheduler()
    app.close_connection()