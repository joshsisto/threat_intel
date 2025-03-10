# threat_intel.py (Main application)
import requests
import time
import sqlite3
import schedule
import datetime
import hashlib
import re

class IntelligenceFeedApp:

    def __init__(self, db_name="threat_intel.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.conn.execute("PRAGMA journal_mode=WAL;")  # Enable WAL mode
        self.create_tables()


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

    def add_source(self, name, url, frequency):
        """Adds a new intelligence source to the database."""
        try:
            self.cursor.execute("""
                INSERT INTO sources (name, url, frequency, last_scan)
                VALUES (?, ?, ?, ?)
            """, (name, url, frequency, None))  # Initialize last_scan to None
            self.conn.commit()
        except sqlite3.IntegrityError:
            print(f"Source '{name}' already exists.")

    def _download_data(self, url):
        """Downloads data from a given URL."""
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error downloading data from {url}: {e}")
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
        return threats

    def process_source(self, source_id, name, url, frequency):
        """Downloads, processes, and stores data from a single source."""
        print(f"Processing source: {name}")
        raw_data = self._download_data(url)
        if raw_data is None:
            return

        data_hash = self._calculate_hash(raw_data)

        try:
            self.cursor.execute("INSERT INTO raw_data (source_id, raw_content, hash, timestamp) VALUES (?, ?, ?, ?)",
                                (source_id, raw_data, data_hash, datetime.datetime.now()))
            self.conn.commit()
        except sqlite3.IntegrityError:
            print(f"  Skipping duplicate raw data for {name}.")
            return

        threats = self._clean_and_extract(name, raw_data)

        # --- Bulk Insert Optimization ---
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
            print(f"  Added {len(bulk_insert_data)} new threats for {name}.")


        if bulk_update_data:
            self.cursor.executemany("UPDATE threats SET last_seen = ? WHERE id = ?", bulk_update_data)
            print(f"  Updated {len(bulk_update_data)} existing threats for {name}.")

        self.cursor.execute("UPDATE sources SET last_scan = ? WHERE id = ?", (datetime.datetime.now(), source_id))
        self.conn.commit() #commit all the changes
        print(f"Finished processing source: {name}")



    def scan_sources(self):
        """Scans all sources based on their defined frequency."""
        now = datetime.datetime.now()
        self.cursor.execute("SELECT id, name, url, frequency, last_scan FROM sources")
        sources = self.cursor.fetchall()

        for source_id, name, url, frequency, last_scan in sources:
            if last_scan is None:
                # First time scanning this source
                self.process_source(source_id, name, url, frequency)
            else:
                last_scan_time = datetime.datetime.strptime(str(last_scan), "%Y-%m-%d %H:%M:%S.%f")
                time_since_last_scan = (now - last_scan_time).total_seconds()
                if time_since_last_scan >= frequency:
                    self.process_source(source_id, name, url, frequency)
                # else: #uncomment for debugging
                    # print(f'Not scanning {name} because time since last scan {time_since_last_scan} is not greater than frequency {frequency}')


    def run_scheduler(self):
        """Sets up and runs the scheduler for periodic scanning."""
        # Schedule the scan_sources function to run every minute.  This is more frequent than
        # any of our scheduled tasks, but it allows us to check if *any* task needs to run.
        schedule.every(1).minutes.do(self.scan_sources)

        while True:
            schedule.run_pending()
            time.sleep(1)  # Check every second



    def close_connection(self):
        """Closes the database connection."""
        self.conn.close()

    def query_threats(self, query):
        """Executes an arbitrary SQL query against the threats table and prints the results."""

        try:
            self.cursor.execute(query)
            results = self.cursor.fetchall()

            # Print column headers (if available)
            if self.cursor.description:
                headers = [col[0] for col in self.cursor.description]
                print("| " + " | ".join(headers) + " |")  # Basic formatting
                print("|" + "---|" * len(headers)) # Separator line

            # Print the results
            for row in results:
                formatted_row = [str(item).replace("\n", "\\n") for item in row]  # Handle newlines
                print("| " + " | ".join(formatted_row) + " |")

        except sqlite3.Error as e:
            print(f"Database error: {e}")

if __name__ == "__main__":
    app = IntelligenceFeedApp()

    # Add the intelligence sources
    app.add_source("urlhaus_hosts", "https://urlhaus.abuse.ch/downloads/hostfile/", 3600)  # 1 hour
    app.add_source("urlhaus_text", "https://urlhaus.abuse.ch/downloads/text/", 1800)  # 30 minutes
    app.add_source("feodotracker_ipblocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 86400)  # 1 day

    # Start the scheduler
    app.run_scheduler()
    app.close_connection()