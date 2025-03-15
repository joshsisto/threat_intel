"""
Database manager for the threat intelligence application.
Handles database connection, table creation, and basic operations.
"""
import sqlite3
import datetime
import logging
from colorama import Fore, Style

from utils.formatters import format_time_period

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database operations for the threat intelligence application."""

    def __init__(self, db_name="threat_intel.db"):
        """Initialize database connection and tables."""
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.conn.execute("PRAGMA journal_mode=WAL;")  # Enable WAL mode
        self.conn.execute("PRAGMA synchronous=NORMAL;")  # Slightly faster operation while maintaining data integrity
        
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
            logger.info(f"Added source: {Fore.CYAN}{name}{Style.RESET_ALL} - Frequency: {format_time_period(frequency)}")
        except sqlite3.IntegrityError:
            logger.warning(f"Source '{name}' already exists - skipping")

    def get_all_sources(self):
        """Returns all sources from the database."""
        self.cursor.execute("SELECT id, name, url, frequency, last_scan FROM sources")
        return self.cursor.fetchall()

    def store_raw_data(self, source_id, raw_data, data_hash):
        """Store raw data in the database. Returns True if it's new data, False if duplicate."""
        try:
            self.cursor.execute("INSERT INTO raw_data (source_id, raw_content, hash, timestamp) VALUES (?, ?, ?, ?)",
                            (source_id, raw_data, data_hash, datetime.datetime.now()))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.info(f"  Skipping duplicate raw data (unchanged since last scan)")
            return False

    def update_last_scan(self, source_id):
        """Update the last_scan timestamp for a source."""
        self.cursor.execute("UPDATE sources SET last_scan = ? WHERE id = ?", 
                        (datetime.datetime.now(), source_id))
        self.conn.commit()

    def store_threats(self, threats, source_id):
        """Store threats in the database."""
        now = datetime.datetime.now()
        processed_count = 0
        
        # Use a transaction for better performance
        self.conn.execute("BEGIN TRANSACTION")
        
        for threat_type, threat_value in threats:
            # Insert using REPLACE conflict resolution strategy
            self.cursor.execute("""
                INSERT OR REPLACE INTO threats (source_id, threat_type, value, first_seen, last_seen)
                VALUES (
                    ?, ?, ?, 
                    COALESCE((SELECT first_seen FROM threats WHERE threat_type = ? AND value = ?), ?),
                    ?
                )
            """, (source_id, threat_type, threat_value, threat_type, threat_value, now, now))
            processed_count += 1

        # Commit the transaction
        self.conn.commit()
        
        return processed_count

    def get_threats_by_type(self, threat_type):
        """Get all threats of a specific type."""
        self.cursor.execute("SELECT value FROM threats WHERE threat_type = ? ORDER BY value", (threat_type,))
        return self.cursor.fetchall()

    def count_threats_by_type(self):
        """Count threats by type."""
        self.cursor.execute("SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type")
        return self.cursor.fetchall()

    def count_total_threats(self):
        """Count total threats."""
        self.cursor.execute("SELECT COUNT(*) FROM threats")
        return self.cursor.fetchone()[0]

    def get_source_stats(self):
        """Get statistics for each source."""
        self.cursor.execute("""
            SELECT s.name, s.last_scan, COUNT(t.id) as count 
            FROM sources s 
            LEFT JOIN threats t ON s.id = t.source_id 
            GROUP BY s.id
        """)
        return self.cursor.fetchall()

    def display_stats(self):
        """Displays database statistics."""
        logger.info(f"{Fore.CYAN}--- Database Statistics ---{Style.RESET_ALL}")
        
        threat_count = self.count_total_threats()
        threat_types = self.count_threats_by_type()
        sources = self.get_source_stats()
        
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

    def close_connection(self):
        """Closes the database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            logger.info("Database connection closed")