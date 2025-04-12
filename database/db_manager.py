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
        
        # Performance and integrity optimizations
        self.conn.execute("PRAGMA journal_mode=WAL;")        # Enable WAL mode for better concurrency
        self.conn.execute("PRAGMA synchronous=NORMAL;")      # Slightly faster operation while maintaining data integrity
        self.conn.execute("PRAGMA cache_size=-10000;")       # 10MB cache, negative value means kibibytes
        self.conn.execute("PRAGMA temp_store=MEMORY;")       # Store temp tables and indices in memory
        self.conn.execute("PRAGMA foreign_keys=ON;")         # Enforce referential integrity
        
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
                UNIQUE(threat_type, value),  -- Changed to pure UNIQUE constraint for proper deduplication
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
                processed_count INTEGER DEFAULT 0,  -- Track how many items were processed from this raw data
                FOREIGN KEY (source_id) REFERENCES sources(id)
            )
        """)
        
        # --- Add Indexes ---
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_source_type_value ON threats (source_id, threat_type, value)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_value ON threats (value)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_data_hash ON raw_data (hash)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_type ON threats (threat_type)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats (last_seen)")  # For faster cleanup of old threats

        self.conn.commit()
        logger.info("Database tables created or verified")

    def deduplicate_threats(self):
        """Removes duplicate entries from the threats table by keeping only the most recent entry."""
        logger.info(f"{Fore.YELLOW}Starting deduplication of threats table...{Style.RESET_ALL}")
        
        # Begin transaction for better performance
        self.conn.execute("BEGIN TRANSACTION")
        
        # Create a temporary table to store unique threat entries
        self.cursor.execute("""
            CREATE TEMPORARY TABLE threats_dedup AS
            SELECT 
                MIN(id) as original_id,  -- Keep the oldest record ID
                threat_type, 
                value, 
                MIN(first_seen) as first_seen,  -- Keep the earliest first_seen date
                MAX(last_seen) as last_seen,    -- Keep the latest last_seen date
                COUNT(*) as duplicate_count
            FROM threats
            GROUP BY threat_type, value
            HAVING COUNT(*) > 1
        """)
        
        # Get the total count of duplicates
        self.cursor.execute("SELECT SUM(duplicate_count - 1) FROM threats_dedup")
        total_duplicate_count = self.cursor.fetchone()[0] or 0
        
        if total_duplicate_count > 0:
            logger.info(f"{Fore.GREEN}Found {total_duplicate_count} duplicate threat entries to consolidate{Style.RESET_ALL}")
            
            # Update the original records with the consolidated first_seen/last_seen dates
            self.cursor.execute("""
                UPDATE threats
                SET 
                    first_seen = (SELECT first_seen FROM threats_dedup WHERE threats_dedup.original_id = threats.id),
                    last_seen = (SELECT last_seen FROM threats_dedup WHERE threats_dedup.original_id = threats.id)
                WHERE id IN (SELECT original_id FROM threats_dedup)
            """)
            
            # Delete the duplicate records, keeping the original ones
            self.cursor.execute("""
                DELETE FROM threats
                WHERE EXISTS (
                    SELECT 1 FROM threats_dedup 
                    WHERE threats.threat_type = threats_dedup.threat_type 
                    AND threats.value = threats_dedup.value
                    AND threats.id != threats_dedup.original_id
                )
            """)
            
            self.conn.commit()
            
            # Run VACUUM to reclaim disk space
            self.conn.execute("VACUUM")
            
            logger.info(f"{Fore.GREEN}Successfully consolidated {total_duplicate_count} duplicate threat entries{Style.RESET_ALL}")
        else:
            logger.info("No duplicate threats found")
        
        # Drop the temporary table
        self.cursor.execute("DROP TABLE IF EXISTS threats_dedup")
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
            self.cursor.execute("INSERT INTO raw_data (source_id, raw_content, hash, timestamp, processed_count) VALUES (?, ?, ?, ?, 0)",
                            (source_id, raw_data, data_hash, datetime.datetime.now()))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.info(f"  Skipping duplicate raw data (unchanged since last scan)")
            # Update timestamp to show we checked it
            self.cursor.execute("UPDATE raw_data SET timestamp = ? WHERE hash = ?", 
                           (datetime.datetime.now(), data_hash))
            self.conn.commit()
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
        duplicate_count = 0
        
        # Use a transaction for better performance
        self.conn.execute("BEGIN TRANSACTION")
        
        for threat_type, threat_value in threats:
            # Check if this exact threat already exists
            self.cursor.execute("""
                SELECT id, first_seen FROM threats 
                WHERE threat_type = ? AND value = ?
            """, (threat_type, threat_value))
            
            existing_threat = self.cursor.fetchone()
            
            if existing_threat:
                # Update last_seen time for existing threat
                threat_id, first_seen = existing_threat
                self.cursor.execute("""
                    UPDATE threats SET last_seen = ? WHERE id = ?
                """, (now, threat_id))
                duplicate_count += 1
            else:
                # Insert new threat
                self.cursor.execute("""
                    INSERT INTO threats (source_id, threat_type, value, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                """, (source_id, threat_type, threat_value, now, now))
                processed_count += 1

        # Commit the transaction
        self.conn.commit()
        
        if duplicate_count > 0:
            logger.info(f"  {Fore.CYAN}Skipped {duplicate_count} existing threats{Style.RESET_ALL}")
        
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
        
    def cleanup_old_threats(self, days_old=90):
        """Remove threats older than the specified number of days."""
        logger.info(f"{Fore.YELLOW}Starting cleanup of old threat data...{Style.RESET_ALL}")
        
        # Calculate cutoff date
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days_old)
        
        # Count threats to be removed
        self.cursor.execute("SELECT COUNT(*) FROM threats WHERE last_seen < ?", (cutoff_date,))
        old_count = self.cursor.fetchone()[0]
        
        if old_count > 0:
            logger.info(f"{Fore.GREEN}Found {old_count} threats older than {days_old} days to remove{Style.RESET_ALL}")
            
            # Delete old threats
            self.cursor.execute("DELETE FROM threats WHERE last_seen < ?", (cutoff_date,))
            self.conn.commit()
            
            # Run VACUUM to reclaim disk space
            self.conn.execute("VACUUM")
            
            logger.info(f"{Fore.GREEN}Successfully removed {old_count} old threat entries{Style.RESET_ALL}")
        else:
            logger.info(f"No threats older than {days_old} days found")
        
        return old_count

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
        
        # Get database file size
        try:
            import os
            db_size_bytes = os.path.getsize(self.db_name)
            db_size_mb = db_size_bytes / (1024 * 1024)
            logger.info(f"Database size: {db_size_mb:.2f} MB")
        except Exception:
            logger.info("Database size: Unknown")
        
        # Get threat statistics
        threat_count = self.count_total_threats()
        threat_types = self.count_threats_by_type()
        
        # Get raw data statistics
        self.cursor.execute("SELECT COUNT(*) FROM raw_data")
        raw_data_count = self.cursor.fetchone()[0]
        
        # Get source statistics
        sources = self.get_source_stats()
        
        # Display statistics
        logger.info(f"Total threats: {threat_count}")
        for threat_type, count in threat_types:
            logger.info(f"  {threat_type}: {count}")
        
        logger.info(f"Raw data entries: {raw_data_count}")
        
        # Get age distribution of threats
        self.cursor.execute("""
            SELECT 
                COUNT(CASE WHEN last_seen >= datetime('now', '-1 day') THEN 1 END) as day1,
                COUNT(CASE WHEN last_seen >= datetime('now', '-7 day') THEN 1 END) as day7,
                COUNT(CASE WHEN last_seen >= datetime('now', '-30 day') THEN 1 END) as day30,
                COUNT(CASE WHEN last_seen >= datetime('now', '-90 day') THEN 1 END) as day90
            FROM threats
        """)
        age_stats = self.cursor.fetchone()
        
        if age_stats:
            logger.info(f"Threat age distribution:")
            logger.info(f"  Last 24 hours: {age_stats[0]}")
            logger.info(f"  Last 7 days: {age_stats[1]}")
            logger.info(f"  Last 30 days: {age_stats[2]}")
            logger.info(f"  Last 90 days: {age_stats[3]}")
            
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