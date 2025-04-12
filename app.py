"""
Threat Intelligence Feed Application - Main Application Class
"""
import time
import logging
import schedule
import datetime
from colorama import Fore, Style

from database.db_manager import DatabaseManager
from collectors.base_collector import BaseCollector
from exporters.file_exporter import FileExporter

logger = logging.getLogger(__name__)

class IntelligenceFeedApp:
    """Main application class that orchestrates the threat intelligence collection."""

    def __init__(self, db_name="threat_intel.db"):
        self.db_name = db_name
        self.db_manager = DatabaseManager(db_name)
        self.exporter = FileExporter(self.db_manager)
        self.start_time = datetime.datetime.now()
        
        # Calculate database size
        db_size_mb = self._get_db_size_mb()
        logger.info(f"Current database size: {db_size_mb:.2f} MB")
        
        # Run deduplication on startup
        self.db_manager.deduplicate_threats()
        
        # Recalculate database size after dedup
        new_db_size_mb = self._get_db_size_mb()
        if new_db_size_mb < db_size_mb:
            logger.info(f"Database size reduced by {db_size_mb - new_db_size_mb:.2f} MB after deduplication")
        
        logger.info(f"{Fore.GREEN}Threat Intelligence Feed Application started{Style.RESET_ALL}")
        logger.info(f"Database initialized: {self.db_name}")
        
    def _get_db_size_mb(self):
        """Get the size of the database file in megabytes."""
        try:
            import os
            if os.path.exists(self.db_name):
                size_bytes = os.path.getsize(self.db_name)
                size_mb = size_bytes / (1024 * 1024)
                return size_mb
            return 0
        except Exception as e:
            logger.warning(f"Could not get database size: {e}")
            return 0

    def add_source(self, name, url, frequency):
        """Adds a new intelligence source to the database."""
        self.db_manager.add_source(name, url, frequency)

    def process_source(self, source_id, name, url, frequency):
        """Downloads, processes, and stores data from a single source."""
        logger.info(f"{Fore.YELLOW}Processing source: {name}{Style.RESET_ALL}")
        process_start = time.time()
        
        # Create collector based on source name
        collector = BaseCollector.create_collector(name)
        
        # Use collector to process source
        processed_count = collector.process(self.db_manager, source_id, name, url)
        
        if processed_count is not None:
            logger.info(f"  {Fore.GREEN}Processed {processed_count} threats from {name}{Style.RESET_ALL}")
        
        elapsed = time.time() - process_start
        logger.info(f"{Fore.GREEN}Finished processing {name} in {elapsed:.2f} seconds{Style.RESET_ALL}")

    def scan_sources(self):
        """Scans all sources based on their defined frequency."""
        now = datetime.datetime.now()
        uptime = now - self.start_time
        logger.info(f"Running scheduled scan check (uptime: {uptime})")
        
        sources = self.db_manager.get_all_sources()

        scan_count = 0
        total_sources = len(sources)
        sources_checked = 0
        
        for source_id, name, url, frequency, last_scan in sources:
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
            
            # Run deduplication after scanning to ensure database size is managed
            if scan_count > 0:
                logger.info("Running database deduplication after scan...")
                self.db_manager.deduplicate_threats()
            
            # Check if this is the final source and if any scans were performed
            if sources_checked == total_sources and scan_count > 0:
                logger.info("All sources checked. Running auto-export...")
                self.export_threat_data()
        
        # Display database statistics at regular intervals
        hour_passed = int(uptime.total_seconds()) % 3600 < 60  # Check if we just passed an hour mark
        if hour_passed:
            self._display_stats()

    def _display_stats(self):
        """Displays database statistics."""
        self.db_manager.display_stats()

    def export_threat_data(self):
        """Exports threat data to master files."""
        return self.exporter.export_threat_data()

    def close_connection(self):
        """Closes the database connection."""
        if hasattr(self, 'db_manager'):
            self.db_manager.close_connection()
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
        
        # Schedule weekly database cleanup to remove old entries (90+ days old)
        schedule.every().sunday.at("01:00").do(self.cleanup_old_data)
        logger.info("Scheduled weekly cleanup of old threat data (Sunday at 1:00 AM)")
        
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
            
    def cleanup_old_data(self):
        """Clean up old threat data that's no longer relevant."""
        logger.info(f"{Fore.YELLOW}Running scheduled database cleanup...{Style.RESET_ALL}")
        
        # Get current database size
        initial_size = self._get_db_size_mb()
        logger.info(f"Database size before cleanup: {initial_size:.2f} MB")
        
        # Remove threats older than 90 days
        removed_count = self.db_manager.cleanup_old_threats(days_old=90)
        
        # Run deduplication to ensure database is compact
        self.db_manager.deduplicate_threats()
        
        # Clean up raw_data table to remove old entries
        self._cleanup_raw_data()
        
        # Report results
        new_size = self._get_db_size_mb()
        size_diff = initial_size - new_size
        
        if size_diff > 0:
            logger.info(f"{Fore.GREEN}Database size reduced by {size_diff:.2f} MB during cleanup{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Database cleanup complete. New size: {new_size:.2f} MB{Style.RESET_ALL}")
        
        return removed_count
        
    def _cleanup_raw_data(self):
        """Clean up old raw data entries that are no longer needed."""
        try:
            # Keep only the last 14 days of raw data
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=14)
            
            # Use db_manager's cursor
            self.db_manager.cursor.execute("SELECT COUNT(*) FROM raw_data WHERE timestamp < ?", (cutoff_date,))
            raw_count = self.db_manager.cursor.fetchone()[0]
            
            if raw_count > 0:
                logger.info(f"Removing {raw_count} old raw data entries (older than 14 days)")
                self.db_manager.cursor.execute("DELETE FROM raw_data WHERE timestamp < ?", (cutoff_date,))
                self.db_manager.conn.commit()
        except Exception as e:
            logger.error(f"Error cleaning up raw data: {str(e)}")
            # Continue with other cleanup operations