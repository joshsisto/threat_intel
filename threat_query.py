# threat_query.py (Separate query application)
import sqlite3
import os
import csv
import json
from datetime import datetime
import argparse

class ThreatQuerier:
    def __init__(self, db_name="threat_intel.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        self.cursor = self.conn.cursor()
        
        # Ensure exports directory exists
        self.export_dir = "exports"
        if not os.path.exists(self.export_dir):
            os.makedirs(self.export_dir)
    
    def _print_results(self, results):
        """Prints query results in a formatted way."""
        if not results:
            print("No results found.")
            return
            
        if self.cursor.description:
            headers = [col[0] for col in self.cursor.description]
            print("| " + " | ".join(headers) + " |")
            print("|" + "---|" * len(headers))
        
        for row in results:
            formatted_row = [str(item).replace("\n", "\\n") for item in row]
            print("| " + " | ".join(formatted_row) + " |")
    
    def _export_results(self, results, filename=None, format="txt"):
        """
        Exports query results to a file.
        
        Args:
            results: The query results to export
            filename: The name of the file to export to (without extension)
            format: The format to export to (txt, csv, json)
        
        Returns:
            str: Path to the exported file
        """
        if not results:
            print("No results to export.")
            return None
            
        # Generate default filename if none provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_export_{timestamp}"
        
        # Add extension based on format
        full_path = os.path.join(self.export_dir, f"{filename}.{format}")
        
        # Export based on format
        headers = [col[0] for col in self.cursor.description] if self.cursor.description else []
        
        if format == "txt":
            with open(full_path, 'w') as file:
                # Write headers
                file.write("| " + " | ".join(headers) + " |\n")
                file.write("|" + "---|" * len(headers) + "\n")
                
                # Write data
                for row in results:
                    formatted_row = [str(item).replace("\n", "\\n") for item in row]
                    file.write("| " + " | ".join(formatted_row) + " |\n")
        
        elif format == "csv":
            with open(full_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(headers)
                writer.writerows(results)
        
        elif format == "json":
            # Convert results to list of dictionaries
            json_data = []
            for row in results:
                # Handle SQLite.Row objects
                if isinstance(row, sqlite3.Row):
                    row_dict = {headers[i]: row[i] for i in range(len(headers))}
                # Handle regular tuples
                else:
                    row_dict = {headers[i]: row[i] for i in range(len(row))}
                json_data.append(row_dict)
                
            with open(full_path, 'w') as file:
                json.dump(json_data, file, indent=2, default=str)
        
        print(f"Results exported to: {full_path}")
        return full_path
    
    def get_all_threats(self, export=False, filename=None, format="txt"):
        """Retrieves all threats from the database."""
        self.cursor.execute("SELECT * FROM threats")
        results = self.cursor.fetchall()
        self._print_results(results)
        
        if export:
            return self._export_results(results, filename, format)
        return None
    
    def get_threats_by_type(self, threat_type, export=False, filename=None, format="txt"):
        """Retrieves threats of a specific type."""
        self.cursor.execute("SELECT * FROM threats WHERE threat_type = ?", (threat_type,))
        results = self.cursor.fetchall()
        self._print_results(results)
        
        if export:
            if not filename:
                filename = f"threats_by_type_{threat_type}"
            return self._export_results(results, filename, format)
        return None
    
    def get_cidr_threats(self, export=False, filename=None, format="txt"):
        """Retrieves all CIDR-based threats."""
        return self.get_threats_by_type("cidr", export, filename, format)
    
    def get_threats_by_source(self, source_name, export=False, filename=None, format="txt"):
        """Retrieves threats from a specific source."""
        self.cursor.execute("""
            SELECT t.* FROM threats t
            JOIN sources s ON t.source_id = s.id
            WHERE s.name = ?
        """, (source_name,))
        results = self.cursor.fetchall()
        self._print_results(results)
        
        if export:
            if not filename:
                filename = f"threats_by_source_{source_name}"
            return self._export_results(results, filename, format)
        return None
    
    def get_threats_since(self, since_datetime, export=False, filename=None, format="txt"):
        """Retrieves threats seen since a given datetime."""
        if isinstance(since_datetime, str):
            since_datetime = datetime.strptime(since_datetime, "%Y-%m-%d %H:%M:%S")
        
        self.cursor.execute("SELECT * FROM threats WHERE last_seen >= ?", (since_datetime,))
        results = self.cursor.fetchall()
        self._print_results(results)
        
        if export:
            if not filename:
                date_str = since_datetime.strftime("%Y%m%d")
                filename = f"threats_since_{date_str}"
            return self._export_results(results, filename, format)
        return None
    
    def get_threat_counts_by_source(self, export=False, filename=None, format="txt"):
        """Retrieves the number of threats from each source."""
        self.cursor.execute("""
            SELECT s.name, COUNT(t.id) as count, 
                   MIN(t.first_seen) as oldest,
                   MAX(t.last_seen) as newest
            FROM threats t
            JOIN sources s ON t.source_id = s.id
            GROUP BY s.name
        """)
        results = self.cursor.fetchall()
        self._print_results(results)
        
        if export:
            if not filename:
                filename = "threat_counts_by_source"
            return self._export_results(results, filename, format)
        return None
    
    def search_threats(self, search_term, export=False, filename=None, format="txt"):
        """Searches for threats containing a specific term in the value."""
        # Use LIKE for partial matching
        self.cursor.execute("SELECT * FROM threats WHERE value LIKE ?", (f"%{search_term}%",))
        results = self.cursor.fetchall()
        self._print_results(results)
        
        if export:
            if not filename:
                filename = f"threats_search_{search_term.replace('.', '_')}"
            return self._export_results(results, filename, format)
        return None
    
    def export_all_data(self, format="csv"):
        """Exports all database tables to files."""
        exported_files = []
        
        # Export sources
        self.cursor.execute("SELECT * FROM sources")
        results = self.cursor.fetchall()
        sources_file = self._export_results(results, "sources", format)
        if sources_file:
            exported_files.append(sources_file)
        
        # Export threats
        self.cursor.execute("SELECT * FROM threats")
        results = self.cursor.fetchall()
        threats_file = self._export_results(results, "all_threats", format)
        if threats_file:
            exported_files.append(threats_file)
        
        # Export threat types
        self.cursor.execute("""
            SELECT threat_type, COUNT(*) as count 
            FROM threats 
            GROUP BY threat_type
        """)
        results = self.cursor.fetchall()
        types_file = self._export_results(results, "threat_types", format)
        if types_file:
            exported_files.append(types_file)
        
        print(f"Exported {len(exported_files)} files to {self.export_dir}")
        return exported_files
    
    def export_ioc_list(self, threat_type=None, filename=None):
        """
        Exports a simple list of IOCs (Indicators of Compromise) for integration with security tools.
        
        Args:
            threat_type: Optional filter by threat type
            filename: Optional filename
        """
        if threat_type:
            self.cursor.execute("SELECT value FROM threats WHERE threat_type = ?", (threat_type,))
            if not filename:
                filename = f"ioc_list_{threat_type}"
        else:
            self.cursor.execute("SELECT threat_type, value FROM threats")
            if not filename:
                filename = "all_iocs"
        
        results = self.cursor.fetchall()
        if not results:
            print("No IOCs found.")
            return None
            
        full_path = os.path.join(self.export_dir, f"{filename}.txt")
        
        with open(full_path, 'w') as file:
            if threat_type:
                # Simple list of values
                for row in results:
                    file.write(f"{row[0]}\n")
            else:
                # Format as type:value
                for row in results:
                    file.write(f"{row[0]}:{row[1]}\n")
        
        print(f"IOC list exported to: {full_path}")
        return full_path
    
    def custom_query(self, query, params=(), export=False, filename=None, format="txt"):
        """Executes a custom SQL query."""
        try:
            self.cursor.execute(query, params)
            results = self.cursor.fetchall()
            self._print_results(results)
            
            if export:
                if not filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"custom_query_{timestamp}"
                return self._export_results(results, filename, format)
            return None
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None
    
    def close_connection(self):
        """Closes the database connection."""
        self.conn.close()
        
def parse_arguments():
    """Parse command line arguments for common threat intelligence queries."""
    parser = argparse.ArgumentParser(description="Threat Intelligence Query Tool")
    
    # Query type
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument("--all", action="store_true", help="Get all threats")
    query_group.add_argument("--type", type=str, help="Get threats by type (e.g., url, domain, ip, ip_port, cidr)")
    query_group.add_argument("--source", type=str, help="Get threats by source name")
    query_group.add_argument("--since", type=str, help="Get threats since datetime (YYYY-MM-DD HH:MM:SS)")
    query_group.add_argument("--search", type=str, help="Search for specific term in threat values")
    query_group.add_argument("--counts", action="store_true", help="Get threat counts by source")
    query_group.add_argument("--export-all", action="store_true", help="Export all data")
    query_group.add_argument("--ioc-list", action="store_true", help="Export IOC list")
    query_group.add_argument("--cidr", action="store_true", help="Get all CIDR threats")
    query_group.add_argument("--custom", type=str, help="Run custom SQL query")
    
    # Export options
    parser.add_argument("--export", action="store_true", help="Export results to file")
    parser.add_argument("--format", type=str, choices=["txt", "csv", "json"], default="txt", 
                        help="Export format (default: txt)")
    parser.add_argument("--filename", type=str, help="Custom filename for export (without extension)")
    
    # IOC list specific options
    parser.add_argument("--ioc-type", type=str, help="Filter IOC list by threat type")
    
    # Database options
    parser.add_argument("--db", type=str, default="threat_intel.db", help="Database file path")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    # Initialize querier with specified database
    querier = ThreatQuerier(db_name=args.db)
    
    try:
        # Process the requested query
        if args.all:
            querier.get_all_threats(export=args.export, filename=args.filename, format=args.format)
        
        elif args.type:
            querier.get_threats_by_type(args.type, export=args.export, filename=args.filename, format=args.format)
        
        elif args.source:
            querier.get_threats_by_source(args.source, export=args.export, filename=args.filename, format=args.format)
        
        elif args.since:
            querier.get_threats_since(args.since, export=args.export, filename=args.filename, format=args.format)
        
        elif args.search:
            querier.search_threats(args.search, export=args.export, filename=args.filename, format=args.format)
        
        elif args.counts:
            querier.get_threat_counts_by_source(export=args.export, filename=args.filename, format=args.format)
        
        elif args.export_all:
            querier.export_all_data(format=args.format)
        
        elif args.ioc_list:
            querier.export_ioc_list(threat_type=args.ioc_type, filename=args.filename)
            
        elif args.cidr:
            querier.get_cidr_threats(export=args.export, filename=args.filename, format=args.format)
        
        elif args.custom:
            querier.custom_query(args.custom, export=args.export, filename=args.filename, format=args.format)
        elif args.search:
            querier.search_threats(args.search, export=args.export, filename=args.filename, format=args.format)
        
        elif args.counts:
            querier.get_threat_counts_by_source(export=args.export, filename=args.filename, format=args.format)
        
        elif args.export_all:
            querier.export_all_data(format=args.format)
        
        elif args.ioc_list:
            querier.export_ioc_list(threat_type=args.ioc_type, filename=args.filename)
            
        elif args.cidr:
            querier.get_cidr_threats(export=args.export, filename=args.filename, format=args.format)
        
        elif args.custom:
            querier.custom_query(args.custom, export=args.export, filename=args.filename, format=args.format)
        elif args.search:
            querier.search_threats(args.search, export=args.export, filename=args.filename, format=args.format)
        
        elif args.counts:
            querier.get_threat_counts_by_source(export=args.export, filename=args.filename, format=args.format)
        
        elif args.export_all:
            querier.export_all_data(format=args.format)
        
        elif args.ioc_list:
            querier.export_ioc_list(threat_type=args.ioc_type, filename=args.filename)
        
        elif args.custom:
            querier.custom_query(args.custom, export=args.export, filename=args.filename, format=args.format)
    
    finally:
        querier.close_connection()