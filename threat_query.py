# threat_query.py (Separate query application)

import sqlite3
from datetime import datetime

class ThreatQuerier:
    def __init__(self, db_name="threat_intel.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()

    def _print_results(self, results):
        """Prints query results in a formatted way."""
        if self.cursor.description:
            headers = [col[0] for col in self.cursor.description]
            print("| " + " | ".join(headers) + " |")
            print("|" + "---|" * len(headers))

        for row in results:
            formatted_row = [str(item).replace("\n", "\\n") for item in row]
            print("| " + " | ".join(formatted_row) + " |")

    def get_all_threats(self):
        """Retrieves all threats from the database."""
        self.cursor.execute("SELECT * FROM threats")
        self._print_results(self.cursor.fetchall())

    def get_threats_by_type(self, threat_type):
        """Retrieves threats of a specific type."""
        self.cursor.execute("SELECT * FROM threats WHERE threat_type = ?", (threat_type,))
        self._print_results(self.cursor.fetchall())

    def get_threats_by_source(self, source_name):
        """Retrieves threats from a specific source."""
        self.cursor.execute("""
            SELECT t.* FROM threats t
            JOIN sources s ON t.source_id = s.id
            WHERE s.name = ?
        """, (source_name,))
        self._print_results(self.cursor.fetchall())

    def get_threats_since(self, since_datetime):
        """Retrieves threats seen since a given datetime."""
        if isinstance(since_datetime, str):
             since_datetime = datetime.strptime(since_datetime, "%Y-%m-%d %H:%M:%S")

        self.cursor.execute("SELECT * FROM threats WHERE last_seen >= ?", (since_datetime,))
        self._print_results(self.cursor.fetchall())
    
    def get_threat_counts_by_source(self):
        """Retrieves the number of threats from each source."""
        self.cursor.execute("""
            SELECT s.name, COUNT(t.id)
            FROM threats t
            JOIN sources s ON t.source_id = s.id
            GROUP BY s.name
        """)
        self._print_results(self.cursor.fetchall())

    def search_threats(self, search_term):
        """Searches for threats containing a specific term in the value."""
         # Use LIKE for partial matching
        self.cursor.execute("SELECT * FROM threats WHERE value LIKE ?", (f"%{search_term}%",))
        self._print_results(self.cursor.fetchall())

    def custom_query(self, query, params=()):
        """Executes a custom SQL query."""
        try:
            self.cursor.execute(query, params)
            self._print_results(self.cursor.fetchall())
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def close_connection(self):
        """Closes the database connection."""
        self.conn.close()



if __name__ == "__main__":
    querier = ThreatQuerier()

    # Examples
    print("All Threats:")
    querier.get_all_threats()

    print("\nMalware Hosts:")
    querier.get_threats_by_type("malware_host")

    print("\nThreats from urlhaus_text:")
    querier.get_threats_by_source("urlhaus_text")

    print("\nThreats since 2023-10-27 12:00:00:")  # Replace with an actual date/time
    querier.get_threats_since("2023-10-27 12:00:00")

    print("\nThreat Counts by Source:")
    querier.get_threat_counts_by_source()

    print("\nSearching for threats containing 'example.com':")
    querier.search_threats("example.com")

    print("\nCustom Query Example (threats with a specific source ID):")
    querier.custom_query("SELECT * FROM threats WHERE source_id = ?", (1,))

    querier.close_connection()