# Threat Intelligence Collector

A modular application for collecting, processing, and exporting threat intelligence data from various sources.

## Features

- Collects threat data from multiple sources
- Supports various threat types (URLs, domains, IPs, CIDR ranges)
- Automatic scheduled scanning of sources
- Deduplication of threat data
- Export to readable text files
- Automatic backup of export files

## Project Structure

```
threat_intel_collector/
├── __init__.py
├── main.py                 # Entry point
├── app.py                  # Main application class
├── utils/                  # Utility modules
├── database/               # Database operations
├── collectors/             # Source-specific collectors
├── exporters/              # Export functionality
└── config/                 # Configuration
```

## Installation

1. Clone the repository
2. Install dependencies:
```

## Configuration

### Database Name

The name of the SQLite database file can be configured using the `THREAT_INTEL_DB_NAME` environment variable. If this variable is not set, it defaults to `threat_intel.db`.

Example:
```bash
export THREAT_INTEL_DB_NAME="my_custom_threats.db"
python -m threat_intel_collector.main
```

### Threat Sources

Threat sources are defined in `config/sources.json`. This file allows you to customize the list of threat intelligence feeds the application will use.

The file should be an array of JSON objects, where each object represents a source and has the following properties:
*   `"name"`: A unique name for the source (e.g., `"urlhaus_text"`).
*   `"url"`: The URL of the threat feed.
*   `"frequency_alias"`: A string representing how often the source should be checked. Valid aliases are:
    *   `"QUICK"`: 5 minutes
    *   `"STANDARD"`: 10 minutes
    *   `"SLOW"`: 30 minutes
    *   `"DAILY"`: 24 hours

Example `config/sources.json`:
```json
[
  {
    "name": "urlhaus_text",
    "url": "https://urlhaus.abuse.ch/downloads/text/",
    "frequency_alias": "STANDARD"
  },
  {
    "name": "openphish",
    "url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "frequency_alias": "STANDARD"
  }
  // ... other sources
]
```

If `config/sources.json` is missing or invalid, the application will log a warning and start without loading any sources from it.

## Usage

Run the application with:

```
python -m threat_intel_collector.main
```

```
nohup ./start_threat_intel.sh &
```

The application will:
1. Initialize the database
2. Add default threat intelligence sources
3. Begin scheduled scanning of sources
4. Export collected threats to files in the `exports` directory

## Adding Custom Sources

Previously, sources were added in `config/sources.py`. This method is now deprecated. Please use `config/sources.json` to manage your threat intelligence sources.

## Exported Data

The application exports data to the following files:
- `exports/urls_master.txt` - URLs
- `exports/domains_master.txt` - Domain names
- `exports/ips_master.txt` - IP addresses
- `exports/cidrs_master.txt` - CIDR ranges

## Updated Threat Feeds Are Posted On My Website

[joshsisto.com](https://joshsisto.com/projects.html)

## Querying the Database

A command-line tool, `tools/threat_query.py`, is provided to directly query the threat intelligence database.

You can use it to perform various queries, such as retrieving all threats, filtering by type or source, or searching for specific indicators.

To see the available options, run:
```bash
python tools/threat_query.py --help
```

## License

[unlicense](LICENSE)