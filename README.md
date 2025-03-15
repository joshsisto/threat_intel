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
pip install -r requirements.txt
```

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

You can add custom sources by modifying `config/sources.py` or by using the `add_source` method:

```python
app.add_source(
    name="custom_source",
    url="https://example.com/threats.txt",
    frequency=FREQUENCY["STANDARD"]
)
```

## Exported Data

The application exports data to the following files:
- `exports/urls_master.txt` - URLs
- `exports/domains_master.txt` - Domain names
- `exports/ips_master.txt` - IP addresses
- `exports/cidrs_master.txt` - CIDR ranges

## Updated Threat Feeds Are Posted On My Website

[joshsisto.com](https://joshsisto.com/projects.html)

## License

[unlicense](LICENSE)