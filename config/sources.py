"""
Source definitions for the threat intelligence application.
"""
import logging
import json
import os
from colorama import Fore, Style

logger = logging.getLogger(__name__)

# Define check frequencies for different categories
# These can be easily modified to preferred values
FREQUENCY = {
    "QUICK": 300,       # 5 minutes - for rapidly changing feeds
    "STANDARD": 600,    # 10 minutes - default for most feeds
    "SLOW": 1800,       # 30 minutes - for slower-changing feeds
    "DAILY": 86400      # 24 hours - for feeds that update once per day
}

SOURCES_FILE_PATH = os.path.join(os.path.dirname(__file__), "sources.json")

def add_default_sources(app):
    """
    Add default sources to the application from the sources.json file.
    
    Args:
        app: IntelligenceFeedApp instance
    """
    logger.info(f"{Fore.CYAN}Loading threat intelligence sources from {SOURCES_FILE_PATH}{Style.RESET_ALL}")
    
    if not os.path.exists(SOURCES_FILE_PATH):
        logger.warning(f"{Fore.YELLOW}Warning: Sources file not found at {SOURCES_FILE_PATH}. No sources will be loaded.{Style.RESET_ALL}")
        return

    try:
        with open(SOURCES_FILE_PATH, 'r') as f:
            sources_data = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"{Fore.RED}Error: Could not decode JSON from {SOURCES_FILE_PATH}. Ensure it is valid JSON.{Style.RESET_ALL}")
        return
    except Exception as e:
        logger.error(f"{Fore.RED}Error reading sources file {SOURCES_FILE_PATH}: {e}{Style.RESET_ALL}")
        return

    if not sources_data:
        logger.warning(f"{Fore.YELLOW}Warning: Sources file {SOURCES_FILE_PATH} is empty. No sources will be loaded.{Style.RESET_ALL}")
        return

    count_added = 0
    for source in sources_data:
        name = source.get("name")
        url = source.get("url")
        frequency_alias = source.get("frequency_alias")

        if not all([name, url, frequency_alias]):
            logger.warning(f"{Fore.YELLOW}Skipping source due to missing 'name', 'url', or 'frequency_alias': {source}{Style.RESET_ALL}")
            continue

        actual_frequency = FREQUENCY.get(frequency_alias.upper())
        if actual_frequency is None:
            logger.warning(f"{Fore.YELLOW}Skipping source '{name}': Invalid frequency_alias '{frequency_alias}'. Valid aliases are: {', '.join(FREQUENCY.keys())}{Style.RESET_ALL}")
            continue
            
        app.add_source(name, url, actual_frequency)
        count_added += 1
    
    if count_added > 0:
        logger.info(f"{Fore.GREEN}Successfully added {count_added} sources from {SOURCES_FILE_PATH}{Style.RESET_ALL}")
    else:
        logger.info(f"No sources were added from {SOURCES_FILE_PATH}.")