"""
Source definitions for the threat intelligence application.
"""
import logging
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

def add_default_sources(app):
    """
    Add default sources to the application.
    
    Args:
        app: IntelligenceFeedApp instance
    """
    logger.info(f"{Fore.CYAN}Adding default threat intelligence sources{Style.RESET_ALL}")
    
    # URL Feeds - typically update more frequently
    app.add_source("urlhaus_text", "https://urlhaus.abuse.ch/downloads/text/", FREQUENCY["STANDARD"])
    app.add_source("openphish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", FREQUENCY["STANDARD"])
    app.add_source("vxvault", "http://vxvault.net/URL_List.php", FREQUENCY["STANDARD"])
    
    # IP Feeds - typically update less frequently
    app.add_source("feodotracker_ipblocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", FREQUENCY["STANDARD"])
    app.add_source("binarydefense", "https://www.binarydefense.com/banlist.txt", FREQUENCY["STANDARD"])
    app.add_source("emergingthreats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", FREQUENCY["STANDARD"])
    app.add_source("cinsscore", "https://cinsscore.com/list/ci-badguys.txt", FREQUENCY["STANDARD"])
    app.add_source("elliotech", "https://cdn.ellio.tech/community-feed", FREQUENCY["SLOW"])
    app.add_source("stamparm", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt", FREQUENCY["SLOW"])
    app.add_source("mirai", "https://mirai.security.gives/data/ip_list.txt", FREQUENCY["STANDARD"])
    
    # IP CIDR Feeds - typically update less frequently
    app.add_source("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt", FREQUENCY["SLOW"])
    app.add_source("dshield", "https://dshield.org/block.txt", FREQUENCY["STANDARD"])
    app.add_source("firehol", "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset", FREQUENCY["DAILY"])
    
    # ThreatFox Feeds - contain recent threats, check frequently
    app.add_source("threatfox_urls", "https://threatfox.abuse.ch/export/csv/urls/recent/", FREQUENCY["STANDARD"])
    app.add_source("threatfox_domains", "https://threatfox.abuse.ch/export/csv/domains/recent/", FREQUENCY["STANDARD"])
    app.add_source("threatfox_ip_port", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", FREQUENCY["STANDARD"])
    
    logger.info(f"{Fore.GREEN}Added {16} default sources{Style.RESET_ALL}")