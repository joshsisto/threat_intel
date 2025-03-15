#!/usr/bin/env python3
"""
Threat Intelligence Feed Application - Main Entry Point
"""
import sys
import signal
import logging
from colorama import Fore, Style

from app import IntelligenceFeedApp
from config.sources import add_default_sources
from utils.logging_config import setup_logging

logger = logging.getLogger(__name__)

def signal_handler(sig, frame):
    """Handle interrupt signals for graceful shutdown."""
    print(f"\n{Fore.YELLOW}Received signal {sig}, shutting down gracefully...{Style.RESET_ALL}")
    if hasattr(app, 'close_connection'):
        app.close_connection()
    sys.exit(0)

if __name__ == "__main__":
    # Set up logging
    setup_logging()
    
    print(f"{Fore.GREEN}Starting Threat Intelligence Feed Application{Style.RESET_ALL}")
    print("Press Ctrl+C to exit")
    
    # Create application instance
    app = IntelligenceFeedApp()
    
    # Add default sources
    add_default_sources(app)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Start the scheduler
        app.run_scheduler()
    except KeyboardInterrupt:
        # This is handled by the signal handler
        pass
    except Exception as e:
        logger.error(f"{Fore.RED}Unhandled exception: {e}{Style.RESET_ALL}")
        logger.exception("Stack trace:")
    finally:
        app.close_connection()