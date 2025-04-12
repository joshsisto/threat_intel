# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands
- Run application: `python3 main.py`
- Start with monitoring: `bash start_threat_intel.sh`

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local imports
- **Naming**: snake_case for functions/variables, CamelCase for classes
- **Docstrings**: Triple quotes with function descriptions, Args/Returns sections
- **Error Handling**: Use try/except with specific exception types
- **Logging**: Use logging module with appropriate levels
- **File Structure**: Maintain modular approach (collectors, utils, database, exporters)
- **Functions**: Keep focused on single responsibility
- **Comments**: Explain complex logic, not obvious operations
- **Code Organization**: Group related functionality in appropriate modules
- **Dependencies**: Keep requirements.txt updated when adding new imports

## Development Notes
- Python 3.6+ recommended
- Primary dependencies: requests, sqlite3, schedule, colorama
- Color terminal output with colorama
- Consider implementing type hints in future development