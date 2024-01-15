#!/usr/bin/env python3.11

import re
import json
import os
import syslog
import subprocess
from datetime import datetime

# Variables
AIDE_DB_SRC  = '/var/lib/aide/aide.db.new.gz'
AIDE_DB_DST  = '/var/lib/aide/aide.db.gz'
AIDE_LOG_SRC = '/var/log/aide/aide.log'
AIDE_LOG_TMP = '/var/log/aide/aide_temp.json'
AIDE_LOG_DST = '/var/log/aide/aide.json'
MAX_LENGTH   = 100 # Set log character truncation lenght size

def truncateString(value, max_length=MAX_LENGTH):
    """
    Truncates a string to a specified maximum length.

    :param value: The string to truncate.
    :param max_length: The maximum allowed length for the string.
    :return: The truncated string.
    """    
    return value[:max_length - 3] + '...' if len(value) > max_length else value

def currentTimestamp():
    """
    Gets the current UTC timestamp in a specific format.
    Date format is mandatory for OCI log ingestor.

    :return: The formatted UTC timestamp.
    """
    daytime = datetime.utcnow()
    return daytime.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

def configExist():
    """
    Checks for the existence of required configuration files.
    """
    files = [AIDE_DB_DST, AIDE_LOG_SRC]
    missing_files = [file for file in files if not os.path.exists(file)]
    
    if missing_files:
        for file in missing_files:
            syslog.syslog(syslog.LOG_ERR, f"Error: Expected config file {file} does not exist.")
        return False
    return True

def aideJson(log_file_path):
    """
    Opens an log input file, creates state transitions and summary patterns for input log, regexes data, appends to JSON output.
    Parses the AIDE log into a structured JSON format.

    :param log_file_path: Path to the AIDE log file.
    :return: Dictionary representation of the parsed log.
    """
    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        syslog.syslog(syslog.LOG_ERR, f"Error: The file {log_file_path} does not exist.")
        return None
    except PermissionError:
        syslog.syslog(syslog.LOG_ERR, f"Error: Permission denied when accessing {log_file_path}.")
        return None
    if not lines:
        syslog.syslog(syslog.LOG_ERR, f"Error: Log file is empty.")
        return None

    # Check for proper starting and ending lines
    if not lines[0].startswith("Start timestamp:"):
        syslog.syslog(syslog.LOG_ERR, f"Error: Invalid log format. Missing 'Start timestamp:' at the beginning.")
        return None
    if not lines[-1].startswith("End timestamp:"):
        syslog.syslog(syslog.LOG_ERR, f"Error: Invalid log format. Missing 'End timestamp:' at the end.")
        return None
    
    # Check for "no differences" or other errors
    if len(lines) < 2 or ("AIDE found differences between database and filesystem!!" not in lines[1] and "AIDE, version" not in lines[1]):
        syslog.syslog(syslog.LOG_ERR, f"Error: No differences found or invalid log format.")
        return None

    # JSON data dicts
    data = {
        "timestamp": None,
        "error_severity": "LOG",
        "application_name": "AIDE",
        "backend_type": "log_analyzer",
        "added_entries": [],
        "removed_entries": [],
        "changed_entries": [],
        "message": "AIDE Log Analysis",
    }

    summary_patterns = {
        "Total number of entries": "total_entries",
        "Added entries": "added_summary",
        "Removed entries": "removed_summary",
        "Changed entries": "changed_summary",
    }

    state = "initial"

    for line in lines:
        stripped_line = line.strip()

        # Check for the start timestamp
        if "Start timestamp:" in line:
            data["timestamp"] = currentTimestamp()
            continue

        # Check for summary patterns
        for label, key in summary_patterns.items():
            match = re.search(f"\s*{label}:\s+(\d+)", stripped_line)
            if match:
                data[key] = int(match.group(1))
                break

        # State transitions
        if "Added entries:" in stripped_line:
            state = "added"
            continue
        elif "Removed entries:" in stripped_line:
            state = "removed"
            continue
        elif "Changed entries:" in stripped_line:
            state = "changed"
            continue

        # Check for entries and append to respective lists
        if re.match(r'^\s*[fd](\s+.*|\s*[+\-.]+):\s*\/', stripped_line):
            path = stripped_line.split(": ", 1)[1]
            if state == "added":
                data["added_entries"].append(truncateString(path))
            elif state == "removed":
                data["removed_entries"].append(truncateString(path))
            elif state == "changed":
                data["changed_entries"].append(truncateString(path))
    return data

def aideCheck():
    """
    Checks the system for changes using AIDE and logs the results.

    :return: Boolean value indicating success or failure of the check.
    """
    try:
        result = subprocess.run(['aide', '--check'], capture_output=True, text=True)
        
        if result.returncode in range(8):
            syslog.syslog(syslog.LOG_INFO, f"AIDE Check: Changes detected.")
            return True
        else:
            syslog.syslog(syslog.LOG_ERR, f"AIDE Check: Command failed with error:\n{result.stderr}")
            return False
            
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"AIDE Check: Command failed with error:\n{e}")
        return False
   
def aideUpdate():
    """
    Updates the AIDE database and manages associated file operations.

    :return: Boolean value indicating success or failure of the update.
    """    
    try:
        subprocess.run(['aide', '--update'])
        
        if os.path.exists(AIDE_DB_SRC):
            os.rename(AIDE_DB_SRC, AIDE_DB_DST)
        else:
            syslog.syslog(syslog.LOG_ERR, f"AIDE Update: Error: Source file {AIDE_DB_SRC} does not exist.")
            return False

        syslog.syslog(syslog.LOG_INFO, "AIDE Update: AIDE database updated successfully!")
        return True
        
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"AIDE Update: Updating AIDE database failed with error:\n{e}")
        return False

def mainWorkflow():
    """
    Orchestrates the entire workflow of:
    1. Checking the system with AIDE.
    2. Parsing the log results to JSON.
    3. Updating the AIDE database.
    """
    if not configExist():
        syslog.syslog(syslog.LOG_ERR, "Exiting due to missing configuration files.")
        return

    # Run the AIDE check
    if not aideCheck():
        syslog.syslog(syslog.LOG_ERR, "AIDE Check: failed. Exiting...")
        return
    
    # If AIDE check succeeded and generated the aide.log
    if not os.path.exists(AIDE_LOG_SRC):
        syslog.syslog(syslog.LOG_ERR, f"AIDE Check: Error: Expected log file {AIDE_LOG_SRC} not found after AIDE check. Exiting...")
        return

    # Parse the aide.log to JSON aide.json  
    data = aideJson(AIDE_LOG_SRC)

    if data is None:
        syslog.syslog(syslog.LOG_ERR, f"AIDE Parse: Error: in parsing AIDE log. Exiting...")
        return

    with open(AIDE_LOG_TMP, 'w') as file:
        file.write(json.dumps(data, separators=(',', ':')))
        file.write('\n')
    
    if os.path.exists(AIDE_LOG_TMP):
        os.rename(AIDE_LOG_TMP, AIDE_LOG_DST)
    else:
        syslog.syslog(syslog.LOG_ERR, f"AIDE Parse: Error: Temporary JSON log {AIDE_LOG_TMP} not found. Exiting...")
        return
    
    # Update the AIDE database
    if not aideUpdate():
        syslog.syslog(syslog.LOG_ERR, "AIDE Update: Failed to update AIDE database. Exiting...")
        return

    syslog.syslog(syslog.LOG_INFO, "Workflow completed successfully!")

if __name__ == '__main__':
    mainWorkflow()
