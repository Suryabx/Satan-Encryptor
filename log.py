# log.py

import os
from datetime import datetime

LOG_FILE = "satan.log"

def write_log(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{level.upper()}] {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

def read_log():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()

def clear_log():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)