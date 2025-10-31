# core/scan_logger.py
import hashlib
import json
import os
from datetime import datetime

SCAN_LOG = os.path.expanduser("~/.pentscan/scan_history.json")

def log_scan(target: str, profile: str = "stealth"):
    """Registra un objetivo escaneado (solo hash SHA-256, sin IP en claro)"""
    os.makedirs(os.path.dirname(SCAN_LOG), exist_ok=True)
    try:
        with open(SCAN_LOG, 'r') as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        history = []
    
    record = {
        "target_hash": hashlib.sha256(target.encode()).hexdigest()[:16],
        "timestamp": datetime.now().isoformat(),
        "profile": profile
    }
    history.append(record)
    
    with open(SCAN_LOG, 'w') as f:
        json.dump(history, f, indent=2)