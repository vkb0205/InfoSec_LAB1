import json
import os
from typing import Any, Dict, Optional

DATA_DIR = os.getenv("DATA_DIR", "./data")

def _get_file_path(filename: str) -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    return os.path.join(DATA_DIR, filename)

def load_json(filename: str) -> Dict[str, Any]:
    """Load data from a JSON file safely. If the file does not exist or is invalid, return an empty dict."""
    file_path = _get_file_path(filename)
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_json(filename: str, data: Dict[str, Any]) -> None:
    """Save data to a JSON file safely."""
    file_path = _get_file_path(filename)
    # Write to a temporary file first, then replace the original to avoid data corruption
    temp_path = f"{file_path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, file_path)