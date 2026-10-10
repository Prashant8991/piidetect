"""
Custom Rules and User-Defined Configuration Engine
Provides secure regex validation, complexity and ReDoS guards,
persistent storage in config/custom_rules.json, and runtime execution.
"""

import os
import re
import json
import time
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
CUSTOM_RULES_FILE = os.path.join(CONFIG_DIR, "custom_rules.json")

# Ensure config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)


def is_safe_regex(pattern: str) -> Tuple[bool, str]:
    """
    Validates that a regex pattern is safe to execute:
    - Non-empty and under 250 characters
    - Valid Python regular expression syntax
    - No nested unbounded quantifiers like (a+)+, (.*)* which trigger catastrophic backtracking
    - Passes an adversarial test string under 50ms timeout
    """
    if not pattern or not pattern.strip():
        return False, "Pattern cannot be empty"

    if len(pattern) > 250:
        return False, "Pattern exceeds maximum allowed length of 250 characters"

    # Reject known ReDoS catastrophic backtracking patterns: (X+)+, (X*)*, (X+)*, (X*)+
    if re.search(r'\([^)]*[+*]\)[+*]', pattern):
        return False, "Unsafe nested quantifiers detected (vulnerable to exponential backtracking)"

    # Syntax test
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return False, f"Invalid regular expression syntax: {str(e)}"

    # ReDoS stress test against repetitive adversarial string
    try:
        test_str = "a" * 35 + "!"
        t0 = time.perf_counter()
        rx.search(test_str)
        elapsed = time.perf_counter() - t0
        if elapsed > 0.05:
            return False, f"Regex failed latency security check ({elapsed*1000:.1f}ms exceeds 50ms safety limit)"
    except Exception as e:
        return False, f"Regex evaluation error: {str(e)}"

    return True, None


def load_custom_config() -> Dict[str, Any]:
    """Loads custom rules and allow-list from persistent JSON storage."""
    default_config = {
        "rules": [],
        "allowlist": []
    }
    if not os.path.exists(CUSTOM_RULES_FILE):
        save_custom_config(default_config)
        return default_config

    try:
        with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return default_config
            data.setdefault("rules", [])
            data.setdefault("allowlist", [])
            return data
    except Exception:
        return default_config


def save_custom_config(config_data: Dict[str, Any]) -> bool:
    """Saves custom rules and allow-list to persistent JSON storage."""
    try:
        with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception:
        return False


def add_custom_rule(entity_type: str, pattern: str, token_type: str = "CUSTOM", description: str = "") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Validates and persists a new custom rule."""
    is_safe, msg = is_safe_regex(pattern)
    if not is_safe:
        return False, msg, None

    clean_type = re.sub(r'[^A-Z0-9_]', '', entity_type.upper().strip())
    clean_token = re.sub(r'[^A-Z0-9_]', '', token_type.upper().strip()) or clean_type

    cfg = load_custom_config()
    rule_id = f"rule_{int(time.time()*1000)}"
    new_rule = {
        "id": rule_id,
        "entity_type": clean_type,
        "pattern": pattern,
        "token_type": clean_token,
        "description": description.strip(),
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    cfg["rules"].append(new_rule)
    save_custom_config(cfg)
    return True, "Custom rule added successfully", new_rule


def remove_custom_rule(rule_id: str) -> bool:
    """Removes a custom rule by ID."""
    cfg = load_custom_config()
    orig_len = len(cfg["rules"])
    cfg["rules"] = [r for r in cfg["rules"] if r.get("id") != rule_id]
    if len(cfg["rules"]) < orig_len:
        save_custom_config(cfg)
        return True
    return False


def test_rule_against_text(pattern: str, sample_text: str) -> List[Dict[str, Any]]:
    """Tests a custom regex against user-provided sample text before saving."""
    is_safe, msg = is_safe_regex(pattern)
    if not is_safe:
        raise ValueError(msg)

    rx = re.compile(pattern)
    matches = []
    for m in rx.finditer(sample_text):
        matches.append({
            "matched_text": m.group(0),
            "start": m.start(),
            "end": m.end()
        })
    return matches
