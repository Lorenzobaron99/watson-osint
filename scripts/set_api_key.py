#!/usr/bin/env python3
"""Set an API key in Watson's config.toml"""
import sys, json, os

key_name = sys.argv[1] if len(sys.argv) > 1 else "newscatcher"
key_value = sys.argv[2] if len(sys.argv) > 2 else ""

sys.path.insert(0, os.path.expanduser("~/Desktop/watson-osint/src"))
from watson.config import load_config, save_config

cfg = load_config()
cfg.setdefault("watson", {}).setdefault("api_keys", {})[key_name] = key_value
save_config(cfg)
print(f"✓ {key_name} API key saved to ~/.watson/config.toml")
