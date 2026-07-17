import json
import os

import config

SETTINGS_FILE = os.path.join(config.BASE_DIR, "settings.json")

DEFAULTS = {"language": "uk", "theme": "dark"}
VALID = {"language": {"uk", "en"}, "theme": {"dark", "light"}}


def load():
    result = dict(DEFAULTS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return result
    for key, allowed in VALID.items():
        if data.get(key) in allowed:
            result[key] = data[key]
    return result


def save(settings):
    try:
        os.makedirs(config.BASE_DIR, exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except OSError:
        pass
