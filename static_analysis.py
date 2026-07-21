import hashlib
import math
import os
import re

import config
import deep_scan


def compute_hashes(path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def compute_entropy(path, sample_size=4 * 1024 * 1024):
    with open(path, "rb") as f:
        data = f.read(sample_size)
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def detect_file_type(path):
    with open(path, "rb") as f:
        header = f.read(16)
    for magic, name in config.MAGIC_SIGNATURES:
        if header.startswith(magic):
            return name
    if all(32 <= b < 127 or b in (9, 10, 13) for b in header):
        return "Text/script"
    return "Unknown binary"


def find_suspicious_strings(path, limit=8 * 1024 * 1024):
    with open(path, "rb") as f:
        data = f.read(limit)
    text = data.decode("latin-1", errors="ignore")
    found = []
    for s in config.SUSPICIOUS_STRINGS:
        if s.lower() in text.lower():
            found.append(s)
    urls = re.findall(r"https?://[^\s\"'<>]{8,120}", text)
    return found, list(dict.fromkeys(urls))[:20]


def check_extension_mismatch(path, real_type):
    ext = os.path.splitext(path)[1].lower()
    doc_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".mp4", ".mp3"}
    if ext in doc_exts and "executable" in real_type.lower():
        return True
    return False


def check_double_extension(path):
    name = os.path.basename(path).lower()
    parts = name.split(".")
    if len(parts) >= 3 and "." + parts[-1] in config.EXECUTABLE_EXTENSIONS:
        fake = "." + parts[-2]
        if fake in {".pdf", ".doc", ".docx", ".xls", ".jpg", ".png", ".txt", ".mp3", ".mp4"}:
            return True
    return False


def group_behaviors(found):
    groups = []
    seen = set()
    for category, markers in config.BEHAVIOR_CATEGORIES:
        hits = [s for s in found if s in markers]
        if hits:
            groups.append((category, hits))
            seen.update(hits)
    rest = [s for s in found if s not in seen]
    if rest:
        groups.append(("cat_other", rest))
    return groups


def analyze(path):
    sha256, md5 = compute_hashes(path)
    entropy = compute_entropy(path)
    ftype = detect_file_type(path)
    sus_strings, urls = find_suspicious_strings(path)
    result = {
        "file_name": os.path.basename(path),
        "file_size": os.path.getsize(path),
        "sha256": sha256,
        "md5": md5,
        "entropy": entropy,
        "detected_type": ftype,
        "extension": os.path.splitext(path)[1].lower(),
        "suspicious_strings": sus_strings,
        "behaviors": group_behaviors(sus_strings),
        "urls": urls,
        "extension_mismatch": check_extension_mismatch(path, ftype),
        "double_extension": check_double_extension(path),
        "high_entropy": entropy >= 7.4,
        "is_executable_type": "executable" in ftype.lower()
        or os.path.splitext(path)[1].lower() in config.EXECUTABLE_EXTENSIONS,
    }
    result["deep"] = deep_scan.analyze(path, ftype)
    return result
