import json
import urllib.error
import urllib.request

import config


def _request(url, headers, timeout):
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def lookup(sha256, api_key):
    if not api_key:
        return {"state": "no_key"}
    url = config.VT_API_URL + sha256
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        payload = _request(url, headers, config.VT_TIMEOUT)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"state": "unknown"}
        if error.code in (401, 403):
            return {"state": "bad_key"}
        if error.code == 429:
            return {"state": "rate_limited"}
        return {"state": "error", "detail": f"HTTP {error.code}"}
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"state": "offline"}
    except (json.JSONDecodeError, ValueError):
        return {"state": "error", "detail": "bad response"}

    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    names = []
    for engine, result in (attributes.get("last_analysis_results") or {}).items():
        if result.get("category") in ("malicious", "suspicious") and result.get("result"):
            names.append(f"{engine}: {result['result']}")
    names.sort()

    return {
        "state": "found",
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "reputation": int(attributes.get("reputation", 0) or 0),
        "times_submitted": int(attributes.get("times_submitted", 0) or 0),
        "label": (attributes.get("popular_threat_classification") or {}).get(
            "suggested_threat_label", ""
        ),
        "names": names[:6],
    }
