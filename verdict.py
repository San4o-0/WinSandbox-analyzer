import config


def _card(key, severity, score, **params):
    return {"key": key, "severity": severity, "score": score, "params": params}


def evaluate(static_result, dynamic_report):
    score = 0
    cards = []

    if static_result.get("extension_mismatch"):
        score += 8
        cards.append(_card("ind_ext_mismatch", "danger", 8))
    if static_result.get("double_extension"):
        score += 6
        cards.append(_card("ind_double_ext", "danger", 6))

    for category, hits in static_result.get("behaviors", []):
        severity = config.CATEGORY_SEVERITY.get(category, "info")
        weight = {"danger": 6, "warn": 3, "info": 1}[severity]
        gained = min(len(hits) * weight, 12)
        score += gained
        cards.append(_card(category, severity, gained, items=", ".join(hits[:8])))

    if static_result.get("high_entropy"):
        score += 8
        cards.append(
            _card("ind_high_entropy", "info", 8, entropy=static_result["entropy"])
        )
    if static_result.get("urls"):
        cards.append(
            _card("ind_urls", "info", 0, count=len(static_result["urls"]))
        )

    if dynamic_report:
        dyn = [
            ("new_autoruns", "ind_autoruns", "danger", 10, 20),
            ("new_tasks", "ind_new_tasks", "danger", 10, 20),
            ("new_services", "ind_new_services", "danger", 8, 20),
            ("new_processes", "ind_new_processes", "warn", 5, 15),
            ("new_connections", "ind_connections", "warn", 5, 10),
            ("new_files", "ind_new_files", "info", 1, 15),
        ]
        for field, key, severity, weight, cap in dyn:
            values = dynamic_report.get(field) or []
            if not values:
                continue
            gained = min(len(values) * weight, cap)
            score += gained
            cards.append(
                _card(
                    key,
                    severity,
                    gained,
                    count=len(values),
                    items=", ".join(str(v) for v in values[:10]),
                )
            )
        if dynamic_report.get("launched") is False:
            cards.append(_card("ind_not_launched", "info", 0))

    score = min(score, 100)
    if score < 20:
        level = "clean"
    elif score < 50:
        level = "suspicious"
    else:
        level = "dangerous"

    order = {"danger": 0, "warn": 1, "info": 2}
    cards.sort(key=lambda c: (order[c["severity"]], -c["score"]))

    return {
        "score": score,
        "level": level,
        "cards": cards,
        "analyzed_dynamically": bool(dynamic_report),
        "indicators": [(c["key"], c["params"]) for c in cards],
    }
