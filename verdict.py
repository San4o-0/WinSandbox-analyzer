import config


def _card(key, severity, score, **params):
    return {"key": key, "severity": severity, "score": score, "params": params}


def _deep_cards(deep):
    score = 0
    cards = []

    if deep.get("signature_broken"):
        score += 20
        cards.append(_card("ind_sig_broken", "danger", 20,
                           status=deep.get("signature_status", "")))
    elif deep.get("signed") and deep.get("signer"):
        bonus = 22 if deep.get("signature_valid") else 14
        score -= bonus
        cards.append(_card("ind_signed", "trust", -bonus, signer=deep["signer"]))
    elif deep.get("is_pe"):
        score += 5
        cards.append(_card("ind_unsigned", "warn", 5))

    if deep.get("packer"):
        score += 12
        cards.append(_card("ind_packer", "warn", 12, packer=deep["packer"]))
    elif deep.get("packed_sections"):
        cards.append(_card("ind_packed_sections", "info", 0,
                           items=", ".join(deep["packed_sections"])))

    if deep.get("few_imports") and not deep.get("is_dotnet"):
        score += 4
        cards.append(_card("ind_few_imports", "info", 4,
                           count=deep.get("import_count", 0)))

    archive = deep.get("archive") or {}
    if archive.get("has_macros"):
        score += 14
        cards.append(_card("ind_macros", "danger", 14))
    if archive.get("nested_executables"):
        score += 10
        cards.append(_card("ind_nested_exe", "warn", 10,
                           count=len(archive["nested_executables"]),
                           items=", ".join(archive["nested_executables"][:6])))
    if archive.get("encrypted"):
        score += 6
        cards.append(_card("ind_encrypted_archive", "warn", 6))

    return score, cards


def evaluate(static_result, dynamic_report):
    score = 0
    cards = []

    deep = static_result.get("deep") or {}
    if deep:
        deep_score, deep_cards = _deep_cards(deep)
        score += deep_score
        cards.extend(deep_cards)

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

    disguised = static_result.get("extension_mismatch") or static_result.get(
        "double_extension"
    )
    has_severe = any(c["severity"] == "danger" and c["key"].startswith("cat_")
                     for c in cards)
    if disguised and has_severe:
        score += 18
        cards.append(_card("ind_combo_disguise", "danger", 18))

    score = max(0, min(score, 100))
    if score < 20:
        level = "clean"
    elif score < 50:
        level = "suspicious"
    else:
        level = "dangerous"

    order = {"danger": 0, "warn": 1, "trust": 2, "info": 3}
    cards.sort(key=lambda c: (order[c["severity"]], -c["score"]))

    return {
        "score": score,
        "level": level,
        "cards": cards,
        "analyzed_dynamically": bool(dynamic_report),
        "indicators": [(c["key"], c["params"]) for c in cards],
    }
