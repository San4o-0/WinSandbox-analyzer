def evaluate(static_result, dynamic_report):
    score = 0
    indicators = []

    if static_result.get("high_entropy"):
        score += 8
        indicators.append(("ind_high_entropy", {"entropy": static_result["entropy"]}))
    if static_result.get("extension_mismatch"):
        score += 8
        indicators.append(("ind_ext_mismatch", {}))
    if static_result.get("double_extension"):
        score += 6
        indicators.append(("ind_double_ext", {}))
    sus = static_result.get("suspicious_strings", [])
    if sus:
        score += min(len(sus) * 2, 12)
        indicators.append(("ind_sus_strings", {"items": ", ".join(sus[:8])}))
    if static_result.get("urls"):
        indicators.append(("ind_urls", {"count": len(static_result["urls"])}))

    if dynamic_report:
        np = dynamic_report.get("new_processes", []) or []
        ns = dynamic_report.get("new_services", []) or []
        nt = dynamic_report.get("new_tasks", []) or []
        na = dynamic_report.get("new_autoruns", []) or []
        nf = dynamic_report.get("new_files", []) or []
        nc = dynamic_report.get("new_connections", []) or []

        if np:
            score += min(len(np) * 5, 15)
            indicators.append(("ind_new_processes", {"items": ", ".join(np[:10])}))
        if na:
            score += min(len(na) * 10, 20)
            indicators.append(("ind_autoruns", {"count": len(na)}))
        if nt:
            score += min(len(nt) * 10, 20)
            indicators.append(("ind_new_tasks", {"items": ", ".join(nt[:10])}))
        if ns:
            score += min(len(ns) * 8, 20)
            indicators.append(("ind_new_services", {"items": ", ".join(ns[:10])}))
        if nf:
            score += min(len(nf), 15)
            indicators.append(("ind_new_files", {"count": len(nf)}))
        if nc:
            score += min(len(nc) * 5, 10)
            indicators.append(("ind_connections", {"items": ", ".join(nc[:10])}))
        if dynamic_report.get("launched") is False:
            indicators.append(("ind_not_launched", {}))

    score = min(score, 100)
    if score < 20:
        level = "clean"
    elif score < 50:
        level = "suspicious"
    else:
        level = "dangerous"

    return {"score": score, "level": level, "indicators": indicators}
