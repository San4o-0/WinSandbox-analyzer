def evaluate(static_result, dynamic_report):
    score = 0
    indicators = []

    if static_result.get("high_entropy"):
        score += 8
        indicators.append(f"Висока ентропія ({static_result['entropy']}) — можливе пакування/шифрування")
    if static_result.get("extension_mismatch"):
        score += 8
        indicators.append("Розширення файлу не відповідає реальному типу")
    if static_result.get("double_extension"):
        score += 6
        indicators.append("Виявлено подвійне розширення (маскування)")
    sus = static_result.get("suspicious_strings", [])
    if sus:
        score += min(len(sus) * 2, 12)
        indicators.append(f"Підозрілі рядки/виклики API: {', '.join(sus[:8])}")
    if static_result.get("urls"):
        indicators.append(f"URL у файлі: {len(static_result['urls'])} шт.")

    if dynamic_report:
        np = dynamic_report.get("new_processes", []) or []
        ns = dynamic_report.get("new_services", []) or []
        nt = dynamic_report.get("new_tasks", []) or []
        na = dynamic_report.get("new_autoruns", []) or []
        nf = dynamic_report.get("new_files", []) or []
        nc = dynamic_report.get("new_connections", []) or []

        if np:
            score += min(len(np) * 5, 15)
            indicators.append(f"Нові процеси: {', '.join(np[:10])}")
        if na:
            score += min(len(na) * 10, 20)
            indicators.append(f"Зміни автозапуску/реєстру: {len(na)}")
        if nt:
            score += min(len(nt) * 10, 20)
            indicators.append(f"Нові заплановані завдання: {', '.join(nt[:10])}")
        if ns:
            score += min(len(ns) * 8, 20)
            indicators.append(f"Нові служби: {', '.join(ns[:10])}")
        if nf:
            score += min(len(nf), 15)
            indicators.append(f"Нові файли у чутливих теках: {len(nf)}")
        if nc:
            score += min(len(nc) * 5, 10)
            indicators.append(f"Мережеві з'єднання: {', '.join(nc[:10])}")
        if dynamic_report.get("launched") is False:
            indicators.append("Файл не вдалося запустити в пісочниці")

    score = min(score, 100)
    if score < 20:
        level = "Чистий"
    elif score < 50:
        level = "Підозрілий"
    else:
        level = "Небезпечний"

    return {"score": score, "level": level, "indicators": indicators}
