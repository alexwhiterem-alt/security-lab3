import json

with open("result_task_2.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Оставляем только уязвимые
vulnerable = [d for d in data if d["vulnerabilities"]]

# Считаем количество уязвимостей по критичности для каждой зависимости
def count_severities(vulns):
    counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    for v in vulns:
        sev = v["severity"]
        if sev in counts:
            counts[sev] += 1
    return counts

def recommend_strategy(dep):
    secure = dep.get("secure_version")
    vulns = dep["vulnerabilities"]
    severities = count_severities(vulns)

    if not secure:
        return "Обновление недоступно — мониторить уязвимость, рассмотреть замену пакета"

    if severities["CRITICAL"] > 0 or severities["HIGH"] > 0:
        return f"Срочно обновить до {secure}"
    elif severities["MODERATE"] > 0:
        return f"Обновить до {secure} в ближайшем релизе"
    else:
        return f"Обновить до {secure} при плановом обновлении зависимостей"

# Сортируем по убыванию количества уязвимостей
vulnerable.sort(key=lambda x: len(x["vulnerabilities"]), reverse=True)

# Выводим таблицу
print(f"{'№':<4} {'Пакет':<45} {'Версия':<20} {'Экосистема':<8} {'CRIT':<6} {'HIGH':<6} {'MOD':<6} {'LOW':<6} {'Всего':<7} {'Безоп. версия':<20} Стратегия")
print("-" * 200)

rows = []
for i, dep in enumerate(vulnerable, 1):
    sev = count_severities(dep["vulnerabilities"])
    total = len(dep["vulnerabilities"])
    secure = dep.get("secure_version") or "—"
    strategy = recommend_strategy(dep)

    rows.append({
        "№": i,
        "name": dep["name"],
        "version": dep["version"],
        "ecosystem": dep["ecosystem"],
        "CRITICAL": sev["CRITICAL"],
        "HIGH": sev["HIGH"],
        "MODERATE": sev["MODERATE"],
        "LOW": sev["LOW"],
        "total": total,
        "secure_version": secure,
        "strategy": strategy
    })

    print(f"{i:<4} {dep['name']:<45} {dep['version']:<20} {dep['ecosystem']:<8} {sev['CRITICAL']:<6} {sev['HIGH']:<6} {sev['MODERATE']:<6} {sev['LOW']:<6} {total:<7} {secure:<20} {strategy}")

# Сохраняем в JSON для отчёта
with open("result_task_3.json", "w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)

print(f"\nВсего уязвимых зависимостей: {len(vulnerable)}")
print(f"Результат сохранён в result_task_3.json")