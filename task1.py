import json
import os
import glob

# Папка с проектом
PROJECT_DIR = "react-17.0.2"

# Поля зависимостей в package.json
DEP_FIELDS = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies"
]

def make_purl(name, version):
    # Формат Package URL для npm
    # Если имя начинается с @ — это scoped пакет, например @babel/core
    clean_version = version.lstrip("^~>=<").split(" ")[0]
    if name.startswith("@"):
        # @scope/name -> pkg:npm/%40scope/name@version
        encoded = name.replace("@", "%40", 1)
        return f"pkg:npm/{encoded}@{clean_version}"
    return f"pkg:npm/{name}@{clean_version}"

def make_url(name):
    if name.startswith("@"):
        encoded = name[1:].replace("/", "%2F")
        return f"https://www.npmjs.com/package/{name}"
    return f"https://www.npmjs.com/package/{name}"

def clean_version(version):
    # Убираем префиксы ^ ~ >= и берём первую часть
    v = version.strip().lstrip("^~>=<").split(" ")[0].split("|")[0].strip()
    return v

# Собираем все package.json
all_files = glob.glob(f"{PROJECT_DIR}/**/package.json", recursive=True)

# Словарь для дедупликации: ключ = (name, version)
seen = {}

for filepath in all_files:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Ошибка чтения {filepath}: {e}")
        continue

    for field in DEP_FIELDS:
        deps = data.get(field, {})
        if not isinstance(deps, dict):
            continue
        for name, version_raw in deps.items():
            v = clean_version(version_raw)
            key = (name, v)
            if key not in seen:
                seen[key] = {
                    "name": name,
                    "version": v,
                    "ecosystem": "npm",
                    "url": make_url(name),
                    "purl": make_purl(name, v)
                }

result = list(seen.values())
result.sort(key=lambda x: x["name"].lower())

with open("result_task_1.json", "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

print(f"Готово! Найдено уникальных зависимостей: {len(result)}")