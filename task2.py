import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging.version import Version, InvalidVersion

from dotenv import load_dotenv
import os
load_dotenv()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
API_URL = "https://api.github.com/graphql"

QUERY = """
query($name: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
  securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $name) {
    nodes {
      advisory { ghsaId severity }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

def query_ghsa(name):
    payload = json.dumps({
        "query": QUERY,
        "variables": {"name": name, "ecosystem": "NPM"}
    }).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Content-Type": "application/json"
        }
    )
    # Пробуем до 5 раз с паузой между попытками
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            wait = (attempt + 1) * 2  # 2, 4, 6, 8, 10 секунд
            print(f"  [{name}] Попытка {attempt+1}/5 неудачна: {e}. Жду {wait}с...")
            time.sleep(wait)
    print(f"  [{name}] Все 5 попыток исчерпаны, пропускаем.")
    return None

def parse_version_safe(v_str):
    v_str = v_str.strip()
    try:
        return Version(v_str)
    except InvalidVersion:
        try:
            cleaned = v_str.replace("-rc", "rc").replace("-alpha", "a").replace("-beta", "b")
            return Version(cleaned)
        except InvalidVersion:
            return None

def version_in_range(version_str, vuln_range):
    v = parse_version_safe(version_str)
    if v is None:
        return False
    parts = [p.strip() for p in vuln_range.split(",")]
    for part in parts:
        part = part.strip()
        if part.startswith(">="):
            bound = parse_version_safe(part[2:].strip())
            if bound is None: continue
            if not (v >= bound): return False
        elif part.startswith(">"):
            bound = parse_version_safe(part[1:].strip())
            if bound is None: continue
            if not (v > bound): return False
        elif part.startswith("<="):
            bound = parse_version_safe(part[2:].strip())
            if bound is None: continue
            if not (v <= bound): return False
        elif part.startswith("<"):
            bound = parse_version_safe(part[1:].strip())
            if bound is None: continue
            if not (v < bound): return False
        elif part.startswith("="):
            bound = parse_version_safe(part[1:].strip())
            if bound is None: continue
            if not (v == bound): return False
    return True

def get_secure_version(vulns):
    versions = [v["first_patched_version"] for v in vulns if v.get("first_patched_version")]
    if not versions:
        return None
    parsed = []
    for ver_str in versions:
        v = parse_version_safe(ver_str)
        if v:
            parsed.append((v, ver_str))
    if not parsed:
        return versions[-1]
    parsed.sort(key=lambda x: x[0])
    return parsed[-1][1]

def process_dep(dep):
    name = dep["name"]
    version = dep["version"]

    # Пропускаем нестандартные версии
    if version.startswith("link:") or version == "*" or version.startswith("npm:"):
        return {
            "name": name,
            "version": version,
            "ecosystem": dep["ecosystem"],
            "url": dep["url"],
            "purl": dep["purl"],
            "vulnerabilities": [],
            "secure_version": None
        }

    data = query_ghsa(name)
    vulnerabilities = []

    if data and "data" in data:
        nodes = data["data"].get("securityVulnerabilities", {}).get("nodes", [])
        for node in nodes:
            vuln_range = node.get("vulnerableVersionRange", "")
            if version_in_range(version, vuln_range):
                fpv_obj = node.get("firstPatchedVersion")
                vulnerabilities.append({
                    "name": node["advisory"]["ghsaId"],
                    "severity": node["advisory"]["severity"],
                    "vulnerable_range": vuln_range,
                    "first_patched_version": fpv_obj["identifier"] if fpv_obj else None
                })

    return {
        "name": name,
        "version": version,
        "ecosystem": dep["ecosystem"],
        "url": dep["url"],
        "purl": dep["purl"],
        "vulnerabilities": vulnerabilities,
        "secure_version": get_secure_version(vulnerabilities) if vulnerabilities else None
    }

# Загружаем зависимости
with open("result_task_1.json", "r", encoding="utf-8") as f:
    deps = json.load(f)

results = [None] * len(deps)
total = len(deps)
completed = 0

print(f"Запускаем проверку {total} зависимостей (5 потоков параллельно)...")

with ThreadPoolExecutor(max_workers=5) as executor:
    future_to_idx = {executor.submit(process_dep, dep): i for i, dep in enumerate(deps)}
    for future in as_completed(future_to_idx):
        idx = future_to_idx[future]
        results[idx] = future.result()
        completed += 1
        if completed % 20 == 0 or completed == total:
            print(f"  [{completed}/{total}] обработано...")

with open("result_task_2.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

vulnerable = [r for r in results if r["vulnerabilities"]]
print(f"\nГотово!")
print(f"Всего зависимостей: {total}")
print(f"Уязвимых: {len(vulnerable)}")
print(f"Безопасных: {total - len(vulnerable)}")