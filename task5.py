import json
import subprocess
import sys
import os

def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr

def scan(sbom_file, output_file):
    print(f"Scanning {sbom_file}...")
    os.system(f"./osv-scanner --sbom {sbom_file} > {output_file} 2>&1")
    with open(output_file) as f:
        count = f.read().count("osv.dev")
    print(f"Vulnerabilities found: {count}")
    return count

def before():
    print("=== BEFORE UPDATE ===")
    print("Generating SBOM...")
    os.system("cdxgen -t os --spec-version 1.4 -o sbom_before.json")
    scan("sbom_before.json", "osv_before.txt")
    print("Done. Now run: sudo apt update && sudo apt upgrade -y")
    print("Then run: python3 task5.py after")

def after():
    print("=== AFTER UPDATE ===")
    print("Generating SBOM...")
    os.system("cdxgen -t os --spec-version 1.4 -o sbom_after.json")
    scan("sbom_after.json", "osv_after.txt")
    print("Done. Now run: python3 task5.py compare")

def compare():
    print("=== COMPARISON ===")

    # Сравниваем уязвимости
    with open("osv_before.txt") as f:
        vuln_before = f.read().count("osv.dev")
    with open("osv_after.txt") as f:
        vuln_after = f.read().count("osv.dev")

    print(f"\n--- Vulnerabilities ---")
    print(f"Before: {vuln_before}")
    print(f"After:  {vuln_after}")
    print(f"Diff:   {vuln_before - vuln_after}")

    # Сравниваем пакеты до/после
    before = json.load(open("sbom_before.json"))
    after = json.load(open("sbom_after.json"))

    b_pkgs = {c["name"]: c.get("version", "") for c in before.get("components", [])}
    a_pkgs = {c["name"]: c.get("version", "") for c in after.get("components", [])}

    updated = [(n, b_pkgs[n], a_pkgs[n]) for n in b_pkgs if n in a_pkgs and b_pkgs[n] != a_pkgs[n]]
    new_pkgs = [n for n in a_pkgs if n not in b_pkgs]
    removed_pkgs = [n for n in b_pkgs if n not in a_pkgs]

    print(f"\n--- Packages before/after ---")
    print(f"Before: {len(b_pkgs)}")
    print(f"After:  {len(a_pkgs)}")
    print(f"Updated: {len(updated)}")
    print(f"New: {len(new_pkgs)}")
    print(f"Removed: {len(removed_pkgs)}")
    print(f"\nTop 10 updated:")
    for name, v1, v2 in updated[:10]:
        print(f"  {name}: {v1} -> {v2}")

    # Сравниваем task4 vs cdxgen
    if os.path.exists("result_task_4.json"):
        task4 = json.load(open("result_task_4.json"))
        task4_pkgs = {p["name"] for p in task4["packages"]}
        sbom_pkgs = set(b_pkgs.keys())

        only_task4 = task4_pkgs - sbom_pkgs
        only_sbom = sbom_pkgs - task4_pkgs

        print(f"\n--- task4.py vs cdxgen ---")
        print(f"task4 packages: {len(task4_pkgs)}")
        print(f"cdxgen packages: {len(sbom_pkgs)}")
        print(f"Only in task4: {len(only_task4)}")
        print(f"Only in cdxgen: {len(only_sbom)}")
        print(f"Examples only in cdxgen: {list(only_sbom)[:5]}")

    # Сохраняем результат
    result = {
        "vulnerabilities": {"before": vuln_before, "after": vuln_after, "diff": vuln_before - vuln_after},
        "packages": {
            "before": len(b_pkgs), "after": len(a_pkgs),
            "updated": len(updated), "new": len(new_pkgs), "removed": len(removed_pkgs)
        },
        "task4_vs_cdxgen": {
            "task4": len(task4_pkgs) if os.path.exists("result_task_4.json") else 0,
            "cdxgen": len(sbom_pkgs),
            "only_in_cdxgen": len(only_sbom) if os.path.exists("result_task_4.json") else 0
        }
    }
    with open("result_task_5.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved to result_task_5.json")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 task5.py [before|after|compare]")
        sys.exit(1)
    
    mode = sys.argv[1]
    if mode == "before":
        before()
    elif mode == "after":
        after()
    elif mode == "compare":
        compare()
    else:
        print("Unknown mode. Use: before, after, compare")