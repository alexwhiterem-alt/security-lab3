import json
import subprocess
import platform

def get_os_info():
    info = {}
    
    # Читаем /etc/os-release
    os_release = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, val = line.split("=", 1)
                    os_release[key] = val.strip('"')
    except Exception:
        pass

    info["name"] = os_release.get("NAME", platform.system())
    info["version"] = os_release.get("VERSION", platform.release())
    info["arch"] = platform.machine()
    info["id"] = os_release.get("ID", "")
    info["version_id"] = os_release.get("VERSION_ID", "")
    
    pretty = os_release.get("PRETTY_NAME", "")
    if pretty:
        info["description"] = pretty
    else:
        info["description"] = info["name"] + " " + info["version"]
    
    codename = os_release.get("VERSION_CODENAME", "")
    if codename:
        info["codename"] = codename

    return info

def get_packages():
    packages = []
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}|${Installed-Size}|${Description}\n"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("|", 4)
            if len(parts) < 5:
                continue
            name, version, arch, size, description = parts
            
            # Берём первое предложение или строку описания
            desc_clean = description.strip()
            if desc_clean:
                first_line = desc_clean.split("\n")[0].strip()
            else:
                first_line = ""

            pkg = {
                "name": name.strip(),
                "version": version.strip(),
                "arch": arch.strip(),
            }
            if first_line:
                pkg["description"] = first_line
            if size.strip():
                try:
                    pkg["size"] = int(size.strip())
                except ValueError:
                    pass

            packages.append(pkg)
    except Exception as e:
        print(f"Ошибка получения пакетов: {e}")
    
    return packages

result = {
    "os": get_os_info(),
    "packages": get_packages()
}

with open("result_task_4.json", "w") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

total = len(result["packages"])
print(f"ОС: {result['os'].get('description')}")
print(f"Архитектура: {result['os'].get('arch')}")
print(f"Всего пакетов: {total}")
print("Сохранено в result_task_4.json")