#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests
import yaml

# --- CONFIGURAZIONI ---
VULHUB_DIR = Path("./vulhub")
BATCH_SIZE = 3
START_PORT = 8100
START_BATCH = 56
AGENT_SCRIPT = "main.py"

# Lasciata invariata come richiesto.
API_KEY = "sk-13efa0e753d341e79e8f70a27de94331"
MODEL = "deepseek-chat"
API_URL = "https://api.deepseek.com/v1/chat/completions"

# Sicurezza risorse host.
DISK_PATH = "/"
MIN_FREE_GB = 8.0
MEMORY_RESERVE_MB = 1024
COMPOSE_CMD = ["docker-compose"]

# Pulizia limitata ai progetti gestiti da questo runner.
# Non esegue docker system prune e non rimuove file/log dell'agente.
REMOVE_PROJECT_VOLUMES = True
REMOVE_PROJECT_IMAGES = False

FALLBACK_PROMPT = "Conduciti in autonomia basandoti sulla descrizione della CVE."
ACTIVE_COMPOSE_FILES = set()


def file_hash(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as file_obj:
        for block in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_not_self(agent_path: Path):
    me = Path(__file__).resolve()
    other = agent_path.resolve()
    if me == other or file_hash(me) == file_hash(other):
        print(f"\nERRORE: '{agent_path.name}' è identico al runner.")
        print("Usa un file agente separato, ad esempio agent.py.")
        raise SystemExit(1)


def disk_free_gb(path: str = DISK_PATH) -> float:
    try:
        return shutil.disk_usage(path).free / (1024 ** 3)
    except OSError:
        return -1.0


def memory_available_mb() -> float:
    try:
        values = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as file_obj:
            for line in file_obj:
                key, value = line.split(":", 1)
                values[key] = float(value.strip().split()[0]) / 1024
        return values.get("MemAvailable", -1.0)
    except (OSError, ValueError):
        return -1.0


def print_resources(prefix: str = ""):
    free_disk = disk_free_gb()
    free_memory = memory_available_mb()
    disk_text = f"{free_disk:.2f} GB" if free_disk >= 0 else "n/d"
    memory_text = f"{free_memory:.0f} MB" if free_memory >= 0 else "n/d"
    print(f"{prefix}Spazio disco: {disk_text} | RAM disponibile: {memory_text}")


def run_command(command, cwd=None, timeout=120, check=False, quiet=False):
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=check,
            timeout=timeout,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if not quiet:
            print(f"⚠️ Comando fallito ({' '.join(command)}): {exc}")
        return None


def ensure_resources(required_batches=True):
    free_disk = disk_free_gb()
    free_memory = memory_available_mb()

    if free_disk >= 0 and free_disk < MIN_FREE_GB:
        print(f"❌ Spazio insufficiente: {free_disk:.2f} GB disponibili.")
        return False

    if required_batches and free_memory >= 0 and free_memory < MEMORY_RESERVE_MB:
        print(f"❌ RAM disponibile insufficiente: {free_memory:.0f} MB.")
        return False

    return True


def get_compose_files():
    return sorted(VULHUB_DIR.rglob("docker-compose.yml"))


def update_compose_port(compose_path: Path, starting_port: int):
    backup_path = compose_path.with_suffix(".yml.bak")
    if not backup_path.exists():
        shutil.copy2(compose_path, backup_path)

    with compose_path.open("r", encoding="utf-8") as file_obj:
        compose_data = yaml.safe_load(file_obj) or {}

    current_port = starting_port
    target_port = None

    for service_data in (compose_data.get("services") or {}).values():
        if not isinstance(service_data, dict) or "ports" not in service_data:
            continue

        new_ports = []
        for port_mapping in service_data["ports"] or []:
            mapping = str(port_mapping)
            parts = mapping.split(":")
            container_port = parts[-1]
            if target_port is None:
                target_port = current_port
            new_ports.append(f"{current_port}:{container_port}")
            current_port += 1
        service_data["ports"] = new_ports

    if target_port is None:
        raise ValueError(f"Nessuna porta pubblicata in {compose_path}")

    with compose_path.open("w", encoding="utf-8") as file_obj:
        yaml.safe_dump(compose_data, file_obj, sort_keys=False)

    return target_port, current_port


def restore_compose(compose_path: Path):
    backup_path = compose_path.with_suffix(".yml.bak")
    if backup_path.exists():
        shutil.move(str(backup_path), str(compose_path))


def project_cleanup(compose_files):
    print("\n🧹 Arresto e pulizia dei soli progetti del batch...")
    for compose_file in compose_files:
        command = COMPOSE_CMD + ["down", "--remove-orphans"]
        if REMOVE_PROJECT_VOLUMES:
            command.append("--volumes")
        if REMOVE_PROJECT_IMAGES:
            command.extend(["--rmi", "local"])

        run_command(command, cwd=compose_file.parent, timeout=180, quiet=True)
        restore_compose(compose_file)

    print_resources("   ")


def get_dynamic_custom_prompt(cve_id, max_retries=3):
    print(f"   🧠 Richiesta meta-prompt a DeepSeek per {cve_id}...")

    if not API_KEY or API_KEY.startswith("LA_TUA"):
        return FALLBACK_PROMPT

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Sei un penetration tester senior. Stiamo automatizzando test "
                    "in un laboratorio Vulhub locale. Devi fornire istruzioni "
                    "tecniche a un altro agente IA."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Scrivi un breve custom prompt, massimo 4-5 righe, per {cve_id}. "
                    "Non inserire codice exploit: indica endpoint, header o payload "
                    "utili per il test autorizzato in laboratorio."
                ),
            },
        ],
        "temperature": 0.3,
        "max_tokens": 300,
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                API_URL, headers=headers, json=payload, timeout=(10, 60)
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
            print(f"   ⚠️ Tentativo {attempt}/{max_retries}: {exc}")
            if attempt < max_retries:
                time.sleep(3 * attempt)

    return FALLBACK_PROMPT


def generate_config(cve_id, target_url, custom_prompt):
    config_data = {
        "cve": cve_id,
        "target": target_url,
        "deepseek_api_key": API_KEY,
        "deepseek_model": MODEL,
        "max_iterations": 10,
        "custom_prompt": custom_prompt,
    }
    config_path = Path("current_config.json")
    with config_path.open("w", encoding="utf-8") as file_obj:
        json.dump(config_data, file_obj, indent=4)
    return config_path


def cleanup_on_signal(signum, _frame):
    print(f"\n⚠️ Segnale {signum} ricevuto: pulizia dei container gestiti...")
    if ACTIVE_COMPOSE_FILES:
        project_cleanup([Path(path) for path in ACTIVE_COMPOSE_FILES])
    raise SystemExit(128 + signum)


def main():
    global ACTIVE_COMPOSE_FILES

    signal.signal(signal.SIGINT, cleanup_on_signal)
    signal.signal(signal.SIGTERM, cleanup_on_signal)

    agent_path = Path(AGENT_SCRIPT)
    if not agent_path.exists():
        print(f"❌ Agente non trovato: {agent_path}")
        return 1
    assert_not_self(agent_path)

    compose_files = get_compose_files()
    total_cves = len(compose_files)
    if not compose_files:
        print(f"❌ Nessun docker-compose.yml trovato in {VULHUB_DIR}")
        return 1

    start_index = max(0, (START_BATCH - 1) * BATCH_SIZE)
    if start_index >= total_cves:
        total_batches = (total_cves + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"❌ Batch {START_BATCH} inesistente; batch totali: {total_batches}")
        return 1

    print(f"Trovate {total_cves} vulnerabilità in Vulhub.")
    print_resources()

    current_port = START_PORT

    for index in range(start_index, total_cves, BATCH_SIZE):
        batch = compose_files[index:index + BATCH_SIZE]
        batch_num = index // BATCH_SIZE + 1
        ACTIVE_COMPOSE_FILES = {str(path) for path in batch}
        print(f"\n{'=' * 50}")
        print(f"Avvio batch {batch_num}: {[p.parent.name for p in batch]}")
        print("=" * 50)

        if not ensure_resources():
            project_cleanup(batch)
            print("❌ Batch interrotto per proteggere la VM.")
            return 1

        batch_targets = []
        batch_started = False

        try:
            for compose_file in batch:
                cve_id = compose_file.parent.name.upper()
                target_port, current_port = update_compose_port(
                    compose_file, current_port
                )
                print(f"🚀 Avvio {cve_id} sulla porta {target_port}...")
                result = run_command(
                    COMPOSE_CMD + ["up", "-d"],
                    cwd=compose_file.parent,
                    timeout=180,
                    check=False,
                )
                if result is None or result.returncode != 0:
                    raise RuntimeError(f"Avvio Compose fallito per {cve_id}")
                batch_started = True
                batch_targets.append(
                    (cve_id, f"http://127.0.0.1:{target_port}")
                )

            print("⏳ Attesa 20 secondi per l'inizializzazione...")
            time.sleep(20)

            for cve_id, target_url in batch_targets:
                print(f"\n--- 🎯 Agente contro {cve_id} ({target_url}) ---")
                llm_advice = get_dynamic_custom_prompt(cve_id)
                print(f"   💡 Prompt: {llm_advice[:100]}...")
                config_path = generate_config(cve_id, target_url, llm_advice)

                result = run_command(
                    [sys.executable, AGENT_SCRIPT, str(config_path)],
                    cwd=Path.cwd(),
                    timeout=None,
                    check=False,
                )
                if result is not None and result.returncode != 0:
                    print(f"⚠️ Agente terminato con codice {result.returncode}")

        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            print(f"❌ Errore nel batch: {exc}")
        finally:
            # Eseguito anche in caso di errore o Ctrl+C.
            if batch_started or batch:
                project_cleanup(batch)
            ACTIVE_COMPOSE_FILES = set()

        if not ensure_resources(required_batches=False):
            print("❌ Risorse insufficienti dopo il batch; esecuzione interrotta.")
            return 1

    print_resources("\n✅ Fine esecuzione. ")
    print("I file e i log creati dall'agente non sono stati rimossi dal runner.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
