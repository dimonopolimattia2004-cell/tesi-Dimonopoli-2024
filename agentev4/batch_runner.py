#!/usr/bin/env python3
"""
Esegue in sequenza l'agente su batch di CVE di Vulhub.
Per ogni batch: avvia i container, genera il custom prompt via API,
lancia l'agente e fa pulizia dei container e delle risorse.
"""

import hashlib
import json
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests
import yaml

# --- CONFIGURAZIONE PER NUOVI TEST ---
VULHUB_DIR = Path("./vulhub")
BATCH_SIZE = 3
START_PORT = 8100
START_BATCH = 1
AGENT_SCRIPT = "main.py"

API_KEY = "sk-13efa0e753d341e79e8f70a27de94331"
MODEL = "deepseek-flash"
API_URL = "https://api.deepseek.com/chat/completions"

DISK_PATH = "/"
MIN_FREE_GB = 8.0
MEMORY_RESERVE_MB = 1024
COMPOSE_CMD = ["docker-compose"]

REMOVE_PROJECT_VOLUMES = True
REMOVE_PROJECT_IMAGES = False

FALLBACK_PROMPT = "Conduciti in autonomia basandoti sulla descrizione della CVE."
ACTIVE_COMPOSE_FILES = set()


def file_hash(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_not_self(agent_path: Path):
    me = Path(__file__).resolve()
    other = agent_path.resolve()
    if me == other or file_hash(me) == file_hash(other):
        print(f"ERRORE: '{agent_path.name}' coincide con il runner.")
        raise SystemExit(1)


def disk_free_gb(path: str = DISK_PATH) -> float:
    try:
        return shutil.disk_usage(path).free / (1024 ** 3)
    except OSError:
        return -1.0


def memory_available_mb() -> float:
    try:
        values = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, value = line.split(":", 1)
                values[key] = float(value.strip().split()[0]) / 1024
        return values.get("MemAvailable", -1.0)
    except (OSError, ValueError):
        return -1.0


def print_resources(prefix: str = ""):
    disk = disk_free_gb()
    mem = memory_available_mb()
    disk_text = f"{disk:.2f} GB" if disk >= 0 else "n/d"
    mem_text = f"{mem:.0f} MB" if mem >= 0 else "n/d"
    print(f"{prefix}Disco: {disk_text} | RAM: {mem_text}")


def run_command(command, cwd=None, timeout=600, check=False, quiet=False):
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
            print(f"Comando fallito ({' '.join(command)}): {exc}")
        return None


def ensure_resources(required_batches=True):
    disk = disk_free_gb()
    mem = memory_available_mb()

    if disk >= 0 and disk < MIN_FREE_GB:
        print(f"Spazio insufficiente: {disk:.2f} GB")
        return False

    if required_batches and mem >= 0 and mem < MEMORY_RESERVE_MB:
        print(f"RAM insufficiente: {mem:.0f} MB")
        return False

    return True


def get_compose_files():
    return sorted(VULHUB_DIR.rglob("docker-compose.yml"))


def update_compose_port(compose_path: Path, starting_port: int):
    backup = compose_path.with_suffix(".yml.bak")
    if not backup.exists():
        shutil.copy2(compose_path, backup)

    with compose_path.open("r") as f:
        compose = yaml.safe_load(f) or {}

    current = starting_port
    target = None

    for service in (compose.get("services") or {}).values():
        if not isinstance(service, dict) or "ports" not in service:
            continue
        new_ports = []
        for mapping in service["ports"] or []:
            parts = str(mapping).split(":")
            container_port = parts[-1]
            if target is None:
                target = current
            new_ports.append(f"{current}:{container_port}")
            current += 1
        service["ports"] = new_ports

    if target is None:
        raise ValueError(f"Nessuna porta esposta in {compose_path}")

    with compose_path.open("w") as f:
        yaml.safe_dump(compose, f, sort_keys=False)

    return target, current


def restore_compose(compose_path: Path):
    backup = compose_path.with_suffix(".yml.bak")
    if backup.exists():
        shutil.move(str(backup), str(compose_path))


def project_cleanup(compose_files):
    print("Arresto dei container del batch...")
    for compose in compose_files:
        cmd = COMPOSE_CMD + ["down", "--remove-orphans"]
        if REMOVE_PROJECT_VOLUMES:
            cmd.append("--volumes")
        if REMOVE_PROJECT_IMAGES:
            cmd.extend(["--rmi", "local"])
        run_command(cmd, cwd=compose.parent, timeout=180, quiet=True)
        restore_compose(compose)
    print_resources()


def get_dynamic_custom_prompt(cve_id, max_retries=3):
    print(f"Richiesta custom prompt per {cve_id}...")

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
            r = requests.post(API_URL, headers=headers, json=payload, timeout=(10, 60))
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
        except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
            print(f"Tentativo {attempt}/{max_retries}: {exc}")
            if attempt < max_retries:
                time.sleep(3 * attempt)

    return FALLBACK_PROMPT


def generate_config(cve_id, target_url, custom_prompt):
    config = {
        "cve": cve_id,
        "target": target_url,
        "deepseek_api_key": API_KEY,
        "deepseek_model": MODEL,
        "max_iterations": 10,
        "custom_prompt": custom_prompt,
    }
    path = Path("current_config.json")
    with path.open("w") as f:
        json.dump(config, f, indent=4)
    return path


def cleanup_on_signal(signum, _frame):
    print(f"Segnale {signum}: pulizia in corso...")
    if ACTIVE_COMPOSE_FILES:
        project_cleanup([Path(p) for p in ACTIVE_COMPOSE_FILES])
    raise SystemExit(128 + signum)


def main():
    global ACTIVE_COMPOSE_FILES

    signal.signal(signal.SIGINT, cleanup_on_signal)
    signal.signal(signal.SIGTERM, cleanup_on_signal)

    agent_path = Path(AGENT_SCRIPT)
    if not agent_path.exists():
        print(f"Agente non trovato: {agent_path}")
        return 1
    assert_not_self(agent_path)

    compose_files = get_compose_files()
    total = len(compose_files)
    if not compose_files:
        print(f"Nessun compose trovato in {VULHUB_DIR}")
        return 1

    start_index = max(0, (START_BATCH - 1) * BATCH_SIZE)
    if start_index >= total:
        total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"Batch {START_BATCH} inesistente; batch totali: {total_batches}")
        return 1

    print(f"Trovate {total} vulnerabilità.")
    print(f"Avvio dal batch {START_BATCH} (indice {start_index})")
    print_resources()

    current_port = START_PORT

    for index in range(start_index, total, BATCH_SIZE):
        batch = compose_files[index:index + BATCH_SIZE]
        batch_num = index // BATCH_SIZE + 1
        ACTIVE_COMPOSE_FILES = {str(p) for p in batch}

        print(f"\n{'=' * 50}")
        print(f"Batch {batch_num}: {[p.parent.name for p in batch]}")
        print("=" * 50)

        if not ensure_resources():
            project_cleanup(batch)
            print("Batch interrotto per risorse insufficienti.")
            return 1

        targets = []
        started = False

        try:
            for compose in batch:
                cve_id = compose.parent.name.upper()
                port, current_port = update_compose_port(compose, current_port)

                if port is None:
                    print(f"{cve_id}: nessuna porta esposta, salto.")
                    continue

                print(f"Avvio {cve_id} sulla porta {port}...")
                result = run_command(
                    COMPOSE_CMD + ["up", "-d"],
                    cwd=compose.parent,
                    timeout=600,
                    check=False,
                )
                if result is None or result.returncode != 0:
                    raise RuntimeError(f"Avvio fallito per {cve_id}")

                started = True
                targets.append((cve_id, f"http://127.0.0.1:{port}"))

            print("Attesa 20 secondi per l'inizializzazione...")
            time.sleep(20)

            for cve_id, target_url in targets:
                print(f"\n--- Agente su {cve_id} ({target_url}) ---")
                prompt = get_dynamic_custom_prompt(cve_id)
                print(f"Prompt: {prompt[:100]}...")
                config_path = generate_config(cve_id, target_url, prompt)

                result = run_command(
                    [sys.executable, AGENT_SCRIPT, str(config_path)],
                    cwd=Path.cwd(),
                    timeout=None,
                    check=False,
                )
                if result is not None and result.returncode != 0:
                    print(f"Agente terminato con codice {result.returncode}")

        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            print(f"Errore nel batch: {exc}")
        finally:
            if started or batch:
                project_cleanup(batch)
            ACTIVE_COMPOSE_FILES = set()

        if not ensure_resources(required_batches=False):
            print("Risorse insufficienti, esecuzione interrotta.")
            return 1

    print_resources("\nEsecuzione completata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())