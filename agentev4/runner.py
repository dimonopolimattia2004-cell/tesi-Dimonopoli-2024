#!/usr/bin/env python3
"""
Esegue uno script exploit in un ambiente isolato, gestendo copia,
esecuzione e parsing dell'output. L'isolamento è delegato al modulo
sandbox.py; il risultato viene restituito in formato JSON.
"""

import json
import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from sandbox import Sandbox, SandboxError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class SandboxRunner:
    def __init__(
        self,
        exploit_path: str,
        target: str,
        timeout: int = 30,
        sandbox_mode: str = "subprocess",
        extra_args: Optional[List[str]] = None,
        normalize_target: bool = False,
        output_file: Optional[Path] = None,
    ):
        self.exploit_path = Path(exploit_path)
        self.target = self._normalize_target(target) if normalize_target else target
        self.timeout = timeout
        self.sandbox_mode = sandbox_mode
        self.extra_args = extra_args or []
        self.output_file = output_file
        self.error = None

    def _normalize_target(self, target: str) -> str:
        if not target:
            return target
        target = target.replace("http://", "").replace("https://", "")
        return target.rstrip("/")

    def _check_prerequisites(self) -> bool:
        if not self.exploit_path.exists():
            self.error = f"Exploit non trovato: {self.exploit_path}"
            return False
        if not self.exploit_path.is_file():
            self.error = f"Percorso non valido: {self.exploit_path}"
            return False
        return True

    def _build_sandbox(self) -> Sandbox:
        try:
            return Sandbox(backend=self.sandbox_mode)
        except SandboxError as e:
            logger.warning(f"Sandbox {self.sandbox_mode} non disponibile: {e}. Fallback su subprocess.")
            self.error = f"{e}. Fallback su subprocess."
            return Sandbox(backend="subprocess")

    def _parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        import re

        try:
            data = json.loads(stdout.strip())
            if isinstance(data, dict) and "exploit_success" in data:
                return data
        except json.JSONDecodeError:
            pass

        pattern = r'\{[^{}]*"exploit_success"[^{}]*\}'
        for match in re.findall(pattern, stdout):
            try:
                data = json.loads(match)
                if "exploit_success" in data:
                    return data
            except json.JSONDecodeError:
                continue

        fallback = {
            "exploit_success": False,
            "evidence": "Nessun JSON valido trovato nell'output",
            "stdout": stdout[:1000] if stdout else "",
            "stderr": stderr[:500] if stderr else "",
            "returncode": returncode,
        }

        markers = ["exploit_success\": true", "vulnerable", "VULNERABLE"]
        for marker in markers:
            if marker in stdout:
                fallback["exploit_success"] = True
                fallback["evidence"] = f"Marker rilevato: {marker}"
                break

        return fallback

    def run(self) -> Dict[str, Any]:
        start = datetime.now()

        if not self._check_prerequisites():
            return self._finalize(False, self.error, start)

        logger.info(f"Esecuzione exploit: {self.exploit_path.name} su {self.target}")
        logger.info(f"Backend: {self.sandbox_mode}, timeout: {self.timeout}s")

        sandbox = self._build_sandbox()
        fallback_msg = self.error
        self.error = None

        with sandbox as sb:
            try:
                exploit_copy = sb.copy_in(self.exploit_path)
            except Exception as e:
                logger.error(f"Errore copia exploit: {e}")
                return self._finalize(
                    False,
                    f"Impossibile copiare l'exploit nella sandbox: {e}",
                    start,
                )

            cmd = ["python3", exploit_copy.name, "--target", self.target]
            if self.extra_args:
                cmd.extend(self.extra_args)

            sandbox_result = sb.run(cmd, timeout=self.timeout)

        returncode = sandbox_result["returncode"]
        stdout = sandbox_result["stdout"]
        stderr = sandbox_result["stderr"]

        parsed = self._parse_output(stdout, stderr, returncode)

        result = {
            "success": returncode == 0,
            "returncode": returncode,
            "execution_time": sandbox_result["execution_time"],
            "exploit_path": str(self.exploit_path),
            "target": self.target,
            "sandbox_mode": sandbox_result["backend"],
            "network_isolated": sandbox_result["network_isolated"],
            "timestamp": datetime.now().isoformat(),
        }

        warnings = list(sandbox_result.get("warnings", []))
        if fallback_msg:
            warnings.append(fallback_msg)
        if warnings:
            result["warnings"] = warnings

        if parsed:
            result.update(parsed)

        if stdout and not result.get("evidence"):
            result["raw_stdout"] = stdout[:1000]
        if stderr:
            result["stderr"] = stderr[:500]

        if result.get("exploit_success"):
            logger.info("Exploit eseguito con successo")
        else:
            logger.warning("Exploit non riuscito")

        if self.output_file:
            self._save_result(result)

        return result

    def _finalize(self, success: bool, error: str, start: datetime) -> Dict[str, Any]:
        result = {
            "success": success,
            "error": error,
            "exploit_path": str(self.exploit_path),
            "timestamp": start.isoformat(),
        }
        if self.output_file:
            self._save_result(result)
        return result

    def _save_result(self, result: Dict[str, Any]) -> None:
        try:
            with open(self.output_file, "w") as f:
                json.dump(result, f, indent=2)
        except OSError as e:
            logger.error(f"Errore salvataggio risultato: {e}")


def main():
    parser = argparse.ArgumentParser(description="Esegue un exploit in sandbox e restituisce JSON.")
    parser.add_argument("--exploit", required=True, help="Percorso dello script exploit")
    parser.add_argument("--target", required=True, help="Target dell'exploit")
    parser.add_argument("--timeout", default="30", help="Timeout in secondi")
    parser.add_argument(
        "--sandbox",
        default="subprocess",
        choices=["subprocess", "docker", "firejail", "auto"],
        help="Modalità sandbox",
    )
    parser.add_argument("--extra-args", default="", help="Argomenti aggiuntivi separati da virgola")
    parser.add_argument("--normalize-target", action="store_true")
    parser.add_argument("--output-file", help="File dove salvare il JSON di risultato")
    args = parser.parse_args()

    extra = [x.strip() for x in args.extra_args.split(",") if x.strip()] if args.extra_args else []
    out = Path(args.output_file) if args.output_file else None

    runner = SandboxRunner(
        exploit_path=args.exploit,
        target=args.target,
        timeout=int(args.timeout),
        sandbox_mode=args.sandbox,
        extra_args=extra,
        normalize_target=args.normalize_target,
        output_file=out,
    )

    print(json.dumps(runner.run(), indent=2))


if __name__ == "__main__":
    main()