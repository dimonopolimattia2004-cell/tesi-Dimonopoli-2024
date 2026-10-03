#!/usr/bin/env python3
"""
Gestione di un ambiente isolato per l'esecuzione di codice non fidato.
Fornisce isolamento di rete, limiti di risorse e pulizia automatica.

Backend supportati, in ordine di preferenza con backend="auto":
  1. docker    - isolamento completo
  2. firejail  - namespace Linux
  3. subprocess - solo limiti POSIX (nessun isolamento di rete reale)
"""

import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False


DEFAULT_IMAGE = "python:3.11-slim"
CONTAINER_LABEL = "exploit-agent-sandbox"


class SandboxError(Exception):
    pass


class Sandbox:
    def __init__(
        self,
        backend: str = "auto",
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
        pids_limit: int = 64,
        network_isolated: bool = True,
        image: str = DEFAULT_IMAGE,
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.network_isolated = network_isolated
        self.image = image

        self.backend = self._resolve_backend(backend)
        self.session_id = uuid.uuid4().hex[:12]
        self.workdir: Optional[Path] = None
        self._container_name: Optional[str] = None
        self.warnings: List[str] = []

        if self.backend == "subprocess":
            self.warnings.append(
                "Backend 'subprocess': nessun isolamento di rete reale disponibile."
            )

    def _resolve_backend(self, backend: str) -> str:
        if backend != "auto":
            if backend == "docker" and not shutil.which("docker"):
                raise SandboxError("Backend 'docker' non trovato nel PATH")
            if backend == "firejail" and not shutil.which("firejail"):
                raise SandboxError("Backend 'firejail' non trovato nel PATH")
            if backend not in ("docker", "firejail", "subprocess"):
                raise SandboxError(f"Backend sconosciuto: {backend}")
            return backend

        if shutil.which("docker") and self._docker_daemon_ok():
            return "docker"
        if shutil.which("firejail"):
            return "firejail"
        return "subprocess"

    @staticmethod
    def _docker_daemon_ok() -> bool:
        try:
            proc = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    def __enter__(self) -> "Sandbox":
        self.workdir = Path(tempfile.mkdtemp(prefix=f"sandbox_{self.session_id}_"))
        if self.backend == "docker":
            self._ensure_image()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    def _ensure_image(self) -> None:
        inspect = subprocess.run(
            ["docker", "image", "inspect", self.image], capture_output=True
        )
        if inspect.returncode != 0:
            pull = subprocess.run(
                ["docker", "pull", self.image], capture_output=True, timeout=120
            )
            if pull.returncode != 0:
                raise SandboxError(
                    f"Impossibile scaricare l'immagine {self.image}: "
                    f"{pull.stderr.decode(errors='ignore')}"
                )

    def copy_in(self, source_path: Path) -> Path:
        if self.workdir is None:
            raise SandboxError("Sandbox non inizializzata")
        source_path = Path(source_path)
        dest = self.workdir / source_path.name
        shutil.copy2(source_path, dest)
        try:
            dest.chmod(0o755)
        except OSError:
            pass
        return dest

    def cleanup(self) -> None:
        if self.backend == "docker":
            self._force_kill_container()
            self._prune_stale_containers()
        if self.workdir and self.workdir.exists():
            shutil.rmtree(self.workdir, ignore_errors=True)
        self.workdir = None

    def _force_kill_container(self) -> None:
        if self._container_name:
            subprocess.run(["docker", "kill", self._container_name], capture_output=True)
            self._container_name = None

    def _prune_stale_containers(self) -> None:
        try:
            proc = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label={CONTAINER_LABEL}={self.session_id}"],
                capture_output=True, text=True, timeout=10,
            )
            ids = [line for line in proc.stdout.splitlines() if line.strip()]
            if ids:
                subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=10)
        except Exception:
            pass

    def run(self, args: List[str], timeout: int = 30) -> Dict[str, Any]:
        if self.workdir is None:
            raise SandboxError("Sandbox non inizializzata")

        start = time.time()
        if self.backend == "docker":
            rc, out, err = self._run_docker(args, timeout)
            net_isolated = self.network_isolated
        elif self.backend == "firejail":
            rc, out, err = self._run_firejail(args, timeout)
            net_isolated = self.network_isolated
        else:
            rc, out, err = self._run_subprocess(args, timeout)
            net_isolated = False

        return {
            "returncode": rc,
            "stdout": out,
            "stderr": err,
            "execution_time": round(time.time() - start, 3),
            "backend": self.backend,
            "network_isolated": net_isolated,
            "warnings": list(self.warnings),
        }

    def _run_docker(self, args: List[str], timeout: int) -> Tuple[int, str, str]:
        self._container_name = f"sandbox-{self.session_id}"
        cmd = [
            "docker", "run", "--rm",
            "--name", self._container_name,
            "--label", f"{CONTAINER_LABEL}={self.session_id}",
            "--memory", self.memory_limit,
            "--cpus", str(self.cpu_limit),
            "--pids-limit", str(self.pids_limit),
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "-v", f"{self.workdir}:/workspace:ro",
            "-w", "/workspace",
        ]
        if self.network_isolated:
            cmd += ["--network", "none"]
        cmd += [self.image] + args

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            self._force_kill_container()
            return -1, "", f"Timeout Docker dopo {timeout}s"
        except Exception as e:
            return -2, "", str(e)
        finally:
            self._container_name = None

    def _run_firejail(self, args: List[str], timeout: int) -> Tuple[int, str, str]:
        mem_mb = self._mem_to_mb(self.memory_limit)
        cmd = ["firejail", "--quiet"]
        if self.network_isolated:
            cmd.append("--net=none")
        cmd += [
            f"--cpu={max(1, int(self.cpu_limit))}",
            f"--rlimit-as={mem_mb}M" if mem_mb else "--rlimit-as=512M",
            f"--rlimit-nproc={self.pids_limit}",
            f"--timeout=00:00:{min(max(timeout, 1), 99):02d}",
        ]
        cmd += args

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 5, cwd=self.workdir
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Timeout Firejail dopo {timeout}s"
        except Exception as e:
            return -2, "", str(e)

    def _run_subprocess(self, args: List[str], timeout: int) -> Tuple[int, str, str]:
        preexec = self._make_rlimits_preexec() if HAS_RESOURCE else None
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.workdir,
                preexec_fn=preexec,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Timeout dopo {timeout}s"
        except Exception as e:
            return -2, "", str(e)

    def _make_rlimits_preexec(self):
        mem_bytes = self._mem_to_mb(self.memory_limit) * 1024 * 1024
        cpu_seconds = 30
        pids_limit = self.pids_limit

        def _apply():
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            except Exception:
                pass
            if hasattr(resource, "RLIMIT_NPROC"):
                try:
                    resource.setrlimit(resource.RLIMIT_NPROC, (pids_limit, pids_limit))
                except Exception:
                    pass

        return _apply

    @staticmethod
    def _mem_to_mb(mem_str: str) -> int:
        s = str(mem_str).strip().lower()
        try:
            if s.endswith("g"):
                return int(float(s[:-1]) * 1024)
            if s.endswith("m"):
                return int(float(s[:-1]))
            return int(s)
        except ValueError:
            return 512


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Smoke test del modulo sandbox.")
    parser.add_argument("--backend", default="auto", choices=["auto", "docker", "firejail", "subprocess"])
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    try:
        with Sandbox(backend=args.backend) as sb:
            result = sb.run(["python3", "-c", "print('sandbox ok')"], timeout=args.timeout)
    except SandboxError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        raise SystemExit(1)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()