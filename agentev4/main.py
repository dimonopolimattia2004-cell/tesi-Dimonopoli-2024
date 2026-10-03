#!/usr/bin/env python3
"""
Orchestratore dell'agente. Data una CVE e un target, esegue il ciclo
di analisi, generazione, esecuzione, validazione e correzione
dell'exploit fino al successo o al numero massimo di iterazioni.
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class ExploitAgent:
    def __init__(self, config_path):
        self.config = self._load_config(config_path)
        self.cve = self.config.get("cve")
        self.target = self.config.get("target")
        self.api_key = self.config.get("deepseek_api_key")
        self.model = self.config.get("deepseek_model", "deepseek-flash")
        self.max_iterations = self.config.get("max_iterations", 5)
        self.custom_prompt = self.config.get("custom_prompt", "")
        self.iteration = 0
        self.cve_data = None
        self.correction_history = []
        self.files = {
            "cve_data": Path(f"cve_data/{self.cve}.json"),
            "exploit": Path(f"exploits/exploit_{self.cve}.py"),
            "result": Path(f"results/result_{self.cve}.json"),
            "report": Path(f"reports/report_{self.cve}.html"),
        }
        for d in ("cve_data", "exploits", "results", "reports"):
            Path(d).mkdir(exist_ok=True)

    def _load_config(self, path):
        if not Path(path).exists():
            logger.error(f"Config file non trovato: {path}")
            sys.exit(1)
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Config file non valido: {e}")
            sys.exit(1)

    def run(self):
        logger.info(f"Avvio agente per CVE: {self.cve}")
        logger.info(f"Target: {self.target}")
        logger.info(f"Max iterazioni: {self.max_iterations}")

        logger.info("Fase 1: analisi CVE")
        self.cve_data = self._analyze_cve()
        if not self.cve_data:
            logger.error("Analisi CVE fallita")
            return
        logger.info(f"CVE analizzata: {self.cve_data.get('vulnerability_type', 'sconosciuto')}")

        desc = str(self.cve_data.get("description") or "")
        logger.info(f"Descrizione: {desc[:100]}...")

        success = False
        exploit_path = None
        consecutive_failures = 0

        while self.iteration < self.max_iterations:
            self.iteration += 1
            logger.info(f"Iterazione {self.iteration}/{self.max_iterations}")

            if exploit_path is None:
                logger.info("Fase 2: generazione exploit")
                exploit_path = self._generate_exploit(self.cve_data)
                if not exploit_path:
                    logger.error("Generazione exploit fallita")
                    consecutive_failures += 1
                    if consecutive_failures >= 2:
                        logger.error("Troppi fallimenti consecutivi, interrompo")
                        break
                    continue
                logger.info(f"Exploit generato: {exploit_path}")
                consecutive_failures = 0
            else:
                logger.info(f"Fase 2: riutilizzo exploit corretto: {exploit_path}")

            logger.info("Fase 3: esecuzione exploit")
            result = self._run_exploit(exploit_path)
            if not result:
                logger.error("Esecuzione exploit fallita")
                if not self._correct_exploit(exploit_path):
                    logger.warning("Correzione fallita, rigenero")
                    exploit_path = None
                    consecutive_failures += 1
                continue

            logger.info("Fase 4: validazione risultato")
            validation = self._validate_result(result, self.cve_data)

            if validation.get("success", False):
                logger.info("Exploit funzionante")
                success = True
                break

            logger.warning(f"Exploit non funzionante: {validation.get('reason', '')}")
            if not self._correct_exploit(exploit_path):
                logger.warning("Correzione fallita, rigenero")
                exploit_path = None
                consecutive_failures += 1

        logger.info("Fase 5: generazione report")
        self._generate_report(success, self.cve_data)

        if success:
            logger.info("Agente completato con successo")
        else:
            logger.warning(f"Agente completato senza successo dopo {self.iteration} iterazioni")

    def _analyze_cve(self):
        try:
            r = subprocess.run(
                ["python3", "analyze_cve.py", "--cve", self.cve],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode != 0:
                logger.error(f"Analisi CVE fallita: {r.stderr}")
                return None
            data = json.loads(r.stdout)
            with open(self.files["cve_data"], "w") as f:
                json.dump(data, f, indent=2)
            return data
        except FileNotFoundError:
            logger.error("analyze_cve.py non trovato")
            return None
        except subprocess.TimeoutExpired:
            logger.error("Analisi CVE timeout")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Output analisi non valido: {e}")
            return None

    def _generate_exploit(self, cve_data):
        try:
            r = subprocess.run(
                [
                    "python3", "generator.py",
                    "--cve", self.cve,
                    "--api-key", self.api_key,
                    "--model", self.model,
                    "--data", json.dumps(cve_data),
                    "--custom-prompt", self.custom_prompt,
                ],
                capture_output=True, text=True, timeout=300,
            )
            if r.returncode != 0:
                logger.error(f"Generazione fallita: {r.stderr}")
                return None
            data = json.loads(r.stdout)
            return data.get("exploit_path")
        except FileNotFoundError:
            logger.error("generator.py non trovato")
            return None
        except subprocess.TimeoutExpired:
            logger.error("Generazione exploit timeout")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Output generatore non valido: {e}")
            return None

    def _run_exploit(self, exploit_path):
        timeout = 30
        try:
            r = subprocess.run(
                [
                    "python3", "runner.py",
                    "--exploit", str(exploit_path),
                    "--target", self.target,
                    "--timeout", str(timeout),
                ],
                capture_output=True, text=True, timeout=timeout + 5,
            )

            if r.returncode != 0:
                data = {"error": r.stderr.strip(), "returncode": r.returncode}
            else:
                try:
                    data = json.loads(r.stdout)
                except json.JSONDecodeError:
                    data = {"error": "Output non JSON", "raw": r.stdout, "returncode": r.returncode}

            with open(self.files["result"], "w") as f:
                json.dump(data, f, indent=2)

            return data if r.returncode == 0 else None

        except subprocess.TimeoutExpired:
            logger.error("Esecuzione exploit timeout")
            with open(self.files["result"], "w") as f:
                json.dump({"error": "Timeout esecuzione exploit", "returncode": -1}, f)
            return None
        except FileNotFoundError:
            logger.error("runner.py non trovato")
            return None

    def _validate_result(self, result, cve_data):
        try:
            r = subprocess.run(
                ["python3", "validator.py"],
                input=json.dumps({
                    "result": result,
                    "cve_data": cve_data,
                    "target": self.target,
                }),
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                return {"success": False, "reason": f"Validator: {r.stderr}"}
            return json.loads(r.stdout)
        except FileNotFoundError:
            return {"success": False, "reason": "validator.py non trovato"}
        except json.JSONDecodeError:
            return {"success": False, "reason": "Output validator non valido"}

    def _correct_exploit(self, exploit_path):
        logger.info("Correzione exploit")
        try:
            if not Path(exploit_path).exists():
                logger.error(f"Exploit non trovato: {exploit_path}")
                return False

            with open(exploit_path, "r") as f:
                code = f.read()

            error = {}
            if self.files["result"].exists():
                with open(self.files["result"], "r") as f:
                    error = json.load(f)

            history = self.correction_history[-3:]
            history_json = json.dumps(history)

            r = subprocess.run(
                [
                    "python3", "corrector.py",
                    "--api-key", self.api_key,
                    "--model", self.model,
                    "--code", code,
                    "--error", json.dumps(error),
                    "--cve", self.cve,
                    "--history", history_json,
                    "--cve-data", json.dumps(self.cve_data),
                ],
                capture_output=True, text=True, timeout=300,
            )

            if r.returncode != 0:
                logger.error(f"Correzione fallita: {r.stderr}")
                self.correction_history.append({
                    "error": error,
                    "corrected_code": None,
                    "outcome": "fallito",
                })
                return False

            corrected = json.loads(r.stdout)
            new_code = corrected.get("code")
            if not new_code or new_code.strip() == code.strip():
                logger.error("Nessuna modifica significativa")
                self.correction_history.append({
                    "error": error,
                    "corrected_code": code,
                    "outcome": "nessuna_modifica",
                })
                return False

            with open(exploit_path, "w") as f:
                f.write(new_code)

            self.correction_history.append({
                "error": error,
                "corrected_code": new_code,
                "outcome": "successo",
            })

            logger.info("Exploit corretto, riprovo")
            return True

        except FileNotFoundError:
            logger.error("corrector.py non trovato")
            return False
        except json.JSONDecodeError:
            logger.error("Output corrector non valido")
            return False

    def _generate_report(self, success, cve_data):
        try:
            subprocess.run(
                [
                    "python3", "reporter.py",
                    "--cve", self.cve,
                    "--success", str(success),
                    "--data", json.dumps(cve_data),
                    "--iterations", str(self.iteration),
                    "--result", str(self.files["result"]),
                ],
                timeout=30,
            )
            logger.info(f"Report generato: {self.files['report']}")
        except FileNotFoundError:
            logger.error("reporter.py non trovato")


def main():
    if len(sys.argv) != 2:
        print("Uso: python main.py <config.json>")
        sys.exit(1)
    agent = ExploitAgent(sys.argv[1])
    agent.run()


if __name__ == "__main__":
    main()