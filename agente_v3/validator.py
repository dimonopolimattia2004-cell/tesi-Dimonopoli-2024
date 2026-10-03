#!/usr/bin/env python3
"""
Validazione del risultato di un exploit. Riceve da stdin un JSON con
i campi {result, cve_data, target} e restituisce un verdetto strutturato
{success, reason, confidence} basato su controlli logici e pattern matching.
"""

import json
import sys
from typing import Any, Dict


class ResultValidator:
    def __init__(self, payload: Dict[str, Any]):
        self.result = payload.get("result", {}) or {}
        self.cve_data = payload.get("cve_data", {}) or {}
        self.target = payload.get("target", "")
        self._extend_markers()

    def _extend_markers(self) -> None:
        custom = self.cve_data.get("validation_markers", {})
        if not custom:
            return
        for vuln_type, markers in custom.items():
            if vuln_type in self.expected_markers:
                self.expected_markers[vuln_type].extend(markers)
            else:
                self.expected_markers[vuln_type] = markers

    @property
    def expected_markers(self) -> Dict[str, list]:
        return {
            "sql_injection": ["sql", "syntax error", "mysql", "postgres", "sqlite", "SELECT", "FROM"],
            "rce": ["uid=", "whoami", "root", "shell", "/bin/sh", "cmd.exe"],
            "command_injection": ["uid=", "whoami", "id=", "groups=", "gid="],
            "lfi": ["root:x:", "/etc/passwd", "/etc/hosts", "C:\\Windows\\System32"],
            "xxe": ["root:x:", "/etc/passwd", "ENTITY", "DOCTYPE"],
            "xss": ["<script>", "alert(", "onerror=", "onload="],
            "ssrf": ["169.254.169.254", "metadata", "internal", "localhost"],
            "authentication_bypass": ["login", "authenticated", "session", "token", "welcome"],
            "information_disclosure": [".env", "secret", "key=", "password", "token"],
            "deserialization": ["traceback", "exception", "unserialize", "pickle", "java"],
            "buffer_overflow": ["overflow", "segmentation fault", "core dumped", "crash"],
            "unknown": [],
        }

    def _check_process_health(self) -> Dict[str, Any]:
        rc = self.result.get("returncode")
        if rc not in (0, None):
            return {"ok": False, "reason": f"Return code non nullo: {rc}"}
        return {"ok": True, "reason": ""}

    def _check_exploit_flag(self) -> Dict[str, Any]:
        if "exploit_success" not in self.result:
            return {"ok": False, "reason": "Campo 'exploit_success' assente"}
        flag = self.result.get("exploit_success")
        if flag is not True:
            return {"ok": False, "reason": f"exploit_success = {flag}"}
        return {"ok": True, "reason": "exploit_success = true"}

    def _check_error_field(self) -> Dict[str, Any]:
        error = self.result.get("error")
        if error:
            return {"ok": False, "reason": f"Errore rilevato: {error}"}
        return {"ok": True, "reason": ""}

    def _check_evidence_quality(self) -> Dict[str, Any]:
        evidence = self.result.get("evidence")
        if not evidence:
            return {"ok": False, "reason": "Evidenza mancante"}

        text = str(evidence)
        for marker in ("Pattern trovato:", "Nessun JSON valido trovato"):
            if marker in text:
                return {
                    "ok": True,
                    "reason": f"Evidenza debole (fallback pattern matching): {text}",
                    "confidence": "low",
                }
        return {
            "ok": True,
            "reason": f"Evidenza presente: {text[:200]}",
            "confidence": "high",
        }

    def _check_payload_usage(self) -> Dict[str, Any]:
        payload = self.cve_data.get("suggested_payload", "")
        if not payload:
            return {"ok": True, "reason": "Nessun payload suggerito"}

        output = self.result.get("raw_stdout") or self.result.get("stdout") or ""
        if payload in str(output):
            return {"ok": True, "reason": "Payload trovato nell'output", "confidence": "high"}
        return {"ok": True, "reason": "Payload non trovato nell'output", "confidence": "low"}

    def _check_vulnerability_consistency(self) -> Dict[str, Any]:
        vuln_type = self.cve_data.get("vulnerability_type", "unknown")
        evidence = str(self.result.get("evidence") or "").lower()
        stdout = str(self.result.get("raw_stdout") or self.result.get("stdout") or "").lower()
        combined = evidence + " " + stdout

        markers = self.expected_markers.get(vuln_type, [])
        if not markers:
            return {"ok": True, "reason": "Nessun marker specifico", "confidence": "medium"}

        if any(m in combined for m in markers):
            return {"ok": True, "reason": f"Marker coerenti con '{vuln_type}'", "confidence": "high"}

        return {
            "ok": True,
            "reason": f"Nessun marker tipico di '{vuln_type}'; possibile falso positivo",
            "confidence": "low",
        }

    def _check_target_consistency(self) -> Dict[str, Any]:
        if "target" in self.result:
            result_target = self.result.get("target")
            if result_target and result_target != self.target:
                return {
                    "ok": False,
                    "reason": f"Target nel risultato ({result_target}) diverso da quello atteso ({self.target})",
                }
        return {"ok": True, "reason": ""}

    def validate(self) -> Dict[str, Any]:
        checks = {
            "process_health": self._check_process_health(),
            "error_field": self._check_error_field(),
            "exploit_flag": self._check_exploit_flag(),
            "evidence_quality": self._check_evidence_quality(),
            "payload_usage": self._check_payload_usage(),
            "vulnerability_consistency": self._check_vulnerability_consistency(),
            "target_consistency": self._check_target_consistency(),
        }

        hard = ("process_health", "error_field", "exploit_flag",
                "evidence_quality", "target_consistency")
        for name in hard:
            if not checks[name]["ok"]:
                return {
                    "success": False,
                    "reason": checks[name]["reason"],
                    "confidence": "high",
                    "details": checks,
                }

        confidences = [
            checks["evidence_quality"].get("confidence", "medium"),
            checks["payload_usage"].get("confidence", "medium"),
            checks["vulnerability_consistency"].get("confidence", "medium"),
        ]
        rank = {"low": 0, "medium": 1, "high": 2}
        overall = min(confidences, key=lambda c: rank.get(c, 1))

        return {
            "success": True,
            "reason": "Tutti i controlli superati",
            "confidence": overall,
            "details": checks,
        }


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"success": False, "reason": "Input vuoto"}), file=sys.stderr)
        sys.exit(1)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"success": False, "reason": f"Input JSON non valido: {e}"}), file=sys.stderr)
        sys.exit(1)

    verdict = ResultValidator(payload).validate()
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()