#!/usr/bin/env python3
"""
Analisi di una CVE tramite NVD. Recupera i metadati (descrizione,
severità, prodotto, versione), deduce il tipo di vulnerabilità con
pattern matching e propone un payload di test.
"""

import json
import sys
import argparse
import requests
from datetime import datetime

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEAnalyzer:
    def __init__(self, cve_id: str):
        self.cve_id = cve_id.upper().strip()
        self.data = {
            "cve": self.cve_id,
            "description": "",
            "product": "",
            "version": "",
            "affected_versions": [],
            "severity": "",
            "cvss_score": 0,
            "references": [],
            "vulnerability_type": "",
            "attack_vector": "",
            "suggested_payload": "",
        }

    def fetch_from_nvd(self) -> bool:
        try:
            r = requests.get(NVD_API_URL, params={"cveId": self.cve_id}, timeout=30)
            if r.status_code != 200:
                print(f"NVD HTTP {r.status_code}", file=sys.stderr)
                return False

            payload = r.json()
            if not payload.get("vulnerabilities"):
                print(f"CVE non trovata su NVD: {self.cve_id}", file=sys.stderr)
                return False

            vuln = payload["vulnerabilities"][0]["cve"]

            for d in vuln.get("descriptions", []):
                if d.get("lang") == "en":
                    self.data["description"] = d.get("value", "")
                    break

            metrics = vuln.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV2", [])
            if cvss:
                c = cvss[0].get("cvssData", {})
                self.data["cvss_score"] = c.get("baseScore", 0)
                self.data["severity"] = c.get("baseSeverity", "")

            self.data["references"] = [r.get("url") for r in vuln.get("references", [])]

            for config in vuln.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable"):
                            continue
                        parts = match.get("criteria", "").split(":")
                        if len(parts) >= 6:
                            product = parts[4]
                            version = parts[5]
                            if product and not self.data["product"]:
                                self.data["product"] = product
                                self.data["version"] = version
                                if version:
                                    self.data["affected_versions"].append(version)

            return True

        except requests.RequestException as e:
            print(f"Errore di rete: {e}", file=sys.stderr)
            return False
        except (KeyError, ValueError) as e:
            print(f"Errore parsing NVD: {e}", file=sys.stderr)
            return False

    def infer_vulnerability_type(self) -> None:
        desc = self.data["description"].lower()

        patterns = {
            "sql_injection": ["sql injection", "sqli", "sql query"],
            "rce": ["remote code execution", "arbitrary code execution"],
            "lfi": ["file inclusion", "path traversal", "directory traversal"],
            "xss": ["cross-site scripting", "cross site scripting"],
            "buffer_overflow": ["buffer overflow", "memory corruption"],
            "command_injection": ["command injection", "os command injection"],
            "privilege_escalation": ["privilege escalation", "elevation of privilege"],
            "dos": ["denial of service", "resource exhaustion"],
            "ssrf": ["server-side request forgery"],
            "xxe": ["xml external entity"],
            "deserialization": ["deserialization", "insecure deserialization"],
            "authentication_bypass": ["authentication bypass", "auth bypass"],
            "information_disclosure": ["information disclosure", "information leakage"],
        }

        for vuln_type, keywords in patterns.items():
            if any(k in desc for k in keywords):
                self.data["vulnerability_type"] = vuln_type
                self._suggest_payload(vuln_type)
                return

        self.data["vulnerability_type"] = "unknown"

    def _suggest_payload(self, vuln_type: str) -> None:
        payloads = {
            "sql_injection": "' OR '1'='1' -- -",
            "rce": "127.0.0.1; whoami",
            "lfi": "../../../../etc/passwd",
            "xss": "<script>alert(1)</script>",
            "buffer_overflow": "A" * 512,
            "command_injection": "127.0.0.1 | id",
            "privilege_escalation": "sudo -u root /bin/bash",
            "dos": "ping -l 65500 -t 127.0.0.1",
            "ssrf": "http://169.254.169.254/latest/meta-data/",
            "xxe": "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "deserialization": "O:1:\"A\":0:{}",
            "authentication_bypass": "admin' OR '1'='1'",
            "information_disclosure": "../../../.env",
        }
        self.data["suggested_payload"] = payloads.get(vuln_type, "")

    def analyze(self) -> dict:
        if not self.fetch_from_nvd():
            self.data["description"] = f"Descrizione non disponibile per {self.cve_id}"

        self.infer_vulnerability_type()
        self.data["analyzed_at"] = datetime.now().isoformat()
        return self.data


def main():
    parser = argparse.ArgumentParser(description="Analizza una CVE tramite NVD.")
    parser.add_argument("--cve", required=True, help="ID della CVE")
    args = parser.parse_args()

    result = CVEAnalyzer(args.cve).analyze()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()