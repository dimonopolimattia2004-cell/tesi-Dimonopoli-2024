#!/usr/bin/env python3
"""
Analisi di una CVE tramite DeepSeek. Recupera i metadati della
vulnerabilità (descrizione, prodotto, versione, severità, tipo,
payload di test) interrogando direttamente l'API del modello,
senza dipendere da NVD o altre fonti esterne.
"""

import json
import os
import sys
import argparse
import requests
import re
from datetime import datetime
from typing import Dict, Any, Optional

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"

CATEGORIE_AMMESSE = [
    "sql_injection", "xss", "csrf", "ssrf", "xxe", "lfi", "rfi",
    "path_traversal", "file_upload", "open_redirect", "clickjacking",
    "http_request_smuggling", "idor", "ssti", "ldap_injection",
    "xpath_injection", "prototype_pollution", "graphql_injection",
    "api_abuse", "rce", "command_injection", "deserialization",
    "buffer_overflow", "integer_overflow", "format_string",
    "use_after_free", "race_condition", "authentication_bypass",
    "privilege_escalation", "session_fixation", "broken_access_control",
    "information_disclosure", "crypto_failure", "insecure_configuration",
    "dos", "business_logic",
]


class CVEAnalyzer:
    def __init__(self, cve_id: str, api_key: Optional[str] = None, model: str = "deepseek-flash"):
        self.cve_id = cve_id.upper().strip()
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY") or "sk-13efa0e753d341e79e8f70a27de94331"
        self.model = model
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

    def analyze_with_deepseek(self) -> bool:
        if not self.api_key:
            print("API key DeepSeek non fornita.", file=sys.stderr)
            return False

        prompt = f"""Analizza la vulnerabilità {self.cve_id} e restituisci un JSON con esattamente questi campi:

{{
  "description": "<descrizione tecnica dettagliata>",
  "product": "<nome del prodotto affetto>",
  "version": "<versione affetta principale>",
  "affected_versions": ["<lista>", "<di>", "<versioni>"],
  "severity": "<LOW, MEDIUM, HIGH o CRITICAL>",
  "cvss_score": <numero decimale>,
  "vulnerability_type": "<una di: {', '.join(CATEGORIE_AMMESSE)}>",
  "attack_vector": "<NETWORK, ADJACENT, LOCAL o PHYSICAL>",
  "suggested_payload": "<payload di test consigliato>",
  "references": ["<url>", "<url>"]
}}

Per ogni campo fornisci un valore plausibile in base alla tua conoscenza della CVE. Non usare mai la parola "unknown" o "other". Rispondi SOLO con il JSON, senza testo aggiuntivo, senza backtick, senza commenti."""

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Sei un analista di sicurezza informatica esperto in vulnerabilità software. Rispondi esclusivamente con JSON valido, senza testo introduttivo o conclusivo.",
                },
                {"role": "user", "content": prompt},
            ],
            "thinking": {"type": "disabled"},
            "max_tokens": 2048,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]

            content = (message.get("content") or "").strip()
            if not content:
                reasoning = (message.get("reasoning_content") or "").strip()
                if reasoning:
                    content = reasoning

            if not content:
                print("Risposta vuota da DeepSeek.", file=sys.stderr)
                return False

            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
            else:
                data = json.loads(content)

            self.data["description"] = data.get("description") or ""
            self.data["product"] = data.get("product") or ""
            self.data["version"] = data.get("version") or ""
            self.data["affected_versions"] = data.get("affected_versions") or []
            self.data["severity"] = data.get("severity") or ""
            self.data["cvss_score"] = data.get("cvss_score") or 0

            vuln_type = data.get("vulnerability_type", "")
            self.data["vulnerability_type"] = vuln_type if vuln_type in CATEGORIE_AMMESSE else ""

            self.data["attack_vector"] = data.get("attack_vector", "")
            self.data["suggested_payload"] = data.get("suggested_payload", "")
            self.data["references"] = data.get("references", [])

            return True

        except requests.exceptions.RequestException as e:
            print(f"Errore di rete: {e}", file=sys.stderr)
            return False
        except json.JSONDecodeError as e:
            print(f"Errore parsing JSON: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Errore generico: {e}", file=sys.stderr)
            return False

    def fallback_minimale(self) -> None:
        self.data["description"] = f"Descrizione non disponibile per {self.cve_id}"
        self.data["vulnerability_type"] = ""
        self.data["suggested_payload"] = ""
        self.data["attack_vector"] = ""
        self.data["severity"] = ""
        self.data["cvss_score"] = 0
        self.data["product"] = ""
        self.data["version"] = ""
        self.data["affected_versions"] = []
        self.data["references"] = []

    def analyze(self) -> Dict[str, Any]:
        print(f"Analisi DeepSeek per {self.cve_id} (model={self.model})...", file=sys.stderr)
        ok = self.analyze_with_deepseek()

        if not ok:
            print("Fallback locale attivato.", file=sys.stderr)
            self.fallback_minimale()

        self.data["analyzed_at"] = datetime.now().isoformat()
        return self.data


def main():
    parser = argparse.ArgumentParser(description="Analizza una CVE tramite DeepSeek e restituisce JSON.")
    parser.add_argument("--cve", required=True, help="ID della CVE")
    parser.add_argument("--api-key", help="Chiave API DeepSeek (opzionale)")
    parser.add_argument("--model", default="deepseek-flash", help="Modello DeepSeek")
    args = parser.parse_args()

    analyzer = CVEAnalyzer(args.cve, api_key=args.api_key, model=args.model)
    result = analyzer.analyze()

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()