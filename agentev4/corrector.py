#!/usr/bin/env python3
"""
Correzione di uno script exploit fallito. Riceve il codice, l'errore
di esecuzione e la cronologia dei tentativi precedenti; interroga
DeepSeek per ottenere una versione corretta del codice.
"""

import json
import sys
import ast
import argparse
import requests
import re
import time
from datetime import datetime
from typing import Dict, Any, Optional, List

from prompts import BASE_GUIDELINES

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"


class ExploitCorrector:
    def __init__(
        self,
        api_key: str,
        model: str,
        code: str,
        error: dict,
        cve: str,
        cve_data: Optional[dict] = None,
        history: Optional[List[dict]] = None,
    ):
        self.api_key = api_key
        self.model = model
        self.code = code
        self.error = error
        self.cve = cve
        self.cve_data = cve_data or {}
        self.history = history or []
        self.corrected_code = None

    def build_user_prompt(self, retry_warnings: Optional[List[str]] = None) -> str:
        error_str = json.dumps(self.error, indent=2) if self.error else "Nessun errore specifico fornito"
        fence = "`" * 3

        cve_context = ""
        if self.cve_data:
            cve_context = f"""
CVE: {self.cve}
Tipo: {self.cve_data.get('vulnerability_type', 'unknown')}
Payload suggerito: {self.cve_data.get('suggested_payload', 'N/A')}
"""

        history_context = ""
        if self.history:
            history_context = "\nCronologia tentativi precedenti:\n"
            for i, entry in enumerate(self.history, 1):
                err = entry.get("error", {}).get("error", "N/A")
                err_short = str(err)[:200]
                outcome = entry.get("outcome", "fallito")
                history_context += f"\nTentativo {i} (esito: {outcome})\n"
                history_context += f"Errore: {err_short}\n"
                if entry.get("corrected_code"):
                    snippet = entry["corrected_code"][:1500]
                    history_context += f"Codice proposto:\n{fence}python\n{snippet}\n{fence}\n"
            history_context += "\nNota: evita di ripetere le correzioni già tentate. Se un approccio ha fallito, prova una strategia diversa."

        retry_block = ""
        if retry_warnings:
            retry_block = "\nRETRY - CORREZIONI IDENTICHE RILEVATE\n"
            for w in retry_warnings:
                retry_block += f"- {w}\n"
            retry_block += (
                "\nDevi fare modifiche SOSTANZIALI. "
                "Non riformattare, non aggiungere commenti, non rinominare variabili. "
                "Se il codice sembra corretto ma fallisce, ripensa la logica: "
                "endpoint, payload, verifica dell'evidenza.\n"
            )

        return f"""Scrivi lo SCRIPT PYTHON corretto per l'exploit della CVE {self.cve}.

ATTENZIONE: devi produrre CODICE PYTHON eseguibile, NON un oggetto JSON.
Il JSON con "exploit_success" e "evidence" è ciò che lo SCRIPT deve STAMPARE quando viene eseguito.
{cve_context}
{history_context}
{retry_block}
Codice exploit attuale (fallito):
{fence}python
{self.code}
{fence}

Errore durante l'esecuzione:
{fence}json
{error_str}
{fence}

Requisiti:
- Mantieni la stessa firma: `def exploit(target)` e `if __name__ == "__main__"`.
- Usa argparse con --target.
- Stampa JSON con "exploit_success" e "evidence".
- Gestisci timeout e retry (almeno 3 tentativi).
- Solo librerie standard: requests, urllib, json, argparse, sys.
- Correggi l'errore specifico identificato sopra.
- Nessun commento, nessuna spiegazione: solo codice Python.

Rispondi con il codice Python COMPLETO, racchiuso in un blocco ```python.
"""

    def call_deepseek(self, retries: int = 2) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        retry_warnings = []
        original_normalized = self._normalize(self.code)

        for attempt in range(retries):
            prompt = self.build_user_prompt(retry_warnings=retry_warnings)

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": BASE_GUIDELINES},
                    {"role": "user", "content": prompt},
                ],
                "reasoning_effort": "low",
                "max_tokens": 16384,
            }

            try:
                response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=300)
                response.raise_for_status()
                result = response.json()
            except requests.exceptions.RequestException as e:
                print(f"Errore di rete ({attempt+1}/{retries}): {e}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue
            except ValueError as e:
                print(f"Risposta non JSON ({attempt+1}/{retries}): {e}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            try:
                message = result["choices"][0]["message"]
            except (KeyError, IndexError, TypeError):
                print(f"Struttura risposta inattesa ({attempt+1}/{retries})", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            code = (message.get("content") or "").strip()
            if not code:
                code = (message.get("reasoning_content") or "").strip()

            if not code:
                print(f"Risposta vuota (tentativo {attempt+1})", file=sys.stderr)
                retry_warnings.append(f"Tentativo {attempt+1}: risposta vuota")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            finish_reason = result.get("choices", [{}])[0].get("finish_reason")
            usage = result.get("usage", {})
            details = usage.get("completion_tokens_details", {}) or {}
            completion = usage.get("completion_tokens", 0)
            reasoning = details.get("reasoning_tokens", 0)

            print(
                f"Token correzione: prompt={usage.get('prompt_tokens')} "
                f"completion={completion} reasoning={reasoning}",
                file=sys.stderr,
            )

            if completion > 0 and reasoning >= completion - 100:
                print(f"Reasoning esaurito (tentativo {attempt+1})", file=sys.stderr)
                retry_warnings.append(f"Tentativo {attempt+1}: reasoning esaurito")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            if finish_reason == "length":
                print(f"Correzione troncata (tentativo {attempt+1})", file=sys.stderr)
                retry_warnings.append(f"Tentativo {attempt+1}: risposta troncata")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            cleaned = self._extract_code(code)
            if not cleaned:
                retry_warnings.append(f"Tentativo {attempt+1}: output non valido")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            try:
                ast.parse(cleaned)
            except SyntaxError as e:
                print(f"Errore di sintassi: {e}", file=sys.stderr)
                retry_warnings.append(f"Tentativo {attempt+1}: SyntaxError")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            if len(cleaned) <= 50:
                retry_warnings.append(f"Tentativo {attempt+1}: codice troppo corto")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            if self._normalize(cleaned) == original_normalized:
                print(f"Codice identico all'input (tentativo {attempt+1})", file=sys.stderr)
                retry_warnings.append(
                    f"Tentativo {attempt+1}: il modello ha restituito codice identico all'input."
                )
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

            return cleaned

        print(f"Correzione fallita dopo {retries} tentativi", file=sys.stderr)
        return None

    def _normalize(self, code: str) -> str:
        lines = []
        for line in code.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                continue
            lines.append(" ".join(stripped.split()))
        return "\n".join(lines)

    def _extract_code(self, raw: str) -> str:
        text = raw.strip()
        if not text:
            return None

        if "```" in text:
            match = re.search(r"```(?:python|py)?\s*\n(.*?)\n```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
            else:
                lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
                text = "\n".join(lines).strip()

        return text

    def correct(self) -> Dict[str, Any]:
        print(f"Correzione exploit per {self.cve} (model={self.model})...", file=sys.stderr)
        code = self.call_deepseek()

        if not code:
            return {
                "error": "Correzione fallita - nessun codice valido o nessuna modifica sostanziale",
                "code": None,
            }

        self.corrected_code = code
        return {
            "code": code,
            "code_length": len(code),
            "timestamp": datetime.now().isoformat(),
        }


def main():
    parser = argparse.ArgumentParser(description="Corregge exploit fallito usando DeepSeek.")
    parser.add_argument("--api-key", required=True, help="Chiave API DeepSeek")
    parser.add_argument(
        "--model",
        default="deepseek-flash",
        choices=["deepseek-flash", "deepseek-v4-pro"],
        help="Modello DeepSeek",
    )
    parser.add_argument("--code", required=True, help="Codice exploit fallito")
    parser.add_argument("--error", required=True, help="Errore dell'esecuzione (JSON)")
    parser.add_argument("--cve", required=True, help="ID della CVE")
    parser.add_argument("--cve-data", default="{}", help="Dati CVE aggiuntivi (JSON)")
    parser.add_argument("--history", default="[]", help="Cronologia errori e correzioni (JSON array)")
    args = parser.parse_args()

    try:
        error_data = json.loads(args.error)
    except json.JSONDecodeError:
        error_data = {"raw_error": args.error}

    try:
        cve_data = json.loads(args.cve_data) if args.cve_data != "{}" else {}
    except json.JSONDecodeError:
        cve_data = {}

    try:
        history = json.loads(args.history) if args.history != "[]" else []
    except json.JSONDecodeError:
        history = []

    corrector = ExploitCorrector(
        api_key=args.api_key,
        model=args.model,
        code=args.code,
        error=error_data,
        cve=args.cve,
        cve_data=cve_data,
        history=history,
    )

    result = corrector.correct()

    if result.get("error"):
        print(json.dumps({"error": result["error"]}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result))


if __name__ == "__main__":
    main()