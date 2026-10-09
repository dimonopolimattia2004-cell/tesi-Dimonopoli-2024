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
        history: Optional[List[dict]] = None
    ):
        self.api_key = api_key
        self.model = model
        self.code = code
        self.error = error
        self.cve = cve
        self.cve_data = cve_data or {}
        self.history = history or []
        self.corrected_code = None

    def build_system_prompt(self) -> str:
        return BASE_GUIDELINES

    def build_user_prompt(self, retry_warnings: Optional[List[str]] = None) -> str:
        error_str = json.dumps(self.error, indent=2) if self.error else "Nessun errore specifico fornito"
        fence = "`" * 3

        cve_context = ""
        if self.cve_data:
            cve_context = (
                f"- CVE: {self.cve}\n"
                f"- Tipo: {self.cve_data.get('vulnerability_type', 'unknown')}\n"
                f"- Prodotto: {self.cve_data.get('product', 'unknown')}\n"
                f"- Payload suggerito: {self.cve_data.get('suggested_payload', 'N/A')}\n"
                f"- Descrizione: {(self.cve_data.get('description') or '')[:300]}"
            )

        history_context = ""
        if self.history:
            history_context = "\n=== CRONOLOGIA TENTATIVI PRECEDENTI ===\n"
            for i, entry in enumerate(self.history, 1):
                err = entry.get('error', {}).get('error', 'N/A')
                err_short = str(err)[:200]
                outcome = entry.get('outcome', 'fallito')
                history_context += f"\n--- Tentativo {i} (esito: {outcome}) ---\n"
                history_context += f"Errore riscontrato: {err_short}\n"
                if entry.get('corrected_code'):
                    code_snippet = entry['corrected_code'][:1500]
                    history_context += f"Codice proposto (troncato):\n{fence}python\n{code_snippet}\n{fence}\n"
            history_context += "\n>>> ATTENZIONE: evita di riproporre correzioni gia tentate senza successo. Se un approccio ha fallito, prova una strategia DIVERSA.\n"

        retry_block = ""
        if retry_warnings:
            retry_block = "\n=== RETRY - CORREZIONI IDENTICHE RILEVATE ===\n"
            for w in retry_warnings:
                retry_block += f"- {w}\n"
            retry_block += (
                "\nDevi fare modifiche SOSTANZIALI alla LOGICA. "
                "NON riformattare, NON aggiungere commenti, NON rinominare variabili. "
                "Se il codice sembra corretto ma fallisce, ripensa: endpoint, payload, "
                "verifica dell'evidenza, timeout, parsing della risposta.\n"
            )

        template = f"""Correggi lo SCRIPT PYTHON per l'exploit della CVE {self.cve} che ha fallito.

=== TASK ===
Produci CODICE PYTHON eseguibile (non un oggetto JSON, non pseudocodice).
Il JSON con "exploit_success" e "evidence" e cio che lo SCRIPT deve STAMPARE quando eseguito.

=== CONTESTO ===
{cve_context}
{history_context}
{retry_block}

=== CODICE ATTUALE (che ha fallito) ===
{fence}python
{self.code}
{fence}

=== ERRORE RISCONTRATO ===
{fence}json
{error_str}
{fence}

=== ANALISI STRUTTURATA (completa in 5 punti brevi, max 80 parole ciascuno) ===
1. CAUSA: qual e la causa radice dell'errore? (timeout, endpoint sbagliato, payload errato, parsing, eccezione)
2. FIX: quale modifica specifica risolve la causa? (non "aggiungi timeout", ma "aumenta timeout a 30s e aggiungi retry su ConnectionError")
3. IMPATTO: la modifica risolve solo l'errore o potrebbe introdurne altri? (es. aumentare timeout rallenta il test)
4. VERIFICA: come saprai che la correzione ha funzionato? (quale output/comportamento diverso)
5. COMPLETEZZA: il resto del codice resta valido? Ci sono altre parti da aggiornare in coerenza?

Dopo aver completato i 5 punti, scrivi IMMEDIATAMENTE il codice corretto.
Non tornare a riflettere dopo il punto 5. Non aggiungere altre analisi.
Inizia la risposta con ```python.

=== REQUISITI DELLA CORREZIONE ===
1. Mantieni la struttura originale: `def exploit(target)`, `if __name__ == "__main__"`
2. Usa argparse con --target
3. Stampa JSON con "exploit_success" (bool) e "evidence" (str)
4. Correggi SOLO l'errore identificato, senza riscrivere da zero parti non problematiche
5. Timeout e retry (almeno 3 tentativi) per connessioni
6. Solo librerie standard: requests, urllib, socket, json, argparse, sys, base64, hashlib, hmac, re, time
7. Se requests non e disponibile, usa urllib.request
8. Prima riga del codice: `#!/usr/bin/env python3` o `import ...`
9. Nessun commento, nessuna spiegazione nel codice

=== ERRORI COMUNI DI CORREZIONE (da EVITARE) ===
- Riscrivere da zero un codice che funzionava quasi: mantieni cio che va bene
- Aggiungere "try/except: pass" che nasconde errori invece di gestirli
- Aumentare timeout senza motivo quando il problema e un endpoint sbagliato
- Aggiungere retry su errori permanenti (403, 401, 404) che non migliorano col retry
- Cambiare firma della funzione exploit() o rimuovere argparse
- Dimenticare di aggiornare la logica di verifica (evidence) dopo il fix
- Ritornare JSON come stringa invece di stamparlo con json.dumps

=== OUTPUT ATTESO ===
Rispondi SOLO con il codice Python completo e corretto, racchiuso in un blocco ```python.
"""
        return template

    def call_deepseek(self, retries: int = 2) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        system_prompt = self.build_system_prompt()
        retry_warnings = []
        original_normalized = self._normalize(self.code)

        for attempt in range(retries):
            prompt = self.build_user_prompt(retry_warnings=retry_warnings)

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "reasoning_effort": "medium",
                "max_tokens": 32768
            }

            try:
                response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=600)
                response.raise_for_status()
                result = response.json()
                message = result['choices'][0]['message']

                code = (message.get('content') or '').strip()
                if not code:
                    code = (message.get('reasoning_content') or '').strip()

                if not code:
                    print(f"ATTENZIONE: risposta vuota da DeepSeek (tentativo {attempt+1})", file=sys.stderr)
                    retry_warnings.append(f"Tentativo {attempt+1}: risposta vuota")
                    if attempt < retries - 1:
                        time.sleep(2 ** attempt)
                    continue

                finish_reason = result.get('choices', [{}])[0].get('finish_reason')
                usage = result.get('usage', {})
                details = usage.get('completion_tokens_details', {}) or {}
                completion = usage.get('completion_tokens', 0)
                reasoning = details.get('reasoning_tokens', 0)

                print(
                    f"Token correzione: prompt={usage.get('prompt_tokens')} "
                    f"completion={completion} reasoning={reasoning}",
                    file=sys.stderr
                )

                if completion > 0 and reasoning >= completion - 100:
                    print(f"ATTENZIONE: reasoning ha esaurito il budget (tentativo {attempt+1})", file=sys.stderr)
                    retry_warnings.append(f"Tentativo {attempt+1}: reasoning esaurito")
                    if attempt < retries - 1:
                        time.sleep(2 ** attempt)
                    continue

                if finish_reason == 'length':
                    print(f"ATTENZIONE: correzione troncata (tentativo {attempt+1})", file=sys.stderr)
                    retry_warnings.append(f"Tentativo {attempt+1}: risposta troncata")
                    if attempt < retries - 1:
                        time.sleep(2 ** attempt)
                    continue

                cleaned = self._clean_code(code)
                if not cleaned:
                    retry_warnings.append(f"Tentativo {attempt+1}: output non valido")
                    if attempt < retries - 1:
                        time.sleep(2 ** attempt)
                    continue

                try:
                    ast.parse(cleaned)
                except SyntaxError as e:
                    print(f"ATTENZIONE: correzione con errore di sintassi: {e}", file=sys.stderr)
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
                    print(f"ATTENZIONE: tentativo {attempt+1}: codice identico all'input", file=sys.stderr)
                    retry_warnings.append(
                        f"Tentativo {attempt+1}: il modello ha restituito codice identico all'input."
                    )
                    if attempt < retries - 1:
                        time.sleep(2 ** attempt)
                    continue

                return cleaned

            except requests.exceptions.RequestException as e:
                print(f"Errore di rete (tentativo {attempt+1}): {e}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue
            except KeyError as e:
                print(f"Errore parsing risposta DeepSeek: {e}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue
            except Exception as e:
                print(f"Errore generico (tentativo {attempt+1}): {e}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                continue

        print(f"Correzione fallita dopo {retries} tentativi", file=sys.stderr)
        return None

    def _normalize(self, code: str) -> str:
        lines = []
        for line in code.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('#'):
                continue
            normalized = ' '.join(stripped.split())
            lines.append(normalized)
        return '\n'.join(lines)

    def _clean_code(self, raw_code: str) -> str:
        text = raw_code.strip()
        if not text:
            return None

        if '```' in text:
            match = re.search(r"```(?:python|py)?\s*\n(.*?)\n```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
            else:
                lines = text.split('\n')
                cleaned_lines = []
                for l in lines:
                    stripped = l.strip()
                    if stripped == '```' or stripped.startswith('```python') or stripped.startswith('```py'):
                        continue
                    cleaned_lines.append(l)
                text = '\n'.join(cleaned_lines).strip()

        return text

    def correct(self) -> Dict[str, Any]:
        print(f"Correzione exploit per {self.cve} (model={self.model}, effort=medium)...", file=sys.stderr)
        code = self.call_deepseek()

        if not code:
            return {
                "error": "Correzione fallita - nessun codice valido o nessuna modifica sostanziale",
                "code": None
            }

        self.corrected_code = code
        return {
            "code": code,
            "code_length": len(code),
            "timestamp": datetime.now().isoformat()
        }


def main():
    parser = argparse.ArgumentParser(description="Corregge exploit fallito usando DeepSeek.")
    parser.add_argument("--api-key", required=True, help="Chiave API DeepSeek")
    parser.add_argument(
        "--model",
        default="deepseek-flash",
        choices=["deepseek-flash", "deepseek-v4-pro"],
        help="Modello DeepSeek (default: deepseek-flash)"
    )
    parser.add_argument("--code", required=True, help="Codice exploit fallito (stringa)")
    parser.add_argument("--error", required=True, help="Errore dell'esecuzione (JSON string)")
    parser.add_argument("--cve", required=True, help="ID della CVE")
    parser.add_argument("--cve-data", default="{}", help="Dati CVE aggiuntivi (JSON string, opzionale)")
    parser.add_argument("--history", default="[]", help="Cronologia errori e correzioni (JSON array, opzionale)")
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
        history=history
    )

    result = corrector.correct()

    if result.get("error"):
        print(json.dumps({"error": result["error"]}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
