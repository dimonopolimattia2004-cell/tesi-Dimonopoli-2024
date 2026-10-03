#!/usr/bin/env python3
"""
Genera uno script exploit Python a partire dai metadati di una CVE
tramite l'API di DeepSeek. Il codice prodotto viene salvato in una
cartella dedicata e reso eseguibile.
"""

import json
import sys
import ast
import argparse
import requests
import re
from pathlib import Path
from datetime import datetime

from prompts import BASE_GUIDELINES

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"


class ExploitGenerator:
    def __init__(self, cve: str, api_key: str, model: str, cve_data: dict, custom_prompt: str = ""):
        self.cve = cve
        self.api_key = api_key
        self.model = model
        self.cve_data = cve_data
        self.custom_prompt = custom_prompt
        self.exploit_path = None

    def build_user_prompt(self) -> str:
        cve_info = self.cve_data
        descrizione = (cve_info.get("description") or "")[:500]
        tipo = cve_info.get("vulnerability_type", "unknown")
        prodotto = cve_info.get("product", "unknown")
        payload = cve_info.get("suggested_payload", "N/A")

        prompt = f"""Scrivi uno SCRIPT PYTHON che testa la CVE {self.cve}.

ATTENZIONE: devi produrre CODICE PYTHON eseguibile, NON un oggetto JSON.
Il JSON con "exploit_success" e "evidence" è ciò che lo SCRIPT deve STAMPARE quando viene eseguito, non ciò che devi restituire tu.

Dettagli della vulnerabilità:
- Descrizione: {descrizione}
- Tipo: {tipo}
- Prodotto: {prodotto}
- Payload suggerito: {payload}

Requisiti dello script:
1. Usa argparse per accettare --target (es. python3 exploit.py --target http://127.0.0.1:8100).
2. Esegui il test della vulnerabilità sul target.
3. Stampa su stdout un JSON con le chiavi "exploit_success" (bool) e "evidence" (stringa).
4. Gestisci timeout ed errori di connessione.
5. Inizia con import o shebang: la prima riga deve essere codice Python.

Rispondi con il codice Python COMPLETO, racchiuso in un blocco ```python.
"""
        if self.custom_prompt:
            prompt += f"\nIstruzioni specifiche per questa CVE:\n{self.custom_prompt[:400]}"
        return prompt

    def call_deepseek(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "reasoning_effort": "medium",
            "max_tokens": 32768,
        }

        try:
            response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=300)
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Errore di rete: {e}", file=sys.stderr)
            return None
        except ValueError as e:
            print(f"Risposta non JSON: {e}", file=sys.stderr)
            return None

        try:
            message = result["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            print("Struttura risposta inattesa", file=sys.stderr)
            return None

        code = (message.get("content") or "").strip()
        if not code:
            code = (message.get("reasoning_content") or "").strip()

        if not code:
            print("Risposta vuota da DeepSeek.", file=sys.stderr)
            return None

        finish_reason = result.get("choices", [{}])[0].get("finish_reason")
        usage = result.get("usage", {})
        details = usage.get("completion_tokens_details", {}) or {}
        completion = usage.get("completion_tokens", 0)
        reasoning = details.get("reasoning_tokens", 0)

        print(
            f"Token: prompt={usage.get('prompt_tokens')} "
            f"completion={completion} reasoning={reasoning}",
            file=sys.stderr,
        )

        if completion > 0 and reasoning >= completion - 100:
            print(
                f"Il reasoning ({reasoning}) ha esaurito il budget. Richiedo retry.",
                file=sys.stderr,
            )
            return None

        if finish_reason == "length":
            print("Risposta troncata per limite di token.", file=sys.stderr)

        return self._extract_code(code)

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

        keywords = ("import", "def ", "class ", "from ", "if __name__", "print(", "return ")
        if not any(k in text for k in keywords):
            print("Output senza codice Python riconoscibile.", file=sys.stderr)
            return None

        try:
            ast.parse(text)
        except SyntaxError as e:
            print(f"Errore di sintassi nel codice: {e}", file=sys.stderr)
            return None

        return text

    def save_exploit(self, code: str) -> Path:
        exploits_dir = Path("exploits")
        exploits_dir.mkdir(exist_ok=True)
        filepath = exploits_dir / f"exploit_{self.cve}.py"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)

        history_dir = exploits_dir / "history"
        history_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(history_dir / f"{self.cve}_{ts}.py", "w", encoding="utf-8") as f:
            f.write(code)

        try:
            filepath.chmod(0o755)
        except OSError:
            pass

        return filepath

    def generate(self) -> dict:
        system_prompt = BASE_GUIDELINES
        user_prompt = self.build_user_prompt()

        print(f"Chiamata DeepSeek per {self.cve} (model={self.model})...", file=sys.stderr)
        code = self.call_deepseek(system_prompt, user_prompt)

        if not code:
            return {"error": "Generazione fallita", "exploit_path": None}

        if len(code.strip()) < 50:
            print(f"Codice generato corto ({len(code)} caratteri).", file=sys.stderr)

        filepath = self.save_exploit(code)
        self.exploit_path = str(filepath)

        return {
            "exploit_path": str(filepath),
            "code_length": len(code),
            "timestamp": datetime.now().isoformat(),
        }


def main():
    parser = argparse.ArgumentParser(description="Genera exploit per CVE usando DeepSeek.")
    parser.add_argument("--cve", required=True, help="ID CVE")
    parser.add_argument("--api-key", required=True, help="Chiave API DeepSeek")
    parser.add_argument("--model", default="deepseek-flash", help="Modello DeepSeek")
    parser.add_argument("--data", required=True, help="Dati CVE in formato JSON")
    parser.add_argument("--custom-prompt", default="", help="Prompt personalizzato aggiuntivo")
    args = parser.parse_args()

    try:
        cve_data = json.loads(args.data)
    except json.JSONDecodeError:
        print("Dati CVE non validi", file=sys.stderr)
        sys.exit(1)

    generator = ExploitGenerator(
        cve=args.cve,
        api_key=args.api_key,
        model=args.model,
        cve_data=cve_data,
        custom_prompt=args.custom_prompt,
    )
    result = generator.generate()

    if result.get("error"):
        print(json.dumps({"error": result["error"]}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result))


if __name__ == "__main__":
    main()