#!/usr/bin/env python3
"""
Genera uno script exploit Python a partire dai metadati di una CVE
tramite l'API di DeepSeek. Il codice prodotto viene salvato in una
cartella dedicata e reso eseguibile.
"""

import json
import sys
import argparse
import requests
import re
from pathlib import Path
from datetime import datetime

from prompts import BASE_GUIDELINES

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"


class ExploitGenerator:
    def __init__(self, cve: str, api_key: str, model: str, cve_data: dict, custom_prompt: str = ""):
        self.cve = cve
        self.api_key = api_key
        self.model = model
        self.cve_data = cve_data
        self.custom_prompt = custom_prompt
        self.exploit_path = None

    def build_user_prompt(self) -> str:
        info = self.cve_data
        prompt = f"""Genera un exploit Python per la seguente vulnerabilità:
- CVE: {info.get('cve', self.cve)}
- Descrizione: {info.get('description', 'N/A')}
- Prodotto: {info.get('product', 'unknown')}
- Versione: {info.get('version', 'unknown')}
- Tipo: {info.get('vulnerability_type', 'unknown')}
- Severità: {info.get('severity', 'N/A')}
- Payload suggerito: {info.get('suggested_payload', 'N/A')}
- Riferimenti: {', '.join(info.get('references', [])[:3])}

Il target sarà raggiungibile all'indirizzo fornito come argomento.
L'exploit deve:
1. Accettare il target tramite argparse con --target.
2. Eseguire il test utilizzando il tipo di vulnerabilità indicato.
3. Restituire JSON con "exploit_success": true/false e "evidence".
4. Essere conciso, senza commenti o spiegazioni.
"""
        if self.custom_prompt:
            prompt += f"\n\nIstruzioni specifiche per questa CVE:\n{self.custom_prompt}"
        return prompt

    def call_deepseek(self, user_prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": BASE_GUIDELINES},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
        }

        try:
            r = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=90)
            r.raise_for_status()
            result = r.json()
        except requests.RequestException as e:
            print(f"Errore di rete: {e}", file=sys.stderr)
            return None
        except ValueError as e:
            print(f"Risposta non JSON: {e}", file=sys.stderr)
            return None

        finish = result.get("choices", [{}])[0].get("finish_reason")
        if finish == "length":
            print("Risposta troncata per limite di token", file=sys.stderr)

        try:
            raw = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            print("Struttura risposta inattesa", file=sys.stderr)
            return None

        return self._extract_code(raw)

    def _extract_code(self, raw: str) -> str:
        text = raw.strip()
        if not text:
            return None

        if "```" in text:
            match = re.search(r"```(?:\w+)?\s*\n(.*?)\n```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
            else:
                lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
                text = "\n".join(lines).strip()

        keywords = ("import ", "def ", "class ", "from ", "if __name__")
        if not any(k in text for k in keywords):
            print("Output senza codice Python riconoscibile", file=sys.stderr)
            return None

        return text

    def save_exploit(self, code: str) -> Path:
        folder = Path("exploits")
        folder.mkdir(exist_ok=True)
        path = folder / f"exploit_{self.cve}.py"

        with open(path, "w", encoding="utf-8") as f:
            f.write(code)

        try:
            path.chmod(0o755)
        except OSError:
            pass

        return path

    def generate(self) -> dict:
        prompt = self.build_user_prompt()
        print(f"Chiamata DeepSeek per {self.cve}...", file=sys.stderr)
        code = self.call_deepseek(prompt)

        if not code:
            return {"error": "Generazione fallita", "exploit_path": None}

        if len(code.strip()) < 50:
            print("Codice generato sospettosamente corto", file=sys.stderr)

        path = self.save_exploit(code)
        self.exploit_path = str(path)

        return {
            "exploit_path": str(path),
            "code_length": len(code),
            "timestamp": datetime.now().isoformat(),
        }


def main():
    parser = argparse.ArgumentParser(description="Genera un exploit per una CVE.")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--data", required=True, help="Metadati CVE in JSON")
    parser.add_argument("--custom-prompt", default="")
    args = parser.parse_args()

    try:
        cve_data = json.loads(args.data)
    except json.JSONDecodeError:
        print("Metadati CVE non validi", file=sys.stderr)
        sys.exit(1)

    gen = ExploitGenerator(
        cve=args.cve,
        api_key=args.api_key,
        model=args.model,
        cve_data=cve_data,
        custom_prompt=args.custom_prompt,
    )
    result = gen.generate()

    if result.get("error"):
        print(json.dumps({"error": result["error"]}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result))


if __name__ == "__main__":
    main()