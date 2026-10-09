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
        self.generated_code = None
        self.exploit_path = None

    def build_system_prompt(self) -> str:
        return BASE_GUIDELINES

    def build_user_prompt(self) -> str:
        cve_info = self.cve_data
        descrizione = (cve_info.get('description') or '')[:500]
        tipo = cve_info.get('vulnerability_type', 'unknown')
        prodotto = cve_info.get('product', 'unknown')
        versione = cve_info.get('version', 'unknown')
        payload = cve_info.get('suggested_payload', 'N/A')

        custom_block = ""
        if self.custom_prompt:
            custom_block = f"""
INFORMAZIONI SPECIFICHE SUL TARGET (più attendibili delle tue ipotesi):
{self.custom_prompt[:500]}
"""

        prompt = f"""Scrivi uno SCRIPT PYTHON che testa la CVE {self.cve} su un target specificato.

═══════════════════════════════════════════════════════════
TASK
═══════════════════════════════════════════════════════════
Produci CODICE PYTHON eseguibile (non un oggetto JSON, non pseudocodice).
Il JSON con "exploit_success" e "evidence" è ciò che lo SCRIPT deve STAMPARE quando eseguito.

═══════════════════════════════════════════════════════════
CONTESTO VULNERABILITÀ
═══════════════════════════════════════════════════════════
- CVE: {self.cve}
- Tipo: {tipo}
- Prodotto: {prodotto} {versione}
- Descrizione: {descrizione}
- Payload suggerito: {payload}
{custom_block}
═══════════════════════════════════════════════════════════
RAGIONAMENTO STRUTTURATO (completa in 6 punti brevi, max 100 parole ciascuno)
═══════════════════════════════════════════════════════════
1. VETTORE: quale endpoint/porta/protocollo raggiunge la vulnerabilità?
2. PAYLOAD: quale payload specifico va inviato (esatto, non generico)?
3. RICHIESTA: come va costruita (metodo HTTP, header, parametri, body, encoding)?
4. VERIFICA: quale indicatore nella risposta conferma il successo (stringa, codice HTTP, output comando)?
5. ERRORI: quali sono i 2-3 errori tipici per questa CVE che devi evitare?
6. OUTPUT: come deve apparire il JSON finale (chiavi, tipi, contenuto di evidence)?

Dopo aver completato i 6 punti, scrivi IMMEDIATAMENTE il codice.
Non tornare a riflettere dopo il punto 6. Non aggiungere altre analisi.
Inizia la risposta con ```python.

═══════════════════════════════════════════════════════════
REQUISITI DELLO SCRIPT
═══════════════════════════════════════════════════════════
1. argparse per accettare --target (es. python3 exploit.py --target http://127.0.0.1:8100)
2. Funzione `exploit(target)` che esegue il test
3. Stampa su stdout: {{"exploit_success": bool, "evidence": str}}
4. Timeout e retry (almeno 3 tentativi) per connessioni
5. Solo librerie standard: requests, urllib, socket, json, argparse, sys, base64, hashlib, hmac, re, time
6. Se requests non è disponibile, usa urllib.request
7. Prima riga del codice: `#!/usr/bin/env python3` o `import ...`
8. Nessun commento, nessuna spiegazione nel codice

═══════════════════════════════════════════════════════════
REGOLE UNIVERSALI PER L'EXPLOIT
═══════════════════════════════════════════════════════════
- NON assumere che il target sia raggiungibile: gestisci timeout, connection refused, DNS failure
- NON assumere che il payload funzioni al primo colpo: prova varianti se rilevante
- Il campo `evidence` deve contenere PROVA concreta (output del comando, dato leaked, codice HTTP anoma)
- Se il test fallisce, `exploit_success` = False e `evidence` spiega cosa è andato storto
- Se la risposta HTTP non è 200, NON è automaticamente un fallimento: verifica il contenuto

═══════════════════════════════════════════════════════════
OUTPUT ATTESO
═══════════════════════════════════════════════════════════
Rispondi SOLO con il codice Python completo, racchiuso in un blocco ```python.
"""
        return prompt

    def call_deepseek(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "reasoning_effort": "medium",
            "max_tokens": 32768
        }

        response = None
        try:
            response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=600)
            response.raise_for_status()
            result = response.json()
            message = result['choices'][0]['message']

            code = (message.get('content') or '').strip()
            if not code:
                code = (message.get('reasoning_content') or '').strip()

            if not code:
                print("Risposta vuota da DeepSeek.", file=sys.stderr)
                return None

            finish_reason = result.get('choices', [{}])[0].get('finish_reason')
            usage = result.get('usage', {})
            details = usage.get('completion_tokens_details', {}) or {}
            completion = usage.get('completion_tokens', 0)
            reasoning = details.get('reasoning_tokens', 0)

            print(
                f"Token: prompt={usage.get('prompt_tokens')} "
                f"completion={completion} reasoning={reasoning}",
                file=sys.stderr
            )

            if completion > 0 and reasoning >= completion - 100:
                print(
                    f"Il reasoning ({reasoning}) ha esaurito il budget di token. "
                    "Nessun output utile generato. Richiedo retry.",
                    file=sys.stderr
                )
                return None

            if finish_reason == 'length':
                print(
                    "Risposta troncata per limite di token (finish_reason='length').",
                    file=sys.stderr
                )

            return self._clean_code(code)

        except requests.exceptions.RequestException as e:
            print(f"Errore di rete chiamata DeepSeek: {e}", file=sys.stderr)
            return None
        except KeyError as e:
            print(f"Errore parsing risposta DeepSeek: {e}", file=sys.stderr)
            if response is not None:
                print(f"Risposta ricevuta: {response.text[:200]}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Errore generico chiamata DeepSeek: {e}", file=sys.stderr)
            return None

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

        keywords = ['import', 'def ', 'class ', 'from ', 'if __name__', 'print(', 'return ']
        if not any(k in text for k in keywords):
            print("Il testo pulito non sembra contenere codice Python valido.", file=sys.stderr)
            print(f"Primi 300 caratteri: {text[:300]}", file=sys.stderr)
            return None

        try:
            ast.parse(text)
        except SyntaxError as e:
            print(f"Codice Python con errore di sintassi: {e}", file=sys.stderr)
            return None

        return text

    def save_exploit(self, code: str) -> Path:
        exploits_dir = Path("exploits")
        exploits_dir.mkdir(exist_ok=True)

        filename = f"exploit_{self.cve}.py"
        filepath = exploits_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(code)

        history_dir = exploits_dir / "history"
        history_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        history_path = history_dir / f"{self.cve}_{ts}.py"
        with open(history_path, 'w', encoding='utf-8') as f:
            f.write(code)

        try:
            filepath.chmod(0o755)
        except Exception:
            pass

        return filepath

    def generate(self) -> dict:
        system_prompt = self.build_system_prompt()
        user_prompt = self.build_user_prompt()

        print(f"Chiamata DeepSeek per generare exploit per {self.cve} (model={self.model}, effort=medium)...", file=sys.stderr)
        code = self.call_deepseek(system_prompt, user_prompt)

        if not code:
            return {"error": "Generazione fallita", "exploit_path": None}

        if len(code.strip()) < 50:
            print(f"Codice generato molto corto ({len(code)} caratteri).", file=sys.stderr)

        filepath = self.save_exploit(code)
        self.generated_code = code
        self.exploit_path = str(filepath)

        return {
            "exploit_path": str(filepath),
            "code_length": len(code),
            "timestamp": datetime.now().isoformat()
        }


def main():
    parser = argparse.ArgumentParser(description="Genera exploit per CVE usando DeepSeek.")
    parser.add_argument("--cve", required=True, help="ID CVE")
    parser.add_argument("--api-key", required=True, help="Chiave API DeepSeek")
    parser.add_argument("--model", default="deepseek-flash", help="Modello DeepSeek")
    parser.add_argument("--data", required=True, help="Dati CVE in formato JSON (stringa)")
    parser.add_argument("--custom-prompt", default="", help="Prompt personalizzato aggiuntivo")
    args = parser.parse_args()

    try:
        cve_data = json.loads(args.data)
    except json.JSONDecodeError:
        print("Errore: i dati CVE non sono in formato JSON valido", file=sys.stderr)
        sys.exit(1)

    generator = ExploitGenerator(
        cve=args.cve,
        api_key=args.api_key,
        model=args.model,
        cve_data=cve_data,
        custom_prompt=args.custom_prompt
    )
    result = generator.generate()

    if result.get("error"):
        print(json.dumps({"error": result["error"]}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
    print(json.dumps(result))


if __name__ == "__main__":
    main()
