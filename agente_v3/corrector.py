#!/usr/bin/env python3
"""
Correzione di uno script exploit fallito. Riceve il codice, l'errore
di esecuzione e la cronologia dei tentativi precedenti; interroga
DeepSeek per ottenere una versione corretta del codice.
"""

import json
import sys
import argparse
import requests
import re
from datetime import datetime

from prompts import BASE_GUIDELINES

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"


class ExploitCorrector:
    def __init__(self, api_key, model, code, error, cve, cve_data=None, history=None):
        self.api_key = api_key
        self.model = model
        self.code = code
        self.error = error
        self.cve = cve
        self.cve_data = cve_data or {}
        self.history = history or []

    def build_user_prompt(self) -> str:
        error_str = json.dumps(self.error, indent=2) if self.error else "Nessun errore fornito"

        cve_context = ""
        if self.cve_data:
            cve_context = f"""
Contesto CVE:
- Descrizione: {self.cve_data.get('description', 'N/A')}
- Tipo: {self.cve_data.get('vulnerability_type', 'unknown')}
- Prodotto: {self.cve_data.get('product', 'unknown')}
- Versione: {self.cve_data.get('version', 'unknown')}
- Payload suggerito: {self.cve_data.get('suggested_payload', 'N/A')}
"""

        history_context = ""
        if self.history:
            history_context = "\nCronologia tentativi precedenti:\n"
            for i, entry in enumerate(self.history, 1):
                err = entry.get("error", {}).get("error", "N/A")
                history_context += f"\nTentativo {i}:\n"
                history_context += f"- Errore: {str(err)[:200]}\n"
                if entry.get("corrected_code"):
                    snippet = entry["corrected_code"][:500]
                    history_context += f"- Codice proposto:\n```python\n{snippet}\n```\n"
                history_context += f"- Esito: {entry.get('outcome', 'fallito')}\n"
            history_context += "\nNota: evita di ripetere le correzioni già tentate."

        return f"""Correggi il seguente exploit per la CVE {self.cve}.
{cve_context}
{history_context}
Codice exploit fallito:
```python
{self.code}