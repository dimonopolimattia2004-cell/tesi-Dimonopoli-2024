#!/usr/bin/env python3
"""
Genera un report HTML riassuntivo dell'analisi di una CVE.
Il report include i metadati della vulnerabilità, l'esito del test
e il dettaglio dell'ultima esecuzione dell'exploit.
"""

import json
import sys
import argparse
import html
from pathlib import Path
from datetime import datetime


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<title>Report {cve}</title>
<style>
    body {{ font-family: -apple-system, Arial, sans-serif; background: #0f1115; color: #e6e6e6; margin: 0; padding: 2rem; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.2rem; }}
    .status {{ display: inline-block; padding: 0.3rem 0.8rem; border-radius: 6px; font-weight: bold; }}
    .status.success {{ background: #1e4620; color: #7CFC7C; }}
    .status.fail {{ background: #4a1e1e; color: #ff8080; }}
    .card {{ background: #1a1d24; border: 1px solid #2a2e37; border-radius: 8px; padding: 1.2rem 1.5rem; margin: 1rem 0; }}
    .label {{ color: #9aa0aa; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }}
    pre {{ background: #0b0d11; border: 1px solid #2a2e37; border-radius: 6px; padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 0.4rem 0.6rem; vertical-align: top; border-bottom: 1px solid #2a2e37; }}
    td.k {{ color: #9aa0aa; width: 180px; }}
    a {{ color: #7ab7ff; }}
    footer {{ margin-top: 2rem; color: #6b7280; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>Report analisi &mdash; {cve}</h1>
    <p><span class="status {status_class}">{status_label}</span> &nbsp; generato il {generated_at}</p>

    <div class="card">
        <table>
            <tr><td class="k">Descrizione</td><td>{description}</td></tr>
            <tr><td class="k">Tipo vulnerabilità</td><td>{vulnerability_type}</td></tr>
            <tr><td class="k">Prodotto</td><td>{product}</td></tr>
            <tr><td class="k">Versione affetta</td><td>{version}</td></tr>
            <tr><td class="k">Severità</td><td>{severity} (CVSS {cvss_score})</td></tr>
            <tr><td class="k">Iterazioni eseguite</td><td>{iterations}</td></tr>
            <tr><td class="k">Riferimenti</td><td>{references}</td></tr>
        </table>
    </div>

    <div class="card">
        <div class="label">Risultato ultima esecuzione</div>
        <pre>{result_json}</pre>
    </div>

    <footer>Report generato automaticamente &mdash; uso didattico in ambiente isolato.</footer>
</div>
</body>
</html>
"""


def esc(value) -> str:
    if value is None:
        return "N/A"
    return html.escape(str(value))


def build_references_html(refs) -> str:
    if not refs:
        return "N/A"
    items = []
    for r in refs[:10]:
        safe = esc(r)
        items.append(f'<a href="{safe}" target="_blank" rel="noopener noreferrer">{safe}</a>')
    return "<br>".join(items)


def load_result(result_path: str) -> dict:
    path = Path(result_path)
    if not path.exists():
        return {"info": "Nessun file di risultato disponibile"}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"Impossibile leggere il risultato: {e}"}


def build_report(cve: str, success: bool, cve_data: dict, iterations: int, result_path: str) -> str:
    result_data = load_result(result_path)

    status_class = "success" if success else "fail"
    status_label = "EXPLOIT FUNZIONANTE" if success else "NON RIUSCITO"

    return HTML_TEMPLATE.format(
        cve=esc(cve),
        status_class=status_class,
        status_label=status_label,
        generated_at=esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        description=esc(cve_data.get("description", "N/A")),
        vulnerability_type=esc(cve_data.get("vulnerability_type", "unknown")),
        product=esc(cve_data.get("product", "N/A")),
        version=esc(cve_data.get("version", "N/A")),
        severity=esc(cve_data.get("severity", "N/A")),
        cvss_score=esc(cve_data.get("cvss_score", "N/A")),
        iterations=esc(iterations),
        references=build_references_html(cve_data.get("references", [])),
        result_json=esc(json.dumps(result_data, indent=2, ensure_ascii=False)),
    )


def main():
    parser = argparse.ArgumentParser(description="Genera report HTML finale per una CVE analizzata.")
    parser.add_argument("--cve", required=True, help="ID della CVE")
    parser.add_argument("--success", required=True, help="Esito finale (True/False)")
    parser.add_argument("--data", required=True, help="Dati CVE in formato JSON")
    parser.add_argument("--iterations", required=True, help="Numero di iterazioni eseguite")
    parser.add_argument("--result", required=True, help="Percorso al file JSON di risultato")
    args = parser.parse_args()

    try:
        cve_data = json.loads(args.data)
    except json.JSONDecodeError:
        print("Dati CVE non validi", file=sys.stderr)
        sys.exit(1)

    success = args.success.strip().lower() == "true"

    report_html = build_report(
        cve=args.cve,
        success=success,
        cve_data=cve_data,
        iterations=args.iterations,
        result_path=args.result,
    )

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out_path = reports_dir / f"report_{args.cve}.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    print(json.dumps({"report_path": str(out_path)}))


if __name__ == "__main__":
    main()