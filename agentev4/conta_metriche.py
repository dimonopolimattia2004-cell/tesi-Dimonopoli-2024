import csv
import json
import os
import time
import urllib.request

API_KEY = "sk-13efa0e753d341e79e8f70a27de94331"
MODEL = "deepseek-flash"
API_URL = "https://api.deepseek.com/chat/completions"

FORCE = True

CAT = [
    "RCE", "Path Traversal", "Authentication Bypass", "Deserialization",
    "SQL Injection", "Information Disclosure", "Command Injection", "SSRF",
    "XXE", "Command Injection / RCE", "Arbitrary Code Execution",
    "Arbitrary File Upload", "Authentication Bypass / User Enumeration",
    "Authorization / Restriction Bypass", "Cross-Site Scripting (XSS)",
    "Insecure RMI / RCE", "Path Traversal / RCE", "Privilege Escalation",
    "RCE / Command Injection", "Sandbox Escape / RCE",
    "Unsafe Deserialization / RCE", "Buffer Overflow", "Denial of Service",
    "Configuration Injection / RCE", "CSRF", "Deserialization / RCE",
    "Improper Access Control / RCE", "Local File Inclusion",
    "Missing Encryption of Sensitive Data",
    "Path Traversal / Arbitrary File Read and Write",
    "Prototype Pollution", "Unauthenticated Access",
]

KW = {
    "rce": "RCE",
    "remote code execution": "RCE",
    "command injection": "Command Injection",
    "code execution": "Arbitrary Code Execution",
    "sql injection": "SQL Injection",
    "sqli": "SQL Injection",
    "sql": "SQL Injection",
    "deserial": "Deserialization",
    "pickle": "Deserialization",
    "path traversal": "Path Traversal",
    "directory traversal": "Path Traversal",
    "file inclusion": "Local File Inclusion",
    "lfi": "Local File Inclusion",
    "rfi": "Local File Inclusion",
    "zip slip": "Path Traversal",
    "zipslip": "Path Traversal",
    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",
    "information disclosure": "Information Disclosure",
    "info disclosure": "Information Disclosure",
    "sensitive information": "Information Disclosure",
    "auth bypass": "Authentication Bypass",
    "authentication bypass": "Authentication Bypass",
    "privilege escalation": "Privilege Escalation",
    "unauthorized": "Unauthenticated Access",
    "denial of service": "Denial of Service",
    "dos": "Denial of Service",
    "xxe": "XXE",
    "xml external entity": "XXE",
    "xss": "Cross-Site Scripting (XSS)",
    "cross-site scripting": "Cross-Site Scripting (XSS)",
    "csrf": "CSRF",
    "cross-site request forgery": "CSRF",
    "buffer overflow": "Buffer Overflow",
    "prototype pollution": "Prototype Pollution",
    "arbitrary file upload": "Arbitrary File Upload",
    "file upload": "Arbitrary File Upload",
    "sandbox escape": "Sandbox Escape / RCE",
    "rmi": "Insecure RMI / RCE",
    "configuration injection": "Configuration Injection / RCE",
}


def chiama(prompt):
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "Sei un assistente esperto in sicurezza informatica."},
            {"role": "user", "content": prompt},
        ],
        "reasoning_effort": "low",
    }).encode()

    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + API_KEY,
        },
    )
    r = urllib.request.urlopen(req, timeout=60)
    d = json.loads(r.read().decode())
    return d["choices"][0]["message"]["content"]


def match(risp):
    r = risp.strip().replace('"', "").replace("`", "").replace("*", "")

    for c in CAT:
        if c.lower() == r.lower():
            return c

    for c in sorted(CAT, key=len, reverse=True):
        if c.lower() in r.lower():
            return c

    rl = r.lower()
    for k, c in KW.items():
        if k in rl:
            return c

    return "Sconosciuta"


def classifica(cve, desc):
    p = "Analizza la vulnerabilità:\nID: " + cve + "\nDescrizione: " + desc
    p += "\n\nScegli UNA sola categoria da questa lista:\n"
    p += json.dumps(CAT, indent=2)
    p += '\n\nSe non hai informazioni sufficienti rispondi "Sconosciuta".'
    p += "\nRispondi solo con il nome della categoria."

    try:
        return match(chiama(p))
    except Exception as e:
        print(cve, "errore:", e)
        return "Sconosciuta"


def perc(s, t):
    if t == 0:
        return 0.0
    return round(s / t * 100, 2)


csv_file = "risultati_exploit.csv"
cve_dir = "cve_data"

if not os.path.exists(csv_file):
    print("manca risultati_exploit.csv, lancia prima lo script dei report")
    raise SystemExit

rows = []
f = open(csv_file, "r", encoding="utf-8")
rd = csv.reader(f)
next(rd)
for row in rd:
    if not row:
        continue
    if row[0].startswith("---") or "Totale" in row[0]:
        continue
    ok = ("✅" in row[1]) or ("Funzionante" in row[1])
    rows.append((row[0], ok))
f.close()

print("Classifico", len(rows), "CVE...")

sev = {}
tip = {}
sconosciute_ok = []
api = 0

for i, (cve, ok) in enumerate(rows):
    jp = os.path.join(cve_dir, cve + ".json")
    s = "Sconosciuta"
    t = "Sconosciuta"

    if os.path.exists(jp):
        try:
            f = open(jp, "r", encoding="utf-8")
            d = json.load(f)
            f.close()

            s = d.get("severity") or "Sconosciuta"
            t = str(d.get("vulnerability_type", "")).strip()
            desc = d.get("description", "")

            if FORCE or t not in CAT:
                print("  [" + str(i + 1) + "/" + str(len(rows)) + "]", cve)
                t = classifica(cve, desc)
                api += 1
                d["vulnerability_type"] = t
                f = open(jp, "w", encoding="utf-8")
                json.dump(d, f, indent=4, ensure_ascii=False)
                f.close()
                time.sleep(0.5)
        except Exception as e:
            print(cve, "errore:", e)

    s = s.capitalize()
    if t not in CAT:
        t = "Sconosciuta"

    if s not in sev:
        sev[s] = [0, 0]
    if t not in tip:
        tip[t] = [0, 0]

    sev[s][0] += 1
    tip[t][0] += 1

    if ok:
        sev[s][1] += 1
        tip[t][1] += 1
        if t == "Sconosciuta":
            sconosciute_ok.append(cve)

print()
print("Chiamate API:", api, "su", len(rows))

print()
print("TASSO DI SUCCESSO PER SEVERITA'")
for k in sorted(sev.keys()):
    v = sev[k]
    print(k.ljust(18) + ":", str(perc(v[1], v[0])).rjust(6) + "%", "(" + str(v[1]) + "/" + str(v[0]) + ")")

print()
print("TASSO DI SUCCESSO PER TIPOLOGIA")
ordinati = sorted(tip.items(), key=lambda x: x[1][0], reverse=True)
for k, v in ordinati:
    print(k.ljust(45)[:45] + ":", str(perc(v[1], v[0])).rjust(6) + "%", "(" + str(v[1]) + "/" + str(v[0]) + ")")

print()
print("FUNZIONANTI SENZA CATEGORIA")
if sconosciute_ok:
    for c in sorted(sconosciute_ok):
        print(" -", c)
else:
    print(" nessuna")