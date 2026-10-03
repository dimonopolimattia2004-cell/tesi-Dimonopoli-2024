import csv
import os

cartella = "reports"
righe = []
ok = 0
ko = 0
tot = 0

for nome in os.listdir(cartella):
    if not nome.startswith("report_") or not nome.endswith(".html"):
        continue
    tot += 1
    cve = nome.replace("report_", "").replace(".html", "")

    f = open(os.path.join(cartella, nome), "r", encoding="utf-8", errors="ignore")
    testo = f.read()
    f.close()

    if "EXPLOIT FUNZIONANTE" in testo:
        righe.append([cve, "Funzionante"])
        ok += 1
    else:
        righe.append([cve, "Fallito"])
        ko += 1

righe.sort()

out = open("risultati_exploit.csv", "w", newline="", encoding="utf-8")
w = csv.writer(out)
w.writerow(["CVE ID", "Esito"])
for r in righe:
    w.writerow(r)

w.writerow([])
w.writerow(["Totale", tot])
w.writerow(["Funzionanti", ok])
w.writerow(["Falliti", ko])
out.close()

print("Totale file analizzati:", tot)
print("Exploit funzionanti:", ok)
print("Exploit falliti:", ko)