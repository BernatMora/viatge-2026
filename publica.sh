#!/bin/bash
# Actualitza la pàgina pública del viatge a partir de la de la RPi:
# baixa → treu els localitzadors → xifra amb la contrasenya de jubilació → publica a GitHub.
set -e
cd "$(dirname "$0")"
scp -q hortosona:~/viatge-andalusia/index.html ./original.html
scp -q hortosona:~/jubilacio/jubilacio-server.py ./jubilacio-server.py
/usr/bin/python3 - <<'PY'
import re, io
t = io.open("original.html", encoding="utf-8").read()
p1 = re.compile(r'(<span class="k">\s*(?:Reserva[^<]*|Localitzador[^<]*)\s*</span>\s*<span class="v">)([^<]+)(</span>)', re.I)
t, n1 = p1.subn(lambda m: m.group(1) + "●●●●●●" + m.group(3), t)
p2 = re.compile(r'(localitzador\s*(?:<b>)?|codi\s*<b>)([A-Z0-9]{5,}(?:-\d{4,})?)(</b>)?', re.I)
t, n2 = p2.subn(lambda m: m.group(1) + "●●●●●●" + (m.group(3) or ""), t)
if "noindex" not in t:
    t = t.replace('<meta name="viewport"', '<meta name="robots" content="noindex, nofollow">\n<meta name="viewport"', 1)
io.open("neta.html", "w", encoding="utf-8").write(t)
print(f"   netejat: {n1} camps i {n2} mencions tapades")
PY
/usr/local/bin/node fes-porta.js neta.html index.html ./jubilacio-server.py
git add -A && git commit -q -m "Viatge: hotel regalat (Punta Bermeja, 24-26 oct)" 2>/dev/null || true
git push -q origin main
echo "   publicat ✓"
