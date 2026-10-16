#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servidor de la pagina de Jubilacio (port 3042).
Serveix ~/jubilacio, pero NOMES amb contrasenya: tota la pagina i els PDFs
de dins /pdfs son dades personals.
Sessio sense estat: cookie signada amb HMAC (sobreviu reinicis del servei).
"""
import http.server
import socketserver
import os
import hmac
import hashlib
import secrets
import time
import html
import urllib.parse

PORT = 3042
DIRECTORY = "/home/bernat/jubilacio"
SECRET_FILE = os.path.join(DIRECTORY, ".secret")

# ===== Contrasenya =====
PASS = "casament2026"
PASS_FILE = os.path.join(DIRECTORY, ".pass")
if os.path.isfile(PASS_FILE):
    with open(PASS_FILE, encoding="utf-8") as f:
        PASS = f.read().strip() or PASS

COOKIE = "jubilacio_sess"
DIES_SESSIO = 60          # la sessio dura 60 dies
MAX_INTENTS = 6           # intents fallits permesos
BLOQUEIG = 600            # segons de bloqueig despres de MAX_INTENTS

_intents = {}             # ip -> [comptador, bloquejat_fins]


def _secret():
    if not os.path.isfile(SECRET_FILE):
        with open(SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32))
        os.chmod(SECRET_FILE, 0o600)
    with open(SECRET_FILE, encoding="utf-8") as f:
        return f.read().strip().encode()


def _signa(valor):
    return hmac.new(_secret(), valor.encode(), hashlib.sha256).hexdigest()


def _crea_token():
    expira = int(time.time()) + DIES_SESSIO * 86400
    cos = f"{expira}.{secrets.token_hex(8)}"
    return f"{cos}.{_signa(cos)}"


def _token_valid(token):
    if not token or token.count(".") != 2:
        return False
    expira, soroll, signatura = token.split(".", 2)
    cos = f"{expira}.{soroll}"
    if not hmac.compare_digest(_signa(cos), signatura):
        return False
    try:
        return int(expira) > time.time()
    except ValueError:
        return False


PAGINA_LOGIN = """<!DOCTYPE html>
<html lang="ca"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acces privat · Jubilacio</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    background:linear-gradient(180deg,#0b1220 0%,#0f1a30 100%);
    color:#eaf0f9;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .box{background:#131f38;border:1px solid #24344f;border-radius:16px;
    padding:32px;max-width:400px;width:100%;box-shadow:0 10px 30px rgba(0,0,0,.35)}
  h1{font-size:1.3em;margin-bottom:6px;color:#38bdf8}
  p.sub{color:#8da2c0;font-size:.9em;margin-bottom:20px}
  label{display:block;font-size:.85em;color:#8da2c0;margin-bottom:6px}
  input{width:100%;padding:12px;border-radius:10px;border:1px solid #24344f;
    background:#0f1a30;color:#eaf0f9;font-size:1em}
  button{width:100%;margin-top:16px;padding:12px;border:none;border-radius:10px;
    background:#38bdf8;color:#08101f;font-size:1em;font-weight:600;cursor:pointer}
  button:hover{background:#5cc9fa}
  .err{margin-top:14px;padding:10px;border-radius:10px;background:rgba(248,113,113,.12);
    color:#f87171;font-size:.9em;__ERR_DISPLAY__}
  .peu{margin-top:18px;font-size:.78em;color:#5d7294;text-align:center}
</style></head><body>
<form class="box" method="POST" action="/__login">
  <h1>🔒 Acces privat</h1>
  <p class="sub">Aquesta pagina es personal. Cal contrasenya per entrar-hi.</p>
  <label for="p">Contrasenya</label>
  <input id="p" name="pass" type="password" autofocus autocomplete="current-password">
  <button type="submit">Entrar</button>
  <div class="err">Contrasenya incorrecta.</div>
  <div class="peu">Jubilacio · Bernat</div>
</form></body></html>"""


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def _ip(client):
    return client[0] if client else "?"


class JubilacioHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, *args):
        pass

    # ---------- helpers ----------
    def _cookies(self):
        cru = self.headers.get("Cookie", "")
        d = {}
        for part in cru.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                d[k] = v
        return d

    def _autenticat(self):
        return _token_valid(self._cookies().get(COOKIE, ""))

    def _bloquejat(self):
        ip = _ip(self.client_address)
        info = _intents.get(ip)
        if info and info[1] > time.time():
            return True
        return False

    def _suma_intent(self):
        ip = _ip(self.client_address)
        info = _intents.setdefault(ip, [0, 0])
        info[0] += 1
        if info[0] >= MAX_INTENTS:
            info[1] = time.time() + BLOQUEIG
            info[0] = 0
        return info[1] > time.time()

    def _login(self, amb_error=False):
        cos = PAGINA_LOGIN.replace("__ERR_DISPLAY__", "display:block" if amb_error else "display:none")
        data = cos.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---------- peticions ----------
    def do_POST(self):
        if urllib.parse.urlparse(self.path).path == "/__login":
            if self._bloquejat():
                self._login(amb_error=True)
                return
            n = int(self.headers.get("Content-Length", 0) or 0)
            cos = self.rfile.read(n).decode("utf-8", "replace")
            camps = urllib.parse.parse_qs(cos)
            donada = camps.get("pass", [""])[0]
            if hmac.compare_digest(donada, PASS):
                _intents.pop(_ip(self.client_address), None)
                self.send_response(303)
                self.send_header("Set-Cookie",
                                 f"{COOKIE}={_crea_token()}; Path=/; Max-Age={DIES_SESSIO*86400}; "
                                 f"HttpOnly; SameSite=Lax")
                self.send_header("Location", "/index.html")
                self.end_headers()
                return
            self._suma_intent()
            time.sleep(0.6)          # frena els intents a la força bruta
            self._login(amb_error=True)
            return
        self.send_error(405)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        cami = urllib.parse.unquote(parsed.path)

        # sortir
        if cami == "/__logout":
            self.send_response(303)
            self.send_header("Set-Cookie", f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            self.send_header("Location", "/__login")
            self.end_headers()
            return
        if cami == "/__login":
            if self._autenticat():
                self.send_response(303)
                self.send_header("Location", "/index.html")
                self.end_headers()
                return
            self._login()
            return

        # TOT la resta requereix sessio (index, opcions, PDFs de /pdfs...)
        if not self._autenticat():
            self._login()
            return

        if cami in ("/", ""):
            self.send_response(303)
            self.send_header("Location", "/index.html")
            self.end_headers()
            return

        self.path = urllib.parse.quote(cami, safe="/%")
        return super().do_GET()

    def end_headers(self):
        # dades personals: que no quedin a la memoria cau de cap navegador
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
        self.send_header("Pragma", "no-cache")
        super().end_headers()


print(f"\u2713 Jubilacio Server (amb contrasenya) escoltant a 0.0.0.0:{PORT}", flush=True)
with ReusableTCPServer(("0.0.0.0", PORT), JubilacioHandler) as httpd:
    httpd.serve_forever()
