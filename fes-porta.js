#!/usr/bin/env node
/**
 * fes-porta.js — xifra la pàgina del viatge amb la contrasenya de jubilació.
 *
 * Llegeix la contrasenya del servidor de jubilació (que viu a la RPi), xifra la pàgina amb
 * PBKDF2 + AES-256-GCM (el que fa servir el navegador amb crypto.subtle) i deixa un index.html
 * que només mostra la pàgina si s'encerta la contrasenya. Així GitHub no cal que tingui servidor.
 *
 * La contrasenya no s'escriu mai enlloc.
 *
 *   /usr/local/bin/node fes-porta.js <pagina-neta.html> <sortida.html> <fitxer-servidor-jubilacio>
 */
const fs = require("fs");
const crypto = require("crypto");

const [, , entrada, sortida, servidorJubilacio] = process.argv;
if (!entrada || !sortida || !servidorJubilacio) {
  console.error("ús: node fes-porta.js <pagina.html> <sortida.html> <servidor-jubilacio.py>");
  process.exit(1);
}

// 1) la contrasenya, del servidor de jubilació (no surt mai d'aquí)
const src = fs.readFileSync(servidorJubilacio, "utf8");
const m = src.match(/^PASS\s*=\s*["']([^"']+)["']/m);
if (!m) { console.error("✗ no trobo la contrasenya al servidor de jubilació"); process.exit(1); }
const contrasenya = m[1];

// 2) xifrem la pàgina
const neta = fs.readFileSync(entrada, "utf8");
const sal = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const iteracions = 310000;
const clau = crypto.pbkdf2Sync(contrasenya, sal, iteracions, 32, "sha256");
const xif = crypto.createCipheriv("aes-256-gcm", clau, iv);
const dades = Buffer.concat([xif.update(neta, "utf8"), xif.final()]);
const etiqueta = xif.getAuthTag();

const paquet = {
  v: 1, iteracions, sal: sal.toString("base64"), iv: iv.toString("base64"),
  dades: dades.toString("base64"), etiqueta: etiqueta.toString("base64"),
};

// 3) la pàgina-porta (tot en català i amb l'estil de la pàgina)
const porta = `<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0b1220">
<title>Viatge Andalusia · 19–26 octubre 2026</title>
<style>
  :root{--bg:#0b1220;--soft:#0f1a30;--panel:#182545;--border:#24344f;--txt:#eaf0f9;
    --muted:#8da2c0;--accent:#f5b942;--rad:14px}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
    background:linear-gradient(180deg,var(--bg),var(--soft));color:var(--txt);min-height:100vh;
    display:flex;align-items:center;justify-content:center;padding:20px;line-height:1.5}
  .caixa{background:var(--panel);border:1px solid var(--border);border-radius:var(--rad);
    padding:28px 24px;max-width:380px;width:100%;text-align:center}
  h1{font-size:1.2rem;margin-bottom:6px}
  p{color:var(--muted);font-size:.9rem;margin-bottom:18px}
  input{width:100%;background:var(--soft);border:1px solid var(--border);color:var(--txt);
    border-radius:10px;padding:12px;font:inherit;font-size:1rem;text-align:center;margin-bottom:12px}
  button{width:100%;background:linear-gradient(90deg,var(--accent),#e07a3f);color:#151515;border:0;
    border-radius:10px;padding:12px;font-weight:700;font-size:1rem;cursor:pointer}
  .err{color:#ff8a80;font-size:.85rem;margin-top:12px;min-height:1.2em}
  .peu{color:#5d7294;font-size:.75rem;margin-top:18px}
</style>
</head>
<body>
<div class="caixa">
  <h1>🌿 Viatge Andalusia</h1>
  <p>19–26 d'octubre de 2026 · pàgina personal</p>
  <input type="password" id="p" placeholder="Contrasenya" autocomplete="current-password"
         autofocus enterkeyhint="go">
  <button id="b">Entrar</button>
  <div class="err" id="e"></div>
  <div class="peu">Es recorda en aquest aparell. Si no, la tornes a posar.</div>
</div>
<script>
const PAQUET = ${JSON.stringify(paquet)};
const clauDesada = "viatge-clau";

function de64(s){ const b = atob(s); const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }

async function clauDe(contrasenya){
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(contrasenya),
                                             "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt: de64(PAQUET.sal),
                                  iterations: PAQUET.iteracions, hash:"SHA-256"},
                                 base, {name:"AES-GCM", length:256}, false, ["decrypt"]);
}

async function obre(contrasenya){
  const clau = await clauDe(contrasenya);
  const pla = await crypto.subtle.decrypt({name:"AES-GCM", iv: de64(PAQUET.iv),
                                            tagLength:128},
                                           clau, (() => { const d = de64(PAQUET.dades);
                                             const t = de64(PAQUET.etiqueta);
                                             const j = new Uint8Array(d.length + t.length);
                                             j.set(d); j.set(t, d.length); return j; })());
  return new TextDecoder().decode(pla);
}

async function prova(contrasenya, desar){
  try {
    const html = await obre(contrasenya);
    if (desar) { try { localStorage.setItem(clauDesada, contrasenya); } catch(e){} }
    document.open(); document.write(html); document.close();
  } catch (e) {
    document.getElementById("e").textContent = "Contrasenya incorrecta.";
    try { localStorage.removeItem(clauDesada); } catch(e){}
  }
}

document.getElementById("b").onclick = () =>
  prova(document.getElementById("p").value, true);
document.getElementById("p").addEventListener("keydown", ev => {
  if (ev.key === "Enter") prova(document.getElementById("p").value, true);
});
try {
  const desada = localStorage.getItem(clauDesada);
  if (desada) prova(desada, false);
} catch(e){}
</script>
</body>
</html>
`;
fs.writeFileSync(sortida, porta);
console.log(`   xifrat ok · ${neta.length} → ${porta.length} bytes · iteracions ${iteracions}`);
console.log(`   contrasenya: ${contrasenya.length} caràcters (no es mostra)`);
