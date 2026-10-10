/**
 * Vérificateur de numéros WhatsApp
 * - Dit si un numéro est toujours disponible sur WhatsApp, ou introuvable / plus disponible
 * - Garde l'historique (date/heure de la dernière fois actif, date/heure où il a disparu)
 * - Peut surveiller des numéros automatiquement
 * Utilise un numéro WhatsApp "vérificateur" lié par code (Baileys).
 */
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const env = process.env;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = env.DATA_DIR || path.join(__dirname, 'data');
const AUTH_DIR = path.join(DATA_DIR, 'auth');
const DB_FILE = path.join(DATA_DIR, 'history.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

const DEMO = env.DEMO_MODE === '1';
const PASSWORD = env.ADMIN_PASSWORD || '';
const DAILY_LIMIT = Number(env.DAILY_LIMIT || 300); // vérifications max par jour (protège ton numéro)
const WATCH_EVERY_MIN = Number(env.CHECK_INTERVAL_MIN || 30);
const MAX_PER_REQUEST = 20;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ======================= Historique (fichier JSON) ======================= */
let db = { numbers: {}, daily: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { /* premier démarrage */ }
db.numbers = db.numbers || {};
db.daily = db.daily || {};
function save() {
  try {
    fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db));
    fs.renameSync(DB_FILE + '.tmp', DB_FILE);
  } catch (e) { console.error('Sauvegarde impossible', e.message); }
}

const fmt = (ms) =>
  ms ? new Date(ms).toLocaleString('fr-FR', { timeZone: 'Africa/Libreville', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' (heure du Gabon)' : '—';

function normalizePhone(input) {
  let s = String(input || '').replace(/[\s().-]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  return /^\+[1-9]\d{7,14}$/.test(s) ? s : null;
}

function addEvent(rec, type, t) {
  rec.events.push({ t, type });
  if (rec.events.length > 30) rec.events.shift();
}

/** Enregistre le résultat d'une vérification et détecte les changements. */
function record(number, exists, now = Date.now()) {
  let rec = db.numbers[number];
  if (!rec) {
    rec = db.numbers[number] = { number, firstChecked: now, lastChecked: now, status: null, lastActiveAt: null, unavailableSince: null, reactivatedAt: null, checks: 0, watch: false, events: [] };
  }
  const prev = rec.status;
  rec.checks++;
  rec.lastChecked = now;
  if (exists) {
    if (prev === 'inactive' && rec.lastActiveAt) { rec.reactivatedAt = now; addEvent(rec, 'back', now); }
    else if (prev === null) addEvent(rec, 'first_active', now);
    rec.status = 'active';
    rec.lastActiveAt = now;
    rec.unavailableSince = null;
  } else {
    if (prev === 'active') { rec.unavailableSince = now; rec.reactivatedAt = null; addEvent(rec, 'gone', now); }
    else if (prev === null) addEvent(rec, 'first_missing', now);
    rec.status = 'inactive';
  }
  save();
  return rec;
}

const EVENT_LABEL = {
  first_active: 'Premier contrôle : numéro actif',
  first_missing: 'Premier contrôle : numéro introuvable',
  gone: 'Numéro devenu indisponible (banni, supprimé ou désactivé)',
  back: 'Numéro de nouveau disponible',
};

function view(rec) {
  let state, headline;
  const lines = [];
  if (rec.status === 'active') {
    state = 'active';
    headline = '✅ Numéro toujours disponible sur WhatsApp';
    lines.push('Vérifié le : ' + fmt(rec.lastChecked));
    if (rec.reactivatedAt) lines.push('Redevenu disponible le : ' + fmt(rec.reactivatedAt));
  } else if (rec.lastActiveAt) {
    state = 'gone';
    headline = '🚫 Numéro plus disponible sur WhatsApp (banni, supprimé ou désactivé)';
    lines.push('Dernière fois vu actif : ' + fmt(rec.lastActiveAt));
    lines.push('Détecté indisponible le : ' + fmt(rec.unavailableSince));
    lines.push('Vérifié le : ' + fmt(rec.lastChecked));
    lines.push("WhatsApp ne dit pas la cause (banni, désinstallé ou supprimé) ni l'heure exacte : la date affichée est celle où ce site l'a constaté.");
  } else {
    state = 'notfound';
    headline = '❓ Numéro introuvable sur WhatsApp';
    lines.push("Jamais vu actif depuis le 1er contrôle du " + fmt(rec.firstChecked) + ". Il n'est pas inscrit, ou il était déjà banni.");
    lines.push('Vérifié le : ' + fmt(rec.lastChecked));
  }
  return {
    number: rec.number, state, headline, lines, watch: !!rec.watch, checks: rec.checks,
    events: rec.events.slice(-6).reverse().map((e) => fmt(e.t) + ' — ' + EVENT_LABEL[e.type]),
  };
}

/* ======================= Connexion WhatsApp (Baileys) ======================= */
const wa = { status: 'disconnected', qr: null, qrReady: false, me: null, pairing: null };
let sock = null;
let starting = false;

async function startWA() {
  if (starting) return;
  starting = true;
  try {
    if (DEMO) {
      // MODE DÉMO : pas de vrai WhatsApp. Fin en 0 = "introuvable". Fin en 9 = actif au 1er contrôle puis "banni".
      wa.status = 'connected';
      wa.me = 'DEMO';
      const seen9 = new Set();
      sock = {
        onWhatsApp: async (jid) => {
          const n = jid.split('@')[0];
          let exists = !n.endsWith('0');
          if (n.endsWith('9')) { exists = !seen9.has(n); seen9.add(n); }
          return [{ jid, exists }];
        },
      };
      return;
    }
    const B = await import('@whiskeysockets/baileys');
    const get = (k) => B[k] || (B.default && B.default[k]);
    const make = typeof B.default === 'function' ? B.default : (B.makeWASocket || (B.default && B.default.default));
    const pino = (await import('pino')).default;
    const QRCode = (await import('qrcode')).default;

    const { state, saveCreds } = await get('useMultiFileAuthState')(AUTH_DIR);
    let version;
    try { version = (await get('fetchLatestBaileysVersion')()).version; } catch (e) { /* version par défaut */ }

    wa.qrReady = false;
    wa.qr = null;
    wa.status = 'connecting';
    const s = make({
      version,
      auth: state,
      logger: pino({ level: 'silent' }),
      printQRInTerminal: false,
      browser: ['Ubuntu', 'Chrome', '22.04.4'],
      syncFullHistory: false,
      markOnlineOnConnect: false,
    });
    sock = s;
    s.ev.on('creds.update', saveCreds);
    s.ev.on('connection.update', async (u) => {
      const { connection, lastDisconnect, qr } = u;
      if (qr) {
        wa.qrReady = true;
        try { wa.qr = await QRCode.toDataURL(qr); } catch (e) { /* ignore */ }
      }
      if (connection === 'connecting') wa.status = 'connecting';
      if (connection === 'open') {
        wa.status = 'connected';
        wa.qr = null;
        wa.pairing = null;
        wa.me = String((s.user && s.user.id) || '').split(':')[0].split('@')[0];
        console.log('WhatsApp connecté :', wa.me);
      }
      if (connection === 'close') {
        wa.status = 'disconnected';
        const code = lastDisconnect && lastDisconnect.error && lastDisconnect.error.output && lastDisconnect.error.output.statusCode;
        const DR = get('DisconnectReason') || {};
        if (code === DR.loggedOut) fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        starting = false;
        setTimeout(startWA, 3000);
      }
    });
  } catch (e) {
    console.error('Démarrage WhatsApp impossible :', e.message);
    wa.status = 'error';
    setTimeout(() => { starting = false; startWA(); }, 15000);
    return;
  } finally {
    if (DEMO || wa.status === 'connecting' || wa.status === 'connected') { /* garde starting=true tant que le socket vit */ }
  }
}

async function requestPairing(phone) {
  if (DEMO) return 'DEMO-1234';
  if (wa.status === 'connected') throw new Error('Déjà connecté à WhatsApp.');
  for (let i = 0; i < 40 && !wa.qrReady; i++) await sleep(500);
  if (!wa.qrReady || !sock) throw new Error('Connexion à WhatsApp pas encore prête, réessaie dans quelques secondes.');
  const code = await sock.requestPairingCode(phone.replace('+', ''));
  wa.pairing = code;
  return code;
}

async function lookup(number) {
  if (wa.status !== 'connected' || !sock) throw new Error('WhatsApp du vérificateur non connecté.');
  const r = await sock.onWhatsApp(number.replace('+', '') + '@s.whatsapp.net');
  return !!(r && r[0] && r[0].exists);
}

/* ======================= Limites quotidiennes ======================= */
function useQuota(n) {
  const day = new Date().toISOString().slice(0, 10);
  db.daily = { [day]: db.daily[day] || 0 };
  if (db.daily[day] + n > DAILY_LIMIT) return false;
  db.daily[day] += n;
  save();
  return true;
}
const usedToday = () => db.daily[new Date().toISOString().slice(0, 10)] || 0;

/* ======================= Surveillance automatique ======================= */
let watching = false;
async function watchLoop() {
  if (watching || wa.status !== 'connected') return;
  watching = true;
  try {
    for (const rec of Object.values(db.numbers)) {
      if (!rec.watch) continue;
      if (!useQuota(1)) break;
      try { record(rec.number, await lookup(rec.number)); } catch (e) { console.error('Surveillance :', e.message); break; }
      await sleep(DEMO ? 0 : 1500 + Math.random() * 2000);
    }
  } finally { watching = false; }
}
setInterval(watchLoop, WATCH_EVERY_MIN * 60 * 1000);

/* ======================= Serveur web ======================= */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const failures = new Map();
const ipOf = (req) => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';

app.get('/healthz', (req, res) => res.type('text').send('ok'));

function auth(req, res, next) {
  if (!PASSWORD) return res.status(503).type('text').send('Définis la variable ADMIN_PASSWORD pour activer le site.');
  const ip = ipOf(req);
  const f = failures.get(ip);
  if (f && f.n >= 10 && Date.now() - f.t < 10 * 60 * 1000) return res.status(429).type('text').send('Trop de tentatives. Réessaie dans 10 minutes.');
  const [type, val] = String(req.headers.authorization || '').split(' ');
  if (type === 'Basic' && val) {
    const pass = Buffer.from(val, 'base64').toString().split(':').slice(1).join(':');
    if (crypto.timingSafeEqual(sha(pass), sha(PASSWORD))) { failures.delete(ip); return next(); }
    failures.set(ip, { n: ((f && Date.now() - f.t < 10 * 60 * 1000 ? f.n : 0) + 1), t: Date.now() });
  }
  res.set('WWW-Authenticate', 'Basic realm="Verification"').status(401).type('text').send('Authentification requise');
}
app.use(auth);

// Protection contre les requêtes venant d'autres sites
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'verif') return res.status(403).json({ ok: false, message: 'Requête refusée.' });
  next();
});

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  res.status(500).json({ ok: false, message: e.message || 'Erreur serveur.' });
});

app.get('/', (req, res) => res.set('Content-Type', 'text/html; charset=utf-8').send(PAGE));

app.get('/api/status', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ demo: DEMO, status: wa.status, me: wa.me, qr: wa.qr, pairing: wa.pairing, usedToday: usedToday(), dailyLimit: DAILY_LIMIT, watchEveryMin: WATCH_EVERY_MIN });
});

app.post('/api/pair', wrap(async (req, res) => {
  const phone = normalizePhone(req.body && req.body.phone);
  if (!phone) return res.status(400).json({ ok: false, message: 'Numéro invalide. Écris-le avec l’indicatif, ex : +241 07 12 34 56.' });
  const code = await requestPairing(phone);
  res.json({ ok: true, code });
}));

app.post('/api/check', wrap(async (req, res) => {
  const raw = Array.isArray(req.body && req.body.numbers) ? req.body.numbers : [];
  const watch = !!(req.body && req.body.watch);
  const numbers = [...new Set(raw.map(normalizePhone).filter(Boolean))];
  if (!numbers.length) return res.status(400).json({ ok: false, message: 'Aucun numéro valide. Utilise le format international, ex : +241 07 12 34 56.' });
  if (numbers.length > MAX_PER_REQUEST) return res.status(400).json({ ok: false, message: 'Maximum ' + MAX_PER_REQUEST + ' numéros à la fois.' });
  if (wa.status !== 'connected') return res.status(409).json({ ok: false, message: "Le WhatsApp du vérificateur n'est pas connecté. Lie-le d'abord (étape 1)." });
  if (!useQuota(numbers.length)) return res.status(429).json({ ok: false, message: 'Limite de ' + DAILY_LIMIT + ' vérifications par jour atteinte (protège ton numéro). Réessaie demain.' });

  const results = [];
  for (let i = 0; i < numbers.length; i++) {
    const rec = record(numbers[i], await lookup(numbers[i]));
    if (watch) { rec.watch = true; save(); }
    results.push(view(rec));
    if (i < numbers.length - 1) await sleep(DEMO ? 0 : 1200 + Math.random() * 1800);
  }
  res.json({ ok: true, results });
}));

app.get('/api/history', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ items: Object.values(db.numbers).sort((a, b) => b.lastChecked - a.lastChecked).map(view) });
});

app.post('/api/watch', (req, res) => {
  const n = normalizePhone(req.body && req.body.number);
  const rec = n && db.numbers[n];
  if (!rec) return res.status(404).json({ ok: false, message: 'Numéro inconnu.' });
  rec.watch = !!req.body.on;
  save();
  res.json({ ok: true, watch: rec.watch });
});

app.delete('/api/number', (req, res) => {
  const n = normalizePhone(req.body && req.body.number);
  if (n && db.numbers[n]) { delete db.numbers[n]; save(); }
  res.json({ ok: true });
});

/* ======================= Page web ======================= */
const PAGE = `<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vérificateur de numéros WhatsApp</title>
<style>
:root{--bg:#0b141a;--card:#111b21;--line:#233138;--text:#e9edef;--muted:#8696a0;--g:#25d366;--r:#ff5c5c;--o:#ffb020}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;line-height:1.5}
.wrap{max-width:760px;margin:0 auto;padding:16px 16px 60px}h1{font-size:24px;margin:8px 0 4px}h2{font-size:17px;margin:0 0 10px}
.muted{color:var(--muted);font-size:14px}p{margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin:14px 0}
input,textarea{width:100%;background:#0b141a;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px;font:inherit;margin-bottom:10px}
input:focus,textarea:focus{outline:2px solid var(--g)}
.btn{background:var(--g);color:#06220f;border:0;border-radius:12px;padding:12px 16px;font:inherit;font-weight:700;cursor:pointer;width:100%}
.btn.small{width:auto;padding:6px 12px;font-size:13px}.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line);font-weight:500}
.btn:disabled{opacity:.5;cursor:not-allowed}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:13px;font-weight:600}
.b-ok{background:rgba(37,211,102,.15);color:var(--g)}.b-no{background:rgba(255,92,92,.15);color:var(--r)}.b-wait{background:rgba(255,176,32,.15);color:var(--o)}
.res{border-left:4px solid var(--line);padding:10px 12px;margin:10px 0;background:#0b141a;border-radius:10px}
.res.active{border-color:var(--g)}.res.gone{border-color:var(--r)}.res.notfound{border-color:var(--o)}
.res h3{margin:0 0 4px;font-size:15px}.res .num{font-family:ui-monospace,monospace;color:var(--muted);font-size:13px}
.res ul{margin:6px 0 0;padding-left:18px;font-size:13px;color:#c5d0d6}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px}
.code{font-size:30px;letter-spacing:4px;font-weight:800;text-align:center;background:#0b141a;border:1px dashed var(--g);border-radius:12px;padding:12px;margin:10px 0}
.error{color:var(--r);font-size:14px}.hidden{display:none}.demo{background:rgba(255,176,32,.15);border:1px solid var(--o);color:var(--o);padding:8px 12px;border-radius:10px;font-size:13px;margin-bottom:10px}
label.chk{display:flex;gap:8px;align-items:center;font-size:14px;margin-bottom:10px}label.chk input{width:auto;margin:0}
img.qr{display:block;margin:10px auto;max-width:260px;background:#fff;padding:8px;border-radius:12px}
</style></head><body><div class="wrap">
<h1>🔎 Vérificateur de numéros WhatsApp</h1>
<p class="muted">Vois si un numéro est toujours disponible, ou s'il a disparu (banni, supprimé), avec la date et l'heure.</p>
<div id="demo" class="demo hidden">MODE DÉMO : résultats simulés. Numéro finissant par 0 = introuvable ; finissant par 9 = actif au 1er contrôle puis « banni » au suivant.</div>

<section class="card" id="conn">
  <h2>1. WhatsApp du vérificateur <span id="badge" class="badge b-wait">…</span></h2>
  <div id="connOk" class="hidden"><p class="muted">Connecté avec le numéro <strong id="me"></strong>. Vérifications aujourd'hui : <span id="quota"></span>.</p></div>
  <div id="connNo" class="hidden">
    <p class="muted">Utilise un numéro WhatsApp secondaire (pas ton numéro principal) pour ce rôle. Entre-le pour obtenir un code de liaison.</p>
    <input id="pairPhone" type="tel" inputmode="tel" placeholder="+241 07 12 34 56">
    <button class="btn" id="pairBtn">Obtenir le code de liaison</button>
    <div id="pairBox" class="hidden">
      <div class="code" id="pairCode"></div>
      <p class="muted">Sur ce téléphone : WhatsApp → ⋮ → Appareils connectés → Connecter un appareil → <strong>Associer avec le numéro de téléphone</strong> → tape ce code.</p>
    </div>
    <img id="qrImg" class="qr hidden" alt="QR code">
    <p class="error" id="pairErr"></p>
  </div>
</section>

<section class="card">
  <h2>2. Vérifier des numéros</h2>
  <textarea id="nums" rows="4" placeholder="Un numéro par ligne, avec l'indicatif&#10;+241 07 12 34 56&#10;+33 6 12 34 56 78"></textarea>
  <label class="chk"><input type="checkbox" id="watch"> Surveiller ces numéros (revérification automatique pour détecter quand ils disparaissent)</label>
  <button class="btn" id="checkBtn">Vérifier</button>
  <p class="error" id="checkErr"></p>
  <div id="results"></div>
</section>

<section class="card">
  <h2>3. Historique</h2>
  <div id="history"><p class="muted">Aucun numéro vérifié pour l'instant.</p></div>
</section>
<p class="muted">Note : le statut « spamé » n'existe pas côté WhatsApp et ne peut pas être détecté. Le site distingue seulement « disponible » et « introuvable / plus disponible ».</p>
</div>
<script>
var H = { 'Content-Type': 'application/json', 'X-Requested-With': 'verif' };
function $(id) { return document.getElementById(id); }
function api(url, method, body) {
  return fetch(url, { method: method || 'GET', headers: H, body: body ? JSON.stringify(body) : undefined }).then(function (r) { return r.json(); });
}
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function show(id, on) { $(id).className = $(id).className.replace(' hidden', '').replace('hidden', '').trim() + (on ? '' : ' hidden'); }

function card(r, withActions) {
  var d = el('div', 'res ' + r.state);
  d.appendChild(el('div', 'num', r.number));
  d.appendChild(el('h3', '', r.headline));
  var ul = el('ul');
  r.lines.forEach(function (l) { ul.appendChild(el('li', '', l)); });
  d.appendChild(ul);
  if (withActions) {
    if (r.events.length > 1) {
      var det = el('details'); det.appendChild(el('summary', 'muted', 'Historique (' + r.checks + ' contrôles)'));
      var u2 = el('ul'); r.events.forEach(function (l) { u2.appendChild(el('li', '', l)); }); det.appendChild(u2); d.appendChild(det);
    }
    var row = el('div', 'row');
    var w = el('button', 'btn small ghost', r.watch ? '👁 Surveillé (arrêter)' : '👁 Surveiller');
    w.onclick = function () { api('/api/watch', 'POST', { number: r.number, on: !r.watch }).then(loadHistory); };
    var re = el('button', 'btn small ghost', '↻ Revérifier');
    re.onclick = function () { $('nums').value = r.number; check(); };
    var x = el('button', 'btn small ghost', 'Supprimer');
    x.onclick = function () { if (confirm('Supprimer ce numéro et son historique ?')) api('/api/number', 'DELETE', { number: r.number }).then(loadHistory); };
    row.appendChild(w); row.appendChild(re); row.appendChild(x); d.appendChild(row);
  }
  return d;
}

function loadHistory() {
  api('/api/history').then(function (d) {
    var box = $('history'); box.innerHTML = '';
    if (!d.items || !d.items.length) { box.appendChild(el('p', 'muted', 'Aucun numéro vérifié pour l\\'instant.')); return; }
    d.items.forEach(function (r) { box.appendChild(card(r, true)); });
  });
}

function refreshStatus() {
  api('/api/status').then(function (s) {
    show('demo', s.demo);
    var b = $('badge');
    if (s.status === 'connected') { b.textContent = 'Connecté'; b.className = 'badge b-ok'; }
    else if (s.status === 'connecting') { b.textContent = 'Connexion…'; b.className = 'badge b-wait'; }
    else { b.textContent = 'Non connecté'; b.className = 'badge b-no'; }
    show('connOk', s.status === 'connected'); show('connNo', s.status !== 'connected');
    $('me').textContent = s.me || ''; $('quota').textContent = s.usedToday + ' / ' + s.dailyLimit;
    if (s.pairing && s.status !== 'connected') { $('pairCode').textContent = s.pairing; show('pairBox', true); }
    var q = $('qrImg'); if (s.qr && s.status !== 'connected') { q.src = s.qr; show('qrImg', true); } else show('qrImg', false);
  });
}

$('pairBtn').onclick = function () {
  $('pairErr').textContent = ''; $('pairBtn').disabled = true; $('pairBtn').textContent = 'Patiente…';
  api('/api/pair', 'POST', { phone: $('pairPhone').value }).then(function (d) {
    $('pairBtn').disabled = false; $('pairBtn').textContent = 'Obtenir le code de liaison';
    if (!d.ok) return ($('pairErr').textContent = d.message);
    $('pairCode').textContent = d.code; show('pairBox', true);
  });
};

function check() {
  $('checkErr').textContent = ''; $('results').innerHTML = '';
  var nums = $('nums').value.split(/[\\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  $('checkBtn').disabled = true; $('checkBtn').textContent = 'Vérification en cours…';
  api('/api/check', 'POST', { numbers: nums, watch: $('watch').checked }).then(function (d) {
    $('checkBtn').disabled = false; $('checkBtn').textContent = 'Vérifier';
    if (!d.ok) return ($('checkErr').textContent = d.message);
    d.results.forEach(function (r) { $('results').appendChild(card(r, false)); });
    loadHistory();
  }).catch(function () { $('checkBtn').disabled = false; $('checkBtn').textContent = 'Vérifier'; $('checkErr').textContent = 'Erreur réseau.'; });
}
$('checkBtn').onclick = check;

refreshStatus(); loadHistory();
setInterval(refreshStatus, 4000);
</script></body></html>`;

app.listen(Number(env.PORT || 3000), () => console.log('Site prêt sur le port ' + (env.PORT || 3000) + (DEMO ? ' (MODE DÉMO)' : '')));
startWA();
