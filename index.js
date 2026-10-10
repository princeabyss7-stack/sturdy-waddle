/**
 * NextIdea — site d'idées + votes + connexion par code WhatsApp.
 * Un seul fichier serveur (Express) hébergé sur Vercel.
 */
const express = require('express');
const crypto = require('crypto');

const env = process.env;

/* ======================= Base de données (Upstash ou mémoire) ======================= */
const UP_URL = env.UPSTASH_REDIS_REST_URL;
const UP_TOKEN = env.UPSTASH_REDIS_REST_TOKEN;
const remote = !!(UP_URL && UP_TOKEN);
const mem = new Map();

async function cmd(args) {
  const r = await fetch(UP_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UP_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d.result;
}
function memGet(k) {
  const e = mem.get(k);
  if (!e) return null;
  if (e.exp && Date.now() > e.exp) { mem.delete(k); return null; }
  return e.v;
}
async function kvGet(k) {
  const raw = remote ? await cmd(['GET', k]) : memGet(k);
  if (raw == null) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}
async function kvSet(k, v, ttl) {
  const raw = JSON.stringify(v);
  if (remote) await cmd(ttl ? ['SET', k, raw, 'EX', ttl] : ['SET', k, raw]);
  else mem.set(k, { v: raw, exp: ttl ? Date.now() + ttl * 1000 : null });
}
async function kvDel(k) {
  if (remote) await cmd(['DEL', k]);
  else mem.delete(k);
}
async function kvIncr(k, ttl) {
  if (remote) {
    const n = Number(await cmd(['INCR', k]));
    if (n === 1) await cmd(['EXPIRE', k, ttl]);
    return n;
  }
  const old = mem.get(k);
  const alive = old && (!old.exp || Date.now() <= old.exp);
  const n = (alive ? Number(old.v) : 0) + 1;
  mem.set(k, { v: String(n), exp: alive && old.exp ? old.exp : Date.now() + ttl * 1000 });
  return n;
}
const rateLimit = async (k, limit, windowSec) => (await kvIncr('rl:' + k, windowSec)) <= limit;

/* ======================= Utilitaires ======================= */
const SECRET = env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');

function normalizePhone(input) {
  let s = String(input || '').replace(/[\s().-]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  return /^\+[1-9]\d{7,14}$/.test(s) ? s : null;
}
const maskPhone = (p) => p.slice(0, 4) + ' •••• ' + p.slice(-2);
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest();

async function isBlocked(phone) {
  const list = (env.BLOCKED_PHONES || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (list.includes(phone)) return true;
  return (await kvGet('blocked:' + phone)) === true;
}

/* ======================= Codes OTP + sessions ======================= */
const OTP_TTL = 300; // 5 minutes
const COOLDOWN = 60; // 1 minute entre deux envois
const MAX_ATTEMPTS = 5;

const codeHash = (phone, code) => hmac(phone + ':' + code).toString('hex');
const generateCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');

async function saveCode(phone, code) {
  await kvSet('otp:' + phone, { hash: codeHash(phone, code), expiresAt: Date.now() + OTP_TTL * 1000, attempts: 0, sentAt: Date.now() }, OTP_TTL);
}
async function cooldownLeft(phone) {
  const r = await kvGet('otp:' + phone);
  if (!r) return 0;
  return Math.max(0, Math.ceil((r.sentAt + COOLDOWN * 1000 - Date.now()) / 1000));
}
async function checkCode(phone, code) {
  const key = 'otp:' + phone;
  const r = await kvGet(key);
  if (!r) return 'none';
  if (Date.now() > r.expiresAt) { await kvDel(key); return 'expired'; }
  if (r.attempts >= MAX_ATTEMPTS) return 'too_many_attempts';
  r.attempts++;
  const left = Math.max(1, Math.ceil((r.expiresAt - Date.now()) / 1000));
  const a = Buffer.from(r.hash);
  const b = Buffer.from(codeHash(phone, code));
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) { await kvDel(key); return 'ok'; }
  await kvSet(key, r, left);
  return 'invalid';
}

function signSession(phone) {
  const body = Buffer.from(JSON.stringify({ phone, exp: Date.now() + 30 * 86400000 })).toString('base64url');
  return body + '.' + hmac(body).toString('base64url');
}
function readSession(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = hmac(parts[0]).toString('base64url');
  if (parts[1].length !== expected.length || !crypto.timingSafeEqual(Buffer.from(parts[1]), Buffer.from(expected))) return null;
  try {
    const d = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    return Date.now() > d.exp ? null : { phone: d.phone };
  } catch (e) { return null; }
}
function getCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const p of h.split(';')) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i).trim() === name) return decodeURIComponent(p.slice(i + 1).trim());
  }
  return null;
}
async function getUser(req) {
  const s = readSession(getCookie(req, 'session'));
  if (!s || (await isBlocked(s.phone))) return null;
  return s;
}
const sessionCookie = (value, maxAge) =>
  'session=' + encodeURIComponent(value) + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + maxAge;

/* ======================= Envoi WhatsApp (API Meta) ======================= */
const WA_ERRORS = {
  131026: ['no_whatsapp', "Ce numéro n'a pas WhatsApp ou ne peut pas recevoir de message."],
  131049: ['spam_limited', 'WhatsApp a limité les messages vers ce numéro (protection anti-spam). Réessaie plus tard.'],
  130429: ['rate_limited', "Trop d'envois pour le moment, réessaie dans quelques minutes."],
  131056: ['rate_limited', 'Trop de messages envoyés vers ce numéro, réessaie plus tard.'],
  131030: ['invalid_number', "Ce numéro n'est pas autorisé (mode test Meta : ajoute-le à la liste des destinataires)."],
  131021: ['invalid_number', 'Numéro destinataire invalide.'],
  133010: ['server_error', "Le numéro d'envoi du site n'est pas enregistré chez Meta."],
};
async function sendWhatsAppCode(phone, code) {
  const token = env.WHATSAPP_TOKEN;
  const phoneId = env.WHATSAPP_PHONE_NUMBER_ID;
  if (!token || !phoneId) return { ok: true, demo: true };
  try {
    const res = await fetch('https://graph.facebook.com/v21.0/' + phoneId + '/messages', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        to: phone.replace('+', ''),
        type: 'template',
        template: {
          name: env.WHATSAPP_TEMPLATE_NAME || 'otp_code',
          language: { code: env.WHATSAPP_TEMPLATE_LANG || 'fr' },
          components: [
            { type: 'body', parameters: [{ type: 'text', text: code }] },
            { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: code }] },
          ],
        },
      }),
    });
    const d = await res.json().catch(() => ({}));
    if (res.ok) return { ok: true };
    const known = WA_ERRORS[d && d.error && d.error.code];
    if (known) return { ok: false, reason: known[0], message: known[1] };
    console.error('WhatsApp error', JSON.stringify(d));
    return { ok: false, reason: 'server_error', message: "Impossible d'envoyer le code pour le moment." };
  } catch (e) {
    console.error(e);
    return { ok: false, reason: 'server_error', message: 'Erreur réseau, réessaie.' };
  }
}

/* ======================= Idées ======================= */
const seedVoters = (p, n) => Array.from({ length: n }, (_, k) => 'seed-' + p + '-' + k);
const SEED = () => [
  { id: 'seed-1', title: 'Application de covoiturage locale', description: 'Mettre en relation les habitants qui font les mêmes trajets chaque jour.', author: 'Communauté', createdAt: Date.now() - 3 * 86400000, voters: seedVoters('a', 14) },
  { id: 'seed-2', title: 'Marché en ligne des artisans', description: 'Une vitrine simple pour que les artisans vendent par WhatsApp.', author: 'Communauté', createdAt: Date.now() - 2 * 86400000, voters: seedVoters('b', 9) },
  { id: 'seed-3', title: 'Cours de code gratuits pour débutants', description: 'Des mini-formations en français, pensées pour le téléphone.', author: 'Communauté', createdAt: Date.now() - 86400000, voters: seedVoters('c', 6) },
];
async function loadIdeas() {
  const v = await kvGet('ideas');
  if (v) return v;
  const s = SEED();
  await kvSet('ideas', s);
  return s;
}
const publicIdea = (i, phone) => ({
  id: i.id, title: i.title, description: i.description, author: i.author, createdAt: i.createdAt,
  votes: i.voters.length, voted: !!phone && i.voters.includes(phone),
});

/* ======================= Serveur ======================= */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  res.status(500).json({ ok: false, message: 'Erreur serveur, réessaie.' });
});
const ipOf = (req) => (String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown');
const fail = (res, status, error, message, extra) => res.status(status).json(Object.assign({ ok: false, error, message }, extra || {}));

app.get('/', (req, res) => {
  const link = JSON.stringify(env.WHATSAPP_LINK || '').replace(/</g, '\\u003c');
  res.set('Content-Type', 'text/html; charset=utf-8').send(PAGE.replace('__WA_LINK__', link));
});

app.post('/api/auth/send-otp', wrap(async (req, res) => {
  const phone = normalizePhone(req.body && req.body.phone);
  if (!phone) return fail(res, 400, 'invalid_number', 'Numéro invalide. Écris-le avec l’indicatif du pays, ex : +241 07 12 34 56.');
  if (await isBlocked(phone)) return fail(res, 403, 'blocked', "Ce numéro n'est pas autorisé à se connecter.");
  if (!(await rateLimit('ip:' + ipOf(req), 10, 600))) return fail(res, 429, 'rate_limited', 'Trop de tentatives, réessaie plus tard.');
  if (!(await rateLimit('phone:' + phone, 3, 600))) return fail(res, 429, 'rate_limited', 'Trop de codes demandés pour ce numéro. Réessaie dans 10 minutes.');
  const wait = await cooldownLeft(phone);
  if (wait > 0) return fail(res, 429, 'cooldown', 'Attends ' + wait + 's avant de redemander un code.', { retryAfter: wait });

  const code = generateCode();
  const r = await sendWhatsAppCode(phone, code);
  if (!r.ok) return fail(res, r.reason === 'server_error' ? 502 : 422, r.reason, r.message);
  await saveCode(phone, code);
  // MODE TEST : tant que WhatsApp n'est pas configuré, le code est affiché à l'écran.
  res.json(Object.assign({ ok: true, phone, message: r.demo ? 'Mode test : WhatsApp non configuré.' : 'Code envoyé sur WhatsApp.' }, r.demo ? { devCode: code } : {}));
}));

const VERIFY_MSG = {
  expired: 'Code expiré. Demande un nouveau code.',
  invalid: 'Code incorrect.',
  too_many_attempts: "Trop d'essais. Demande un nouveau code.",
  none: 'Aucun code demandé pour ce numéro.',
};
app.post('/api/auth/verify-otp', wrap(async (req, res) => {
  const phone = normalizePhone(req.body && req.body.phone);
  const code = String((req.body && req.body.code) || '');
  if (!phone || !/^[0-9]{6}$/.test(code)) return fail(res, 400, 'invalid', 'Numéro ou code invalide.');
  if (!(await rateLimit('verify:' + ipOf(req), 30, 600))) return fail(res, 429, 'rate_limited', 'Trop de tentatives.');
  if (await isBlocked(phone)) return fail(res, 403, 'blocked', 'Compte bloqué.');
  const result = await checkCode(phone, code);
  if (result !== 'ok') return fail(res, 401, result, VERIFY_MSG[result]);
  if (!(await kvGet('user:' + phone))) await kvSet('user:' + phone, { phone, createdAt: Date.now() }); // 1 compte par numéro
  res.set('Set-Cookie', sessionCookie(signSession(phone), 30 * 86400));
  res.json({ ok: true, phone });
}));

app.get('/api/auth/me', wrap(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: await getUser(req) });
}));
app.delete('/api/auth/me', (req, res) => {
  res.set('Set-Cookie', sessionCookie('', 0));
  res.json({ ok: true });
});

app.get('/api/ideas', wrap(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const user = await getUser(req);
  const list = await loadIdeas();
  const ideas = list.map((i) => publicIdea(i, user && user.phone)).sort((a, b) => b.votes - a.votes || b.createdAt - a.createdAt);
  res.json({ ideas });
}));

app.post('/api/ideas', wrap(async (req, res) => {
  const user = await getUser(req);
  if (!user) return fail(res, 401, 'auth', 'Connecte-toi pour proposer une idée.');
  const title = String((req.body && req.body.title) || '').trim();
  const description = String((req.body && req.body.description) || '').trim();
  if (title.length < 3 || title.length > 80) return fail(res, 400, 'invalid', 'Le titre doit faire entre 3 et 80 caractères.');
  if (description.length > 500) return fail(res, 400, 'invalid', 'La description est trop longue (500 caractères max).');
  if (!(await rateLimit('idea:' + user.phone, 5, 86400))) return fail(res, 429, 'rate_limited', 'Tu as atteint la limite de 5 idées par jour.');
  const list = await loadIdeas();
  list.unshift({ id: crypto.randomUUID(), title, description, author: maskPhone(user.phone), createdAt: Date.now(), voters: [user.phone] });
  await kvSet('ideas', list);
  res.json({ ok: true });
}));

// Un vote par numéro et par idée. Re-cliquer retire le vote.
app.post('/api/vote', wrap(async (req, res) => {
  const user = await getUser(req);
  if (!user) return fail(res, 401, 'auth', 'Connecte-toi pour voter.');
  if (!(await rateLimit('vote:' + user.phone, 60, 3600))) return fail(res, 429, 'rate_limited', 'Trop de votes, réessaie plus tard.');
  const list = await loadIdeas();
  const idea = list.find((i) => i.id === (req.body && req.body.id));
  if (!idea) return fail(res, 404, 'not_found', 'Idée introuvable.');
  idea.voters = idea.voters.includes(user.phone) ? idea.voters.filter((p) => p !== user.phone) : idea.voters.concat([user.phone]);
  await kvSet('ideas', list);
  res.json({ ok: true, votes: idea.voters.length });
}));

/* ======================= Page web ======================= */
const PAGE = `<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NextIdea – Les idées de la communauté</title>
<style>
:root{--bg:#0d0b1a;--card:#17142b;--line:#2b2650;--text:#f2f0ff;--muted:#9a96c0;--a:#7c5cff;--b:#ff5ca8;--ok:#25d366;--err:#ff6b6b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;line-height:1.5}
h1,h2,h3{margin:0 0 8px;line-height:1.2}p{margin:0 0 10px}.muted{color:var(--muted);font-size:14px}
.wrap{max-width:900px;margin:0 auto;padding:16px 16px 60px}
.top{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(13,11,26,.94);z-index:5}
.logo{font-weight:800;font-size:20px}.logo span{color:var(--b)}.who{display:flex;gap:10px;align-items:center}
.hero{text-align:center;padding:36px 0 24px}.hero h1{font-size:clamp(30px,8vw,52px)}
.hero h1 span{background:linear-gradient(90deg,var(--a),var(--b));-webkit-background-clip:text;background-clip:text;color:transparent}
.stats{display:flex;gap:14px;justify-content:center;margin-top:18px}
.stats div{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 22px;display:grid}
.stats strong{font-size:24px}.stats span{color:var(--muted);font-size:13px}
.banner{display:block;text-align:center;padding:14px;margin:8px 0 20px;border-radius:14px;background:rgba(37,211,102,.12);border:1px solid var(--ok);color:var(--ok);text-decoration:none;font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;margin-bottom:28px}
input,textarea{width:100%;background:#0f0d20;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px;font:inherit;margin-bottom:10px}
input:focus,textarea:focus{outline:2px solid var(--a)}
.btn{background:linear-gradient(90deg,var(--a),var(--b));color:#fff;border:0;border-radius:12px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer;width:100%;margin-bottom:8px}
.btn.small{width:auto;padding:8px 14px;margin:0}.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--text);font-weight:500}
.btn:disabled{opacity:.5;cursor:not-allowed}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));margin-top:12px}
.idea{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px;display:flex;flex-direction:column;gap:6px}
.idea p{color:#cfcbf2;font-size:14px;flex:1}.rank{color:var(--b);font-weight:800;font-size:13px}
.foot{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:6px}
.vote{background:transparent;color:var(--text);border:1px solid var(--a);border-radius:999px;padding:8px 14px;font:inherit;font-weight:600;cursor:pointer;white-space:nowrap}
.vote.on{background:var(--a)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;place-items:center;padding:16px;z-index:20}
.overlay.open{display:grid}
.modal{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:22px;width:100%;max-width:400px;position:relative}
.close{position:absolute;top:10px;right:12px;background:none;border:0;color:var(--muted);font-size:18px;cursor:pointer}
.error{color:var(--err);font-size:14px}.okmsg{color:var(--ok);font-size:14px}
.devcode{background:rgba(255,200,0,.12);border:1px dashed #ffc800;border-radius:10px;padding:10px;font-size:14px}
.devcode strong{font-size:20px;letter-spacing:3px}.hidden{display:none}
</style></head><body>
<header class="top"><div class="logo">next<span>idea</span> ✦</div><div id="who"></div></header>
<main class="wrap">
  <section class="hero">
    <h1>Propose. Vote.<br><span>Construisons ensemble ✦</span></h1>
    <p class="muted">Les meilleures idées de la communauté deviennent de vrais projets.</p>
    <div class="stats"><div><strong id="nIdeas">0</strong><span>idées</span></div><div><strong id="nVotes">0</strong><span>votes</span></div></div>
  </section>
  <a id="banner" class="banner hidden" target="_blank" rel="noreferrer">💬 Rejoins la communauté sur WhatsApp</a>
  <section class="card">
    <h2>Proposer une idée</h2>
    <input id="title" placeholder="Titre de ton idée" maxlength="80">
    <textarea id="desc" rows="3" maxlength="500" placeholder="Explique-la en quelques mots (facultatif)"></textarea>
    <button class="btn" id="submit">Publier mon idée</button>
    <p class="error" id="formErr"></p>
  </section>
  <section><h2>Les idées les plus votées</h2><div class="grid" id="list"></div></section>
</main>
<div class="overlay" id="overlay"><div class="modal">
  <button class="close" id="closeBtn" aria-label="Fermer">✕</button>
  <h2>Connexion par WhatsApp</h2>
  <div id="step1">
    <p class="muted">Entre ton numéro avec l'indicatif du pays. Tu recevras un code sur WhatsApp.</p>
    <input id="phone" type="tel" inputmode="tel" placeholder="+241 07 12 34 56">
    <button class="btn" id="sendBtn">Recevoir le code</button>
  </div>
  <div id="step2" class="hidden">
    <p class="muted" id="sentTo"></p>
    <p class="devcode hidden" id="devBox">🧪 Mode test — ton code est <strong id="devCode"></strong></p>
    <input id="code" inputmode="numeric" maxlength="6" placeholder="123456">
    <button class="btn" id="verifyBtn">Valider</button>
    <button class="btn ghost" id="resendBtn">Renvoyer le code</button>
    <button class="btn ghost" id="changeBtn">Changer de numéro</button>
  </div>
  <p id="loginMsg"></p>
</div></div>
<script>
var WA_LINK = __WA_LINK__;
var state = { user: null, ideas: [] };
var cooldown = 0, timer = null, currentPhone = '';
function $(id) { return document.getElementById(id); }
function api(url, method, body) {
  return fetch(url, { method: method || 'GET', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
    .then(function (r) { return r.json(); });
}
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

function load() {
  return Promise.all([api('/api/auth/me'), api('/api/ideas')]).then(function (r) {
    state.user = r[0].user; state.ideas = r[1].ideas || []; render();
  });
}
function render() {
  var who = $('who'); who.innerHTML = ''; who.className = 'who';
  if (state.user) {
    who.appendChild(el('span', 'muted', state.user.phone));
    var out = el('button', 'btn small ghost', 'Déconnexion');
    out.onclick = function () { api('/api/auth/me', 'DELETE').then(load); };
    who.appendChild(out);
  } else {
    var inb = el('button', 'btn small', 'Se connecter');
    inb.onclick = openLogin; who.appendChild(inb);
  }
  $('submit').textContent = state.user ? 'Publier mon idée' : 'Se connecter pour publier';
  $('nIdeas').textContent = state.ideas.length;
  $('nVotes').textContent = state.ideas.reduce(function (s, i) { return s + i.votes; }, 0);
  var list = $('list'); list.innerHTML = '';
  state.ideas.forEach(function (idea, idx) {
    var c = el('article', 'idea');
    c.appendChild(el('div', 'rank', '#' + (idx + 1)));
    c.appendChild(el('h3', '', idea.title));
    if (idea.description) c.appendChild(el('p', '', idea.description));
    var foot = el('div', 'foot');
    foot.appendChild(el('span', 'muted', 'par ' + idea.author));
    var v = el('button', 'vote' + (idea.voted ? ' on' : ''), (idea.voted ? '✓ Voté' : '▲ Voter') + ' · ' + idea.votes);
    v.onclick = function () { vote(idea.id); };
    foot.appendChild(v); c.appendChild(foot); list.appendChild(c);
  });
}
function vote(id) {
  if (!state.user) return openLogin();
  api('/api/vote', 'POST', { id: id }).then(function (d) { if (d.error === 'auth') openLogin(); else load(); });
}
$('submit').onclick = function () {
  if (!state.user) return openLogin();
  $('formErr').textContent = '';
  api('/api/ideas', 'POST', { title: $('title').value, description: $('desc').value }).then(function (d) {
    if (!d.ok) { $('formErr').textContent = d.message; if (d.error === 'auth') openLogin(); return; }
    $('title').value = ''; $('desc').value = ''; load();
  });
};

/* ---- Connexion ---- */
function msg(text, ok) { var m = $('loginMsg'); m.textContent = text || ''; m.className = ok ? 'okmsg' : 'error'; }
function openLogin() { $('overlay').className = 'overlay open'; showStep(1); msg(''); }
function closeLogin() { $('overlay').className = 'overlay'; }
function showStep(n) { $('step1').className = n === 1 ? '' : 'hidden'; $('step2').className = n === 2 ? '' : 'hidden'; }
function tick() {
  clearTimeout(timer);
  var b = $('resendBtn');
  if (cooldown > 0) { b.disabled = true; b.textContent = 'Renvoyer le code (' + cooldown + 's)'; cooldown--; timer = setTimeout(tick, 1000); }
  else { b.disabled = false; b.textContent = 'Renvoyer le code'; }
}
function sendCode() {
  msg(''); $('sendBtn').disabled = true;
  api('/api/auth/send-otp', 'POST', { phone: currentPhone || $('phone').value }).then(function (d) {
    $('sendBtn').disabled = false;
    if (!d.ok) { if (d.retryAfter) { cooldown = d.retryAfter; tick(); } return msg(d.message); }
    currentPhone = d.phone; $('sentTo').textContent = 'Code envoyé au ' + d.phone;
    $('devBox').className = d.devCode ? 'devcode' : 'devcode hidden'; $('devCode').textContent = d.devCode || '';
    showStep(2); cooldown = 60; tick(); msg(d.devCode ? d.message : 'Code envoyé sur WhatsApp ✅', true);
  });
}
$('sendBtn').onclick = function () { currentPhone = ''; sendCode(); };
$('resendBtn').onclick = sendCode;
$('changeBtn').onclick = function () { currentPhone = ''; $('code').value = ''; showStep(1); msg(''); };
$('code').oninput = function () { this.value = this.value.replace(/[^0-9]/g, ''); };
$('verifyBtn').onclick = function () {
  msg('');
  api('/api/auth/verify-otp', 'POST', { phone: currentPhone, code: $('code').value }).then(function (d) {
    if (!d.ok) return msg(d.message);
    closeLogin(); $('code').value = ''; load();
  });
};
$('closeBtn').onclick = closeLogin;
$('overlay').onclick = function (e) { if (e.target === this) closeLogin(); };
if (WA_LINK) { var bn = $('banner'); bn.href = WA_LINK; bn.className = 'banner'; }
load();
</script></body></html>`;

module.exports = app;

if (require.main === module) {
  const port = env.PORT || 3000;
  app.listen(port, () => console.log('Site sur http://localhost:' + port));
}
