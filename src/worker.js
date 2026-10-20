// El HUB — Cloudflare Worker
// Sirve los archivos de /public y expone la API en /api/*
// Datos en Workers KV (binding HUB):
//   portals            -> [{id,name,desc,url,icon}]
//   users              -> {username: {username,name,role,salt,hash,portals:[ids],createdAt}}
//   session:<token>    -> {username,exp}           (expira sola a las 12 h)
//   rl:<ip>            -> intentos fallidos de login (expira a los 15 min)

const SESSION_HOURS = 12;
const SESSION_TTL = SESSION_HOURS * 3600;
const COOKIE = "hub_session";
const PBKDF2_ITER = 100000; // máximo permitido en Workers
const MAX_FAILS = 10;
const LOCK_SECONDS = 900;

const DEFAULT_PORTALS = [
  { id: "cockpit", name: "SE Cockpit Idira", desc: "Panel de control de ingeniería de ventas para Idira.", url: "https://maurosystem.com/cockpit", icon: "cockpit" },
  { id: "paloalto", name: "Palo Alto", desc: "Portal de seguridad y redes Palo Alto Networks.", url: "https://maurosystem.com/paloalto", icon: "shield" },
  { id: "tablero", name: "El Tablero", desc: "Indicadores y métricas clave en una sola vista.", url: "https://maurosystem.com/tablero", icon: "board" },
  { id: "embarazo", name: "Seguimiento de embarazo", desc: "Semana a semana: controles, citas y recuerdos.", url: "https://maurosystem.com/embarazo", icon: "sprout" },
  { id: "finanzas", name: "Finanzas Casa", desc: "Presupuesto, gastos y ahorro del hogar.", url: "https://maurosystem.com/finanzas", icon: "coins" },
  { id: "familiar", name: "Portal Familiar", desc: "Calendario, fotos y novedades de la familia.", url: "https://maurosystem.com/familia", icon: "family" },
];
const ICONS = ["cockpit", "shield", "board", "sprout", "coins", "family", "leaf", "link"];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    try {
      return await api(request, env, url);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: "Error interno del servidor." }, 500);
    }
  },
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/* ---------------- Routing ---------------- */
async function api(request, env, url) {
  const method = request.method;
  const path = url.pathname.replace(/\/+$/, "");

  // Protección CSRF: las escrituras deben venir del mismo origen
  if (method !== "GET") {
    const origin = request.headers.get("Origin");
    if (origin && origin !== url.origin) throw new HttpError(403, "Origen no permitido.");
  }

  if (path === "/api/login" && method === "POST") return login(request, env);
  if (path === "/api/logout" && method === "POST") return logout(request, env);

  const me = await currentUser(request, env);
  if (!me) throw new HttpError(401, "Tu sesión expiró. Vuelve a entrar.");

  if (path === "/api/me" && method === "GET") {
    const portals = await getPortals(env);
    const visible = me.role === "admin" ? portals : portals.filter(p => (me.portals || []).includes(p.id));
    return json({ user: publicUser(me), portals: visible, sessionHours: SESSION_HOURS });
  }
  if (path === "/api/password" && method === "POST") return changeOwnPassword(request, env, me);

  // ---- Solo administradores ----
  if (path.startsWith("/api/admin/")) {
    if (me.role !== "admin") throw new HttpError(403, "Solo un administrador puede hacer esto.");
    if (path === "/api/admin/state" && method === "GET") {
      const users = await getUsers(env);
      return json({ portals: await getPortals(env), users: Object.values(users).map(publicUser) });
    }
    if (path === "/api/admin/portals" && method === "PUT") return savePortals(request, env);
    if (path === "/api/admin/users" && method === "POST") return createUser(request, env);
    const m = path.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (m) {
      const username = decodeURIComponent(m[1]).toLowerCase();
      if (method === "PUT") return updateUser(request, env, username, me);
      if (method === "DELETE") return deleteUser(env, username, me);
    }
  }
  throw new HttpError(404, "Ruta no encontrada.");
}

/* ---------------- Auth ---------------- */
async function login(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "local";
  const rlKey = "rl:" + ip;
  const fails = parseInt((await env.HUB.get(rlKey)) || "0", 10);
  if (fails >= MAX_FAILS) throw new HttpError(429, "Demasiados intentos. Espera 15 minutos y vuelve a intentar.");

  const body = await readJson(request);
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  let users = await getUsers(env);
  let user = users[username];

  // Primer arranque: si no hay usuarios, crea "admin" con ADMIN_INITIAL_PASSWORD
  if (Object.keys(users).length === 0 && username === "admin") {
    if (!env.ADMIN_INITIAL_PASSWORD) throw new HttpError(500, "Falta el secreto ADMIN_INITIAL_PASSWORD en Cloudflare.");
    if (password === env.ADMIN_INITIAL_PASSWORD) {
      user = await makeUser({ username: "admin", name: "Administrador", role: "admin", password, portals: [] });
      users = { admin: user };
      await env.HUB.put("users", JSON.stringify(users));
    }
  }

  if (!user || !(await verifyPassword(password, user.salt, user.hash))) {
    await env.HUB.put(rlKey, String(fails + 1), { expirationTtl: LOCK_SECONDS });
    throw new HttpError(401, "Usuario o contraseña incorrectos.");
  }
  if (fails) await env.HUB.delete(rlKey);

  const token = randomToken();
  const exp = Date.now() + SESSION_TTL * 1000;
  await env.HUB.put("session:" + token, JSON.stringify({ username: user.username, exp }), { expirationTtl: SESSION_TTL });
  return json({ user: publicUser(user), expiresAt: exp }, 200, {
    "Set-Cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`,
  });
}

async function logout(request, env) {
  const token = readCookie(request, COOKIE);
  if (token) await env.HUB.delete("session:" + token);
  return json({ ok: true }, 200, { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
}

async function currentUser(request, env) {
  const token = readCookie(request, COOKIE);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const raw = await env.HUB.get("session:" + token);
  if (!raw) return null;
  const s = JSON.parse(raw);
  if (s.exp < Date.now()) return null;
  const users = await getUsers(env);
  return users[s.username] || null;
}

async function changeOwnPassword(request, env, me) {
  const body = await readJson(request);
  if (!(await verifyPassword(String(body.current || ""), me.salt, me.hash))) throw new HttpError(400, "La contraseña actual no coincide.");
  checkPassword(body.next);
  const users = await getUsers(env);
  Object.assign(users[me.username], await hashPassword(String(body.next)));
  await env.HUB.put("users", JSON.stringify(users));
  return json({ ok: true });
}

/* ---------------- Portals ---------------- */
async function getPortals(env) {
  const raw = await env.HUB.get("portals");
  return raw ? JSON.parse(raw) : DEFAULT_PORTALS;
}
async function savePortals(request, env) {
  const body = await readJson(request);
  if (!Array.isArray(body.portals) || body.portals.length > 60) throw new HttpError(400, "Lista de portales no válida.");
  const seen = new Set();
  const clean = body.portals.map(p => {
    const id = String(p.id || "").replace(/[^a-z0-9_-]/gi, "").slice(0, 40) || "p" + Math.random().toString(36).slice(2, 9);
    if (seen.has(id)) throw new HttpError(400, "Hay portales con el mismo identificador.");
    seen.add(id);
    const name = String(p.name || "").trim().slice(0, 40);
    if (!name) throw new HttpError(400, "Cada portal necesita un nombre.");
    let u;
    try { u = new URL(String(p.url)); } catch { throw new HttpError(400, `El enlace de "${name}" no es válido.`); }
    if (!/^https?:$/.test(u.protocol)) throw new HttpError(400, `El enlace de "${name}" debe empezar con https://`);
    return { id, name, desc: String(p.desc || "").trim().slice(0, 140), url: u.href, icon: ICONS.includes(p.icon) ? p.icon : "link" };
  });
  await env.HUB.put("portals", JSON.stringify(clean));
  return json({ portals: clean });
}

/* ---------------- Users ---------------- */
async function getUsers(env) {
  const raw = await env.HUB.get("users");
  return raw ? JSON.parse(raw) : {};
}
function publicUser(u) {
  return { username: u.username, name: u.name, role: u.role, portals: u.portals || [] };
}
function checkUsername(username) {
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw new HttpError(400, "El usuario debe tener entre 3 y 32 caracteres: letras, números, punto, guion o guion bajo.");
}
function checkPassword(pw) {
  if (typeof pw !== "string" || pw.length < 8) throw new HttpError(400, "La contraseña necesita al menos 8 caracteres.");
}
async function makeUser({ username, name, role, password, portals }) {
  return {
    username, name: String(name || username).trim().slice(0, 60),
    role: role === "admin" ? "admin" : "user",
    portals: Array.isArray(portals) ? portals.map(String).slice(0, 100) : [],
    createdAt: Date.now(),
    ...(await hashPassword(password)),
  };
}
async function createUser(request, env) {
  const b = await readJson(request);
  const username = String(b.username || "").trim().toLowerCase();
  checkUsername(username);
  checkPassword(b.password);
  const users = await getUsers(env);
  if (users[username]) throw new HttpError(409, "Ese nombre de usuario ya existe.");
  users[username] = await makeUser({ ...b, username });
  await env.HUB.put("users", JSON.stringify(users));
  return json({ user: publicUser(users[username]) });
}
async function updateUser(request, env, username, me) {
  const b = await readJson(request);
  const users = await getUsers(env);
  const u = users[username];
  if (!u) throw new HttpError(404, "Ese usuario no existe.");
  if (b.name !== undefined) u.name = String(b.name).trim().slice(0, 60) || u.username;
  if (b.role !== undefined) {
    const role = b.role === "admin" ? "admin" : "user";
    if (username === me.username && role !== "admin") throw new HttpError(400, "No puedes quitarte a ti mismo el rol de administrador.");
    u.role = role;
  }
  if (Array.isArray(b.portals)) u.portals = b.portals.map(String).slice(0, 100);
  if (b.password) { checkPassword(b.password); Object.assign(u, await hashPassword(b.password)); }
  await env.HUB.put("users", JSON.stringify(users));
  return json({ user: publicUser(u) });
}
async function deleteUser(env, username, me) {
  if (username === me.username) throw new HttpError(400, "No puedes eliminar tu propio usuario.");
  const users = await getUsers(env);
  if (!users[username]) throw new HttpError(404, "Ese usuario no existe.");
  delete users[username];
  await env.HUB.put("users", JSON.stringify(users));
  return json({ ok: true });
}

/* ---------------- Crypto & helpers ---------------- */
async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, key, 256);
  return { salt: bytesToHex(salt), hash: bytesToHex(new Uint8Array(bits)) };
}
async function verifyPassword(password, saltHex, hashHex) {
  if (!saltHex || !hashHex) return false;
  const { hash } = await hashPassword(password, saltHex);
  // comparación en tiempo constante
  if (hash.length !== hashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ hashHex.charCodeAt(i);
  return diff === 0;
}
function randomToken() { return bytesToHex(crypto.getRandomValues(new Uint8Array(32))); }
function bytesToHex(b) { return [...b].map(x => x.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(h) { return new Uint8Array(h.match(/../g).map(x => parseInt(x, 16))); }
function readCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? m[1] : null;
}
async function readJson(request) {
  try { return await request.json(); } catch { throw new HttpError(400, "Solicitud no válida."); }
}
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
