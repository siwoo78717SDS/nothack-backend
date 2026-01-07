const fs = require("fs");
const path = require("path");
const express = require("express");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const bcrypt = require("bcryptjs");

function loadEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  const raw = fs.readFileSync(envPath, "utf8");
  raw.split(/\r?\n/).forEach((line) => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) return;
    const k = m[1];
    let v = m[2];
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    if (v.startsWith("'") && v.endsWith("'")) v = v.slice(1, -1);
    if (!(k in process.env)) process.env[k] = v;
  });
}
loadEnv();

const app = express();
app.set("trust proxy", true);

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false }));

const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
const SESS_DIR = path.join(DATA_DIR, "sessions");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(SESS_DIR)) fs.mkdirSync(SESS_DIR, { recursive: true });

function now() {
  return Date.now();
}
function safeId() {
  return "id_" + now().toString(36) + "_" + Math.random().toString(36).slice(2, 9);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function readDb() {
  try {
    const db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));

    // auto-migrate old dbs (if you already had users without email)
    if (Array.isArray(db.users)) {
      for (const u of db.users) {
        if (typeof u.email !== "string") u.email = "";
      }
    }

    return {
      users: [],
      factsApproved: [],
      factsSubmissions: [],
      bans: [],
      banRequests: [],
      visits: [],
      commandLogs: [],
      controlAudit: [],
      ...db,
    };
  } catch {
    return {
      users: [],
      factsApproved: [],
      factsSubmissions: [],
      bans: [],
      banRequests: [],
      visits: [],
      commandLogs: [],
      controlAudit: [],
    };
  }
}
function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

function jsonError(res, status, msg) {
  // send BOTH keys so your pages can use either data.error or data.message
  return res.status(status).json({ ok: false, error: msg, message: msg });
}

function getClientIp(req) {
  return String(req.ip || "").replace(/^::ffff:/, "");
}
function maskIp(ip) {
  const s = String(ip || "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    const p = s.split(".");
    return `${p[0]}.${p[1]}.${p[2]}.xxx`;
  }
  if (s.includes(":")) return s.split(":").slice(0, 3).join(":") + "::xxxx";
  return "";
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return jsonError(res, 401, "Not logged in");
  next();
}
function requireRole(...roles) {
  return (req, res, next) => {
    const db = readDb();
    const me = db.users.find((u) => u.id === req.session.userId);
    if (!me) return jsonError(res, 401, "Not logged in");
    if (!roles.includes(me.role)) return jsonError(res, 403, "Forbidden");
    req.me = me;
    next();
  };
}
function requireRolePage(...roles) {
  return (req, res, next) => {
    if (!req.session || !req.session.userId) return res.redirect("/login");
    const db = readDb();
    const me = db.users.find((u) => u.id === req.session.userId);
    if (!me) return res.redirect("/login");
    if (!roles.includes(me.role)) return res.status(403).send("Forbidden");
    req.me = me;
    next();
  };
}

// sessions
app.use(
  session({
    store: new FileStore({ path: SESS_DIR }),
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  }),
);

/**
 * IP bans disabled by default (set ENABLE_IP_BANS=true to enable).
 */
app.use((req, res, next) => {
  if (String(process.env.ENABLE_IP_BANS || "").toLowerCase() !== "true") return next();
  const db = readDb();
  const ip = getClientIp(req);
  const ipBanned = db.bans.some((b) => b.active && b.type === "ip" && b.ip === ip);
  if (ipBanned) return res.status(403).send("This IP is banned.");
  next();
});

// visit log
app.use((req, res, next) => {
  const ip = getClientIp(req);
  const ua = String(req.headers["user-agent"] || "");
  const p = req.path || "/";
  const key = "v:" + p;
  if (!req.session._visits) req.session._visits = {};
  if (!req.session._visits[key]) {
    req.session._visits[key] = true;
    const db = readDb();
    db.visits.unshift({
      id: safeId(),
      ip,
      userId: req.session.userId || null,
      userAgent: ua.slice(0, 240),
      at: now(),
      path: p,
    });
    db.visits = db.visits.slice(0, 5000);
    writeDb(db);
  }
  next();
});

/* ============================================================
   PAGES (MUST be before express.static)
   ============================================================ */

app.get("/", (req, res) => {
  if (!req.session || !req.session.userId) return res.redirect("/login");
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/index.html", (req, res) => {
  if (!req.session || !req.session.userId) return res.redirect("/login");
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));

app.get("/admin", requireRolePage("admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html")),
);
app.get("/admin.html", requireRolePage("admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html")),
);

app.get("/mod", requireRolePage("mod", "admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "mod.html")),
);
app.get("/mod.html", requireRolePage("mod", "admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "mod.html")),
);

// static AFTER protected page routes
app.use(
  express.static(path.join(__dirname, "public"), {
    extensions: ["html"],
    index: false,
  }),
);

// bootstrap admin
function ensureBootstrapAdmin() {
  const db = readDb();
  const hasAdmin = db.users.some((u) => u.role === "admin");
  if (hasAdmin) return;

  const fullName = process.env.BOOTSTRAP_ADMIN_FULLNAME || "Site Admin";
  const username = (process.env.BOOTSTRAP_ADMIN_USERNAME || "admin").toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || "951212";
  const email = normalizeEmail(process.env.BOOTSTRAP_ADMIN_EMAIL || "");

  const passHash = bcrypt.hashSync(password, 10);
  const user = {
    id: safeId(),
    fullName,
    email,
    username,
    passHash,
    role: "admin",
    createdAt: now(),
    banned: false,
  };
  db.users.push(user);
  writeDb(db);
  console.log("[BOOTSTRAP] Created admin:", username);
}
ensureBootstrapAdmin();

/* ============================================================
   AUTH ROUTES
   ============================================================ */

// Canonical register
app.post("/api/auth/register", (req, res) => {
  // accept both: fullName OR name
  const fullName = String(req.body.fullName || req.body.name || "").trim();
  const email = normalizeEmail(req.body.email || "");
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (fullName.length < 2) return jsonError(res, 400, "Full name too short");

  if (email && !isValidEmail(email)) return jsonError(res, 400, "Invalid email");

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return jsonError(res, 400, "Username must be 3-20 chars: a-z 0-9 _");
  }

  if (password.length < 6) return jsonError(res, 400, "Password must be at least 6 chars");

  const db = readDb();

  if (db.users.some((u) => u.username === username)) {
    return jsonError(res, 409, "Username already taken");
  }

  if (email && db.users.some((u) => normalizeEmail(u.email) === email)) {
    return jsonError(res, 409, "Email already in use");
  }

  // Optional: auto-admin by env match (remove the env later for safety)
  // Set in Secrets: ADMIN_EMAIL=you@example.com
  let role = "user";
  const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL || "");
  const adminUsername = String(process.env.ADMIN_USERNAME || "").trim().toLowerCase();
  if (adminEmail && email && email === adminEmail) role = "admin";
  if (adminUsername && username === adminUsername) role = "admin";

  const passHash = bcrypt.hashSync(password, 10);
  const user = {
    id: safeId(),
    fullName,
    email,
    username,
    passHash,
    role,
    createdAt: now(),
    banned: false,
  };

  db.users.push(user);
  writeDb(db);

  res.json({ ok: true, role });
});

// Canonical login (username OR email)
app.post("/api/auth/login", (req, res) => {
  // accept both: username OR id OR email
  const rawId = String(req.body.username || req.body.id || req.body.email || "").trim();
  const password = String(req.body.password || "");

  if (!rawId) return jsonError(res, 400, "Missing username/email");
  if (!password) return jsonError(res, 400, "Missing password");

  const db = readDb();
  const idLower = rawId.toLowerCase();
  const idAsEmail = normalizeEmail(rawId);

  const user = db.users.find(
    (u) => u.username === idLower || (u.email && normalizeEmail(u.email) === idAsEmail),
  );

  if (!user) return jsonError(res, 401, "Invalid login");

  const userBanned = db.bans.some((b) => b.active && b.type === "user" && b.userId === user.id);
  if (userBanned || user.banned) return jsonError(res, 403, "Account is banned");

  const ok = bcrypt.compareSync(password, user.passHash);
  if (!ok) return jsonError(res, 401, "Invalid login");

  req.session.userId = user.id;

  res.json({
    ok: true,
    role: user.role,
    username: user.username,
    fullName: user.fullName,
  });
});

// logout + me
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) return res.json({ ok: true, loggedIn: false });
  const db = readDb();
  const me = db.users.find((u) => u.id === req.session.userId);
  if (!me) return res.json({ ok: true, loggedIn: false });
  res.json({
    ok: true,
    loggedIn: true,
    user: { id: me.id, username: me.username, fullName: me.fullName, role: me.role },
  });
});

// Aliases so older frontend paths work too
app.post("/api/register", (req, res) => res.redirect(307, "/api/auth/register"));
app.post("/api/login", (req, res) => res.redirect(307, "/api/auth/login"));

// Helpful “wrong method” messages
app.get("/api/auth/register", (req, res) => jsonError(res, 405, "Use POST /api/auth/register"));
app.get("/api/auth/login", (req, res) => jsonError(res, 405, "Use POST /api/auth/login"));

/* ============================================================
   ADMIN / LOGS (kept from your file, with email added)
   ============================================================ */

app.get("/api/admin/users", requireRole("admin"), (req, res) => {
  const db = readDb();
  const users = db.users.map((u) => ({
    id: u.id,
    fullName: u.fullName,
    email: u.email || "",
    username: u.username,
    role: u.role,
    createdAt: u.createdAt,
  }));
  res.json({ ok: true, users });
});

app.patch("/api/admin/users/:id/role", requireRole("admin"), (req, res) => {
  const role = String(req.body.role || "").toLowerCase();
  if (!["user", "mod", "admin"].includes(role)) return jsonError(res, 400, "Invalid role");

  const db = readDb();
  const u = db.users.find((x) => x.id === req.params.id);
  if (!u) return jsonError(res, 404, "User not found");

  u.role = role;
  writeDb(db);
  res.json({ ok: true });
});

app.post("/api/admin/password", requireRole("admin"), (req, res) => {
  const newPassword = String(req.body.newPassword || "");
  if (newPassword.length < 6) return jsonError(res, 400, "Password too short");
  const db = readDb();
  const me = db.users.find((u) => u.id === req.me.id);
  me.passHash = bcrypt.hashSync(newPassword, 10);
  writeDb(db);
  res.json({ ok: true });
});

app.get("/api/admin/visits", requireRole("admin"), (req, res) => {
  const db = readDb();
  const visits = db.visits.slice(0, 1500).map((v) => ({ ...v, ip: maskIp(v.ip) }));
  res.json({ ok: true, visits });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log("Backend running on http://localhost:" + port);
});
