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
  return (
    "id_" +
    now().toString(36) +
    "_" +
    Math.random().toString(36).slice(2, 9)
  );
}

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    return {
      users: [],
      factsApproved: [],
      factsSubmissions: [],

      // bans: keep structure, but we will not expose full IPs or enable IP bans by default
      bans: [], // {id,type:'user'|'ip', userId?, ip?, reason, createdAt, createdBy, active:true}
      banRequests: [], // {id, targetType, userId?, ip?, reason, createdAt, createdBy, status:'pending'|'approved'|'rejected', decidedAt?, decidedBy?}

      visits: [], // {id, ip, userId?, userAgent, at, path}
      commandLogs: [], // {id, userId, ip, at, command}
      controlAudit: [], // {id, byUserId, target, payload, at}
    };
  }
}
function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

function getClientIp(req) {
  // express will respect trust proxy, req.ip is fine, but normalize
  return String(req.ip || "").replace(/^::ffff:/, "");
}

function maskIp(ip) {
  const s = String(ip || "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    const p = s.split(".");
    return `${p[0]}.${p[1]}.${p[2]}.xxx`;
  }
  if (s.includes(":")) {
    // very rough IPv6 mask
    return s.split(":").slice(0, 3).join(":") + "::xxxx";
  }
  return "";
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId)
    return res.status(401).json({ ok: false, error: "Not logged in" });
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    const db = readDb();
    const me = db.users.find((u) => u.id === req.session.userId);
    if (!me) return res.status(401).json({ ok: false, error: "Not logged in" });
    if (!roles.includes(me.role))
      return res.status(403).json({ ok: false, error: "Forbidden" });
    req.me = me;
    next();
  };
}

// For HTML page routes: redirect instead of returning JSON
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
      secure: false, // set true behind https
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  }),
);

/**
 * IP bans: disabled by default.
 * If you truly need them for your own private testing, set:
 *   ENABLE_IP_BANS=true
 * but note: IP bans are unreliable + can harm innocent users (shared networks).
 */
app.use((req, res, next) => {
  if (String(process.env.ENABLE_IP_BANS || "").toLowerCase() !== "true") {
    return next();
  }
  const db = readDb();
  const ip = getClientIp(req);
  const ipBanned = db.bans.some((b) => b.active && b.type === "ip" && b.ip === ip);
  if (ipBanned) return res.status(403).send("This IP is banned.");
  next();
});

// visit log for main pages + static assets
app.use((req, res, next) => {
  // log only once per session per path group to reduce spam
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
   ✅ PAGES (THIS IS THE “RIGHT PLACE” TO ADD 2) + 3))
   Put BEFORE express.static so admin/mod pages can be protected.
   ============================================================ */

// Protect the homepage (terminal)
app.get("/", (req, res) => {
  if (!req.session || !req.session.userId) return res.redirect("/login");
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Also protect direct access to /index.html
app.get("/index.html", (req, res) => {
  if (!req.session || !req.session.userId) return res.redirect("/login");
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Nice routes for your buttons (/login and /register)
app.get("/login", (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.get("/register", (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Protect admin/mod pages (must be BEFORE express.static)
app.get("/admin", requireRolePage("admin"), (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.get("/admin.html", requireRolePage("admin"), (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/mod", requireRolePage("mod", "admin"), (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "mod.html"));
});
app.get("/mod.html", requireRolePage("mod", "admin"), (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "mod.html"));
});

// static (after protected routes)
app.use(
  express.static(path.join(__dirname, "public"), {
    extensions: ["html"],
    index: false,
  }),
);

// ---- bootstrap admin if needed ----
function ensureBootstrapAdmin() {
  const db = readDb();
  const hasAdmin = db.users.some((u) => u.role === "admin");
  if (hasAdmin) return;
  const fullName = process.env.BOOTSTRAP_ADMIN_FULLNAME || "Site Admin";
  const username = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || "951212";
  const passHash = bcrypt.hashSync(password, 10);
  const user = {
    id: safeId(),
    fullName,
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

// ---- auth routes ----
app.post("/api/auth/register", (req, res) => {
  const fullName = String(req.body.fullName || "").trim();
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (fullName.length < 2)
    return res.status(400).json({ ok: false, error: "Full name too short" });
  if (!/^[a-z0-9_]{3,20}$/.test(username))
    return res.status(400).json({
      ok: false,
      error: "Username must be 3-20 chars: a-z 0-9 _",
    });
  if (password.length < 6)
    return res
      .status(400)
      .json({ ok: false, error: "Password must be at least 6 chars" });

  const db = readDb();
  if (db.users.some((u) => u.username === username)) {
    return res.status(409).json({ ok: false, error: "Username already taken" });
  }

  const passHash = bcrypt.hashSync(password, 10);
  const user = {
    id: safeId(),
    fullName,
    username,
    passHash,
    role: "user",
    createdAt: now(),
    banned: false,
  };
  db.users.push(user);
  writeDb(db);

  res.json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const db = readDb();
  const user = db.users.find((u) => u.username === username);
  if (!user) return res.status(401).json({ ok: false, error: "Invalid login" });

  // account ban (by user)
  const userBanned = db.bans.some(
    (b) => b.active && b.type === "user" && b.userId === user.id,
  );
  if (userBanned || user.banned)
    return res.status(403).json({ ok: false, error: "Account is banned" });

  const ok = bcrypt.compareSync(password, user.passHash);
  if (!ok) return res.status(401).json({ ok: false, error: "Invalid login" });

  req.session.userId = user.id;
  res.json({
    ok: true,
    role: user.role,
    username: user.username,
    fullName: user.fullName,
  });
});

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

// ---- facts ----
// Anyone can read (approved only)
app.get("/api/facts", (req, res) => {
  const db = readDb();
  res.json({ ok: true, facts: db.factsApproved });
});

// Mods can submit facts (pending)
app.post("/api/facts/submit", requireRole("mod", "admin"), (req, res) => {
  const text = String(req.body.text || "").trim();
  if (!text) return res.status(400).json({ ok: false, error: "Missing text" });

  const db = readDb();
  db.factsSubmissions.unshift({
    id: safeId(),
    text,
    status: "pending",
    submittedAt: now(),
    submittedBy: req.me.id,
  });
  db.factsSubmissions = db.factsSubmissions.slice(0, 5000);
  writeDb(db);
  res.json({ ok: true });
});

// Admin approves/rejects facts
app.get("/api/admin/facts/pending", requireRole("admin"), (req, res) => {
  const db = readDb();
  res.json({ ok: true, pending: db.factsSubmissions.filter((f) => f.status === "pending") });
});

app.post("/api/admin/facts/:id/approve", requireRole("admin"), (req, res) => {
  const db = readDb();
  const sub = db.factsSubmissions.find((f) => f.id === req.params.id);
  if (!sub) return res.status(404).json({ ok: false, error: "Not found" });
  if (sub.status !== "pending") return res.status(400).json({ ok: false, error: "Not pending" });

  sub.status = "approved";
  sub.decidedAt = now();
  sub.decidedBy = req.me.id;

  db.factsApproved.unshift({
    id: safeId(),
    text: sub.text,
    approvedAt: sub.decidedAt,
    approvedBy: sub.decidedBy,
  });
  db.factsApproved = db.factsApproved.slice(0, 10000);
  writeDb(db);
  res.json({ ok: true });
});

app.post("/api/admin/facts/:id/reject", requireRole("admin"), (req, res) => {
  const db = readDb();
  const sub = db.factsSubmissions.find((f) => f.id === req.params.id);
  if (!sub) return res.status(404).json({ ok: false, error: "Not found" });
  if (sub.status !== "pending") return res.status(400).json({ ok: false, error: "Not pending" });

  sub.status = "rejected";
  sub.decidedAt = now();
  sub.decidedBy = req.me.id;
  writeDb(db);
  res.json({ ok: true });
});

// ---- telemetry / usage record ----
app.post("/api/telemetry/command", requireAuth, (req, res) => {
  const cmd = String(req.body.command || "").slice(0, 300);
  if (!cmd.trim()) return res.status(400).json({ ok: false, error: "Missing command" });

  const db = readDb();
  const ip = getClientIp(req);
  db.commandLogs.unshift({ id: safeId(), userId: req.session.userId, ip, at: now(), command: cmd });
  db.commandLogs = db.commandLogs.slice(0, 20000);
  writeDb(db);
  res.json({ ok: true });
});

// ---- bans ----
// SAFE: only allow ban requests by USER (not raw IP)
app.post("/api/mod/ban/request", requireRole("mod", "admin"), (req, res) => {
  const targetType = String(req.body.targetType || "").toLowerCase(); // only 'user'
  const reason = String(req.body.reason || "").trim().slice(0, 400);
  const userId = req.body.userId ? String(req.body.userId).trim() : null;

  if (targetType !== "user") {
    return res.status(400).json({ ok: false, error: "targetType must be user" });
  }
  if (!reason) return res.status(400).json({ ok: false, error: "Reason required" });
  if (!userId) return res.status(400).json({ ok: false, error: "userId required" });

  const db = readDb();
  db.banRequests.unshift({
    id: safeId(),
    targetType,
    userId,
    ip: null,
    reason,
    createdAt: now(),
    createdBy: req.me.id,
    status: "pending",
  });
  db.banRequests = db.banRequests.slice(0, 5000);
  writeDb(db);
  res.json({ ok: true });
});

app.get("/api/admin/ban/requests", requireRole("admin"), (req, res) => {
  const db = readDb();
  res.json({ ok: true, pending: db.banRequests.filter((r) => r.status === "pending") });
});

app.post("/api/admin/ban/:id/approve", requireRole("admin"), (req, res) => {
  const db = readDb();
  const r = db.banRequests.find((x) => x.id === req.params.id);
  if (!r) return res.status(404).json({ ok: false, error: "Not found" });
  if (r.status !== "pending") return res.status(400).json({ ok: false, error: "Not pending" });
  if (r.targetType !== "user") return res.status(400).json({ ok: false, error: "Only user bans allowed" });

  r.status = "approved";
  r.decidedAt = now();
  r.decidedBy = req.me.id;

  const ban = {
    id: safeId(),
    type: "user",
    userId: r.userId,
    ip: null,
    reason: r.reason,
    createdAt: r.decidedAt,
    createdBy: r.decidedBy,
    active: true,
  };
  db.bans.unshift(ban);
  db.bans = db.bans.slice(0, 10000);
  writeDb(db);
  res.json({ ok: true });
});

app.post("/api/admin/ban/:id/reject", requireRole("admin"), (req, res) => {
  const db = readDb();
  const r = db.banRequests.find((x) => x.id === req.params.id);
  if (!r) return res.status(404).json({ ok: false, error: "Not found" });
  if (r.status !== "pending") return res.status(400).json({ ok: false, error: "Not pending" });

  r.status = "rejected";
  r.decidedAt = now();
  r.decidedBy = req.me.id;
  writeDb(db);
  res.json({ ok: true });
});

// ---- users / roles ----
app.get("/api/admin/users", requireRole("admin"), (req, res) => {
  const db = readDb();
  const users = db.users.map((u) => ({
    id: u.id,
    fullName: u.fullName,
    username: u.username,
    role: u.role,
    createdAt: u.createdAt,
  }));
  res.json({ ok: true, users });
});

app.patch("/api/admin/users/:id/role", requireRole("admin"), (req, res) => {
  const role = String(req.body.role || "").toLowerCase();
  if (!["user", "mod", "admin"].includes(role))
    return res.status(400).json({ ok: false, error: "Invalid role" });

  const db = readDb();
  const u = db.users.find((x) => x.id === req.params.id);
  if (!u) return res.status(404).json({ ok: false, error: "User not found" });

  u.role = role;
  writeDb(db);
  res.json({ ok: true });
});

app.post("/api/admin/password", requireRole("admin"), (req, res) => {
  const newPassword = String(req.body.newPassword || "");
  if (newPassword.length < 6)
    return res.status(400).json({ ok: false, error: "Password too short" });
  const db = readDb();
  const me = db.users.find((u) => u.id === req.me.id);
  me.passHash = bcrypt.hashSync(newPassword, 10);
  writeDb(db);
  res.json({ ok: true });
});

// ---- visits + logs for admin review (MASKED IPs) ----
app.get("/api/admin/visits", requireRole("admin"), (req, res) => {
  const db = readDb();
  const visits = db.visits.slice(0, 1500).map((v) => ({
    ...v,
    ip: maskIp(v.ip),
  }));
  res.json({ ok: true, visits });
});

app.get("/api/admin/commands", requireRole("admin"), (req, res) => {
  const db = readDb();
  const commands = db.commandLogs.slice(0, 2000).map((c) => ({
    ...c,
    ip: maskIp(c.ip),
  }));
  res.json({ ok: true, commands });
});

// ---- Remote control (SSE) ----
const streams = new Map(); // clientId -> res

app.get("/api/control/stream", (req, res) => {
  const clientId = String(req.query.clientId || "").trim() || safeId();
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders && res.flushHeaders();

  streams.set(clientId, res);

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, clientId })}\n\n`);

  req.on("close", () => {
    streams.delete(clientId);
  });
});

app.post("/api/control/send", requireRole("admin"), (req, res) => {
  const target = String(req.body.target || "").trim(); // 'all' or clientId
  const payload = req.body.payload || null;
  if (!target) return res.status(400).json({ ok: false, error: "Missing target" });

  const msg = `event: control\ndata: ${JSON.stringify(payload)}\n\n`;

  if (target === "all") {
    for (const [, r] of streams) r.write(msg);
  } else {
    const r = streams.get(target);
    if (!r) return res.status(404).json({ ok: false, error: "Client not connected" });
    r.write(msg);
  }

  const db = readDb();
  db.controlAudit.unshift({ id: safeId(), byUserId: req.me.id, target, payload, at: now() });
  db.controlAudit = db.controlAudit.slice(0, 5000);
  writeDb(db);

  res.json({ ok: true });
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ---- start ----
const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log("ZeroPoint backend running on http://localhost:" + port);
});
