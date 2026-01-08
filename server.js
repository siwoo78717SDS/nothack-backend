const fs = require("fs");
const path = require("path");
const express = require("express");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const bcrypt = require("bcryptjs");

/* ============================================================
   Helpers
   ============================================================ */

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

function now() {
  return Date.now();
}

function safeId() {
  return (
    "id_" +
    now().toString(36) +
    "_" +
    Math.random().toString(36).slice(2, 10)
  );
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function jsonError(res, status, msg) {
  return res.status(status).json({ ok: false, error: msg, message: msg });
}

/* ============================================================
   Storage (db.json)
   ============================================================ */

const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
const SESS_DIR = path.join(DATA_DIR, "sessions");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(SESS_DIR)) fs.mkdirSync(SESS_DIR, { recursive: true });

function readDb() {
  try {
    const db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));

    // Defaults / migrations
    if (!Array.isArray(db.users)) db.users = [];
    if (!Array.isArray(db.roleRequests)) db.roleRequests = [];
    if (!Array.isArray(db.visits)) db.visits = [];

    for (const u of db.users) {
      if (typeof u.email !== "string") u.email = "";
      if (!u.role) u.role = "user";
      if (typeof u.banned !== "boolean") u.banned = false;
      if (!u.createdAt) u.createdAt = now();
    }

    return db;
  } catch {
    return { users: [], roleRequests: [], visits: [] };
  }
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

/* ============================================================
   App + Session
   ============================================================ */

const app = express();
app.set("trust proxy", true);

app.use(express.json({ limit: "250kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    store: new FileStore({ path: SESS_DIR }),
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      // Good default: secure cookies in production (Render/HTTPS),
      // but still works on localhost.
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  }),
);

/* ============================================================
   Auth middleware
   ============================================================ */

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId)
    return jsonError(res, 401, "Not logged in");
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session || !req.session.userId)
      return jsonError(res, 401, "Not logged in");
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

/* ============================================================
   Visit log (optional / harmless)
   ============================================================ */

function getClientIp(req) {
  return String(req.ip || "").replace(/^::ffff:/, "");
}

app.use((req, res, next) => {
  const p = req.path || "/";
  if (!req.session._vis) req.session._vis = {};
  if (req.session._vis[p]) return next();
  req.session._vis[p] = true;

  const db = readDb();
  db.visits.unshift({
    id: safeId(),
    at: now(),
    ip: getClientIp(req),
    userId: req.session.userId || null,
    path: p,
    ua: String(req.headers["user-agent"] || "").slice(0, 200),
  });
  db.visits = db.visits.slice(0, 2500);
  writeDb(db);

  next();
});

/* ============================================================
   Pages (put BEFORE static)
   ============================================================ */

// Home (requires login; redirects to /login)
app.get("/", requireRolePage("user", "mod", "admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html")),
);

app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html")),
);

app.get("/register", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "register.html")),
);

// My Page (requires login; redirects to /login)
app.get("/account", requireRolePage("user", "mod", "admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "account.html")),
);

// Moderator page (Option A: mods can view tools, but cannot approve requests)
app.get("/mod", requireRolePage("mod", "admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "mod.html")),
);

// Real admin page (approval dashboard)
app.get("/admin", requireRolePage("admin"), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html")),
);

// Static files
app.use(
  express.static(path.join(__dirname, "public"), {
    extensions: ["html"],
    index: false,
  }),
);

/* ============================================================
   Bootstrap admin (creates an admin if none exists)
   ============================================================ */

function ensureBootstrapAdmin() {
  const db = readDb();
  const hasAdmin = db.users.some((u) => u.role === "admin");
  if (hasAdmin) return;

  const fullName = process.env.BOOTSTRAP_ADMIN_FULLNAME || "Site Admin";
  const username = String(
    process.env.BOOTSTRAP_ADMIN_USERNAME || "admin",
  ).trim().toLowerCase();
  const password = String(process.env.BOOTSTRAP_ADMIN_PASSWORD || "951212");
  const email = normalizeEmail(process.env.BOOTSTRAP_ADMIN_EMAIL || "");

  const passHash = bcrypt.hashSync(password, 10);
  db.users.push({
    id: safeId(),
    fullName,
    email,
    username,
    passHash,
    role: "admin",
    createdAt: now(),
    banned: false,
  });
  writeDb(db);

  console.log("[BOOTSTRAP] Created admin:", username);
}
ensureBootstrapAdmin();

/* ============================================================
   API: Auth
   ============================================================ */

app.post("/api/auth/register", (req, res) => {
  const fullName = String(req.body.fullName || req.body.name || "").trim();
  const email = normalizeEmail(req.body.email || "");
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (fullName.length < 2) return jsonError(res, 400, "Full name too short");
  if (email && !isValidEmail(email)) return jsonError(res, 400, "Invalid email");
  if (!/^[a-z0-9_]{3,20}$/.test(username))
    return jsonError(res, 400, "Username must be 3-20 chars: a-z 0-9 _");
  if (password.length < 6)
    return jsonError(res, 400, "Password must be at least 6 chars");

  const db = readDb();

  if (db.users.some((u) => u.username === username))
    return jsonError(res, 409, "Username already taken");

  if (email && db.users.some((u) => normalizeEmail(u.email) === email))
    return jsonError(res, 409, "Email already in use");

  // Optional auto-admin (NOT required; bootstrap handles it anyway)
  const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL || "");
  const adminUsername = String(process.env.ADMIN_USERNAME || "")
    .trim()
    .toLowerCase();
  let role = "user";
  if (adminEmail && email && email === adminEmail) role = "admin";
  if (adminUsername && username && username === adminUsername) role = "admin";

  const passHash = bcrypt.hashSync(password, 10);
  db.users.push({
    id: safeId(),
    fullName,
    email,
    username,
    passHash,
    role,
    createdAt: now(),
    banned: false,
  });
  writeDb(db);

  res.json({ ok: true, role });
});

app.post("/api/auth/login", (req, res) => {
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
  if (user.banned) return jsonError(res, 403, "Account is banned");

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
    user: {
      id: me.id,
      username: me.username,
      fullName: me.fullName,
      email: me.email || "",
      role: me.role,
    },
  });
});

// Legacy aliases (so old frontends still work)
app.post("/api/register", (req, res) => res.redirect(307, "/api/auth/register"));
app.post("/api/login", (req, res) => res.redirect(307, "/api/auth/login"));

/* ============================================================
   API: Account (change username / password)
   ============================================================ */

app.patch("/api/account/username", requireAuth, (req, res) => {
  const newUsername = String(req.body.username || "").trim().toLowerCase();
  const currentPassword = String(req.body.currentPassword || "");

  if (!/^[a-z0-9_]{3,20}$/.test(newUsername))
    return jsonError(res, 400, "Username must be 3-20 chars: a-z 0-9 _");
  if (!currentPassword) return jsonError(res, 400, "Missing current password");

  const db = readDb();
  const me = db.users.find((u) => u.id === req.session.userId);
  if (!me) return jsonError(res, 401, "Not logged in");

  if (!bcrypt.compareSync(currentPassword, me.passHash))
    return jsonError(res, 401, "Wrong password");

  if (db.users.some((u) => u.username === newUsername && u.id !== me.id))
    return jsonError(res, 409, "Username already taken");

  me.username = newUsername;
  writeDb(db);

  res.json({ ok: true, username: me.username });
});

app.patch("/api/account/password", requireAuth, (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");

  if (!currentPassword) return jsonError(res, 400, "Missing current password");
  if (newPassword.length < 6)
    return jsonError(res, 400, "New password must be at least 6 chars");

  const db = readDb();
  const me = db.users.find((u) => u.id === req.session.userId);
  if (!me) return jsonError(res, 401, "Not logged in");

  if (!bcrypt.compareSync(currentPassword, me.passHash))
    return jsonError(res, 401, "Wrong password");

  me.passHash = bcrypt.hashSync(newPassword, 10);
  writeDb(db);

  res.json({ ok: true });
});

/* ============================================================
   API: Role Requests (user->mod, mod->admin)
   ============================================================ */

function nextRoleFor(role) {
  if (role === "user") return "mod";
  if (role === "mod") return "admin";
  return null;
}

function canRequestRole(db, userId) {
  const nowMs = now();

  // 1 pending at a time
  const pending = db.roleRequests.find(
    (r) => r.userId === userId && r.status === "pending",
  );
  if (pending) return { ok: false, error: "You already have a pending request." };

  // cooldown: 6 hours from last request
  const last = db.roleRequests
    .filter((r) => r.userId === userId)
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))[0];

  if (last && nowMs - (last.createdAt || 0) < 6 * 60 * 60 * 1000) {
    const mins = Math.ceil(
      (6 * 60 * 60 * 1000 - (nowMs - last.createdAt)) / 60000,
    );
    return { ok: false, error: `Cooldown active. Try again in ~${mins} min.` };
  }

  // max 3 requests per 7 days
  const weekAgo = nowMs - 7 * 24 * 60 * 60 * 1000;
  const weekCount = db.roleRequests.filter(
    (r) => r.userId === userId && (r.createdAt || 0) >= weekAgo,
  ).length;

  if (weekCount >= 3)
    return { ok: false, error: "Too many requests this week. Try later." };

  return { ok: true };
}

app.post("/api/roles/request", requireAuth, (req, res) => {
  const reason = String(req.body.reason || "").trim().slice(0, 500);

  const db = readDb();
  const me = db.users.find((u) => u.id === req.session.userId);
  if (!me) return jsonError(res, 401, "Not logged in");

  const toRole = nextRoleFor(me.role);
  if (!toRole) return jsonError(res, 400, "You cannot request a higher role.");

  const ok = canRequestRole(db, me.id);
  if (!ok.ok) return jsonError(res, 429, ok.error);

  const reqObj = {
    id: safeId(),
    userId: me.id,
    fromRole: me.role,
    toRole,
    reason,
    status: "pending", // pending | approved | rejected
    createdAt: now(),
    decidedAt: null,
    decidedBy: null,
    decisionNote: "",
  };

  db.roleRequests.unshift(reqObj);
  writeDb(db);

  res.json({ ok: true, request: reqObj });
});

app.get("/api/roles/my-requests", requireAuth, (req, res) => {
  const db = readDb();
  const list = db.roleRequests
    .filter((r) => r.userId === req.session.userId)
    .slice(0, 50);
  res.json({ ok: true, requests: list });
});

/* ============================================================
   API: Admin role requests (approve/reject + history)
   Option A: admin-only
   ============================================================ */

app.get("/api/admin/role-requests", requireRole("admin"), (req, res) => {
  const status = String(req.query.status || "pending").toLowerCase(); // pending|approved|rejected|all
  const db = readDb();

  let list = db.roleRequests;
  if (status !== "all") list = list.filter((r) => r.status === status);

  const usersById = Object.fromEntries(db.users.map((u) => [u.id, u]));
  const out = list.slice(0, 200).map((r) => {
    const u = usersById[r.userId] || {};
    return {
      ...r,
      user: {
        id: u.id || r.userId,
        username: u.username || "(unknown)",
        fullName: u.fullName || "(unknown)",
        role: u.role || r.fromRole,
      },
    };
  });

  res.json({ ok: true, requests: out });
});

app.get(
  "/api/admin/role-requests/pending-count",
  requireRole("admin"),
  (req, res) => {
    const db = readDb();
    const n = db.roleRequests.filter((r) => r.status === "pending").length;
    res.json({ ok: true, pendingCount: n });
  },
);

app.post(
  "/api/admin/role-requests/:id/decide",
  requireRole("admin"),
  (req, res) => {
    const decision = String(req.body.decision || "").toLowerCase(); // approve|reject
    const note = String(req.body.note || "").trim().slice(0, 300);

    if (!["approve", "reject"].includes(decision))
      return jsonError(res, 400, "Invalid decision");

    const db = readDb();
    const r = db.roleRequests.find((x) => x.id === req.params.id);
    if (!r) return jsonError(res, 404, "Request not found");
    if (r.status !== "pending")
      return jsonError(res, 400, "Request is not pending");

    const targetUser = db.users.find((u) => u.id === r.userId);
    if (!targetUser) return jsonError(res, 404, "User not found");

    r.status = decision === "approve" ? "approved" : "rejected";
    r.decidedAt = now();
    r.decidedBy = req.me.id;
    r.decisionNote = note;

    if (decision === "approve") {
      // Only allow intended upgrade path
      const expected = nextRoleFor(targetUser.role);
      if (expected !== r.toRole)
        return jsonError(res, 400, "User role changed; request no longer valid.");

      targetUser.role = r.toRole;
    }

    writeDb(db);
    res.json({ ok: true });
  },
);

/* ============================================================
   Admin users list (optional)
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

/* ============================================================
   Health
   ============================================================ */

app.get("/api/health", (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log("Server running on http://localhost:" + port);
});
