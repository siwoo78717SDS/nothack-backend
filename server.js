const fs = require("fs");
const path = require("path");
const express = require("express");
const session = require("express-session");
const FileStoreFactory = require("session-file-store");
const bcrypt = require("bcryptjs");

const app = express();
app.set("trust proxy", 1);

/* ============================================================
   Paths + storage
   ============================================================ */

const DATA_PATH = path.join(__dirname, "db.json");
const SESS_DIR = path.join(__dirname, "sessions");
if (!fs.existsSync(SESS_DIR)) fs.mkdirSync(SESS_DIR, { recursive: true });

function readDB() {
  try {
    const raw = fs.readFileSync(DATA_PATH, "utf8");
    const db = JSON.parse(raw);
    db.users ||= [];
    db.roleRequests ||= [];
    return db;
  } catch (e) {
    return { users: [], roleRequests: [] };
  }
}

function writeDB(db) {
  fs.writeFileSync(DATA_PATH, JSON.stringify(db, null, 2), "utf8");
}

function nowISO() {
  return new Date().toISOString();
}

function nextId(prefix = "id") {
  return (
    prefix +
    "_" +
    Math.random().toString(36).slice(2, 10) +
    "_" +
    Date.now().toString(36)
  );
}

function normalizeUsername(u) {
  return String(u || "").trim();
}

function usernameKey(u) {
  return normalizeUsername(u).toLowerCase();
}

function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, createdAt: u.createdAt };
}

/* ============================================================
   Auth middleware (API)
   ============================================================ */

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}

function requireAdmin(req, res, next) {
  const db = readDB();
  const u = db.users.find((x) => x.id === req.session.userId);
  if (!u) return res.status(401).json({ error: "Not logged in" });
  if (u.role !== "admin") return res.status(403).json({ error: "Admin only" });
  req.me = u;
  next();
}

/* ============================================================
   Auth middleware (Pages)
   ============================================================ */

function requireRolePage(roles = []) {
  return (req, res, next) => {
    if (!req.session.userId) return res.redirect("/login");
    const db = readDB();
    const me = db.users.find((u) => u.id === req.session.userId);
    if (!me) return res.redirect("/login");
    if (!roles.includes(me.role)) return res.status(403).send("Forbidden");
    req.me = me;
    next();
  };
}

/* ============================================================
   Bootstrap admin
   ============================================================ */

function ensureBootstrapAdmin() {
  const db = readDB();
  const adminUsername = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
  const adminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || "951212";

  const hasAdmin = db.users.some((u) => u.role === "admin");
  if (hasAdmin) return;

  const username = normalizeUsername(adminUsername);
  const key = usernameKey(username);

  if (!username || adminPassword.length < 6) {
    console.warn("[bootstrap] Missing/weak BOOTSTRAP admin credentials; skipping.");
    return;
  }

  // Upgrade existing user if same username exists
  const existing = db.users.find((u) => usernameKey(u.username) === key);
  if (existing) {
    existing.role = "admin";
    writeDB(db);
    console.log("[bootstrap] Upgraded existing user to admin:", existing.username);
    return;
  }

  const passHash = bcrypt.hashSync(adminPassword, 10);
  const u = {
    id: nextId("u"),
    username,
    passHash,
    role: "admin",
    createdAt: nowISO(),
  };
  db.users.push(u);
  writeDB(db);
  console.log("[bootstrap] Created admin user:", username);
}

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false }));

const FileStore = FileStoreFactory(session);
app.use(
  session({
    store: new FileStore({
      path: SESS_DIR,
      retries: 0,
    }),
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  }),
);

ensureBootstrapAdmin();

/* ============================================================
   Page routes (BEFORE static so auth cannot be bypassed)
   ============================================================ */

// Public home page (you can keep it public so people can see it)
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/index.html", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/register.html", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "register.html")),
);

// Protected pages (also protect direct .html access)
app.get(
  ["/account", "/account.html"],
  requireRolePage(["user", "mod", "admin"]),
  (req, res) => res.sendFile(path.join(__dirname, "public", "account.html")),
);

app.get(["/admin", "/admin.html"], requireRolePage(["admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html")),
);

app.get(["/mod", "/mod.html"], requireRolePage(["mod", "admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "mod.html")),
);

/* ============================================================
   Static assets (AFTER routes)
   ============================================================ */

app.use(express.static(path.join(__dirname, "public")));

/* ============================================================
   API: Auth
   ============================================================ */

app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) return res.status(200).json({ loggedIn: false });
  const db = readDB();
  const u = db.users.find((x) => x.id === req.session.userId);
  if (!u) return res.status(200).json({ loggedIn: false });
  return res.status(200).json({ loggedIn: true, user: publicUser(u) });
});

app.post("/api/auth/register", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  if (!username || username.length < 3 || username.length > 24) {
    return res.status(400).json({ error: "Username must be 3-24 characters." });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res
      .status(400)
      .json({ error: "Username can only use letters, numbers, underscore." });
  }
  if (password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: "Password must be 6-128 characters." });
  }

  const db = readDB();
  const key = usernameKey(username);
  if (db.users.some((u) => usernameKey(u.username) === key)) {
    return res.status(409).json({ error: "Username already taken." });
  }

  const passHash = bcrypt.hashSync(password, 10);
  const u = { id: nextId("u"), username, passHash, role: "user", createdAt: nowISO() };
  db.users.push(u);
  writeDB(db);

  req.session.userId = u.id;
  return res.status(201).json({ ok: true, user: publicUser(u) });
});

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  const db = readDB();
  const u = db.users.find((x) => usernameKey(x.username) === usernameKey(username));
  if (!u) return res.status(401).json({ error: "Invalid username or password." });

  const ok = bcrypt.compareSync(password, u.passHash);
  if (!ok) return res.status(401).json({ error: "Invalid username or password." });

  req.session.userId = u.id;
  return res.status(200).json({ ok: true, user: publicUser(u) });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

/* ============================================================
   API: Account
   ============================================================ */

app.post("/api/account/change-username", requireAuth, (req, res) => {
  const newUsername = normalizeUsername(req.body.newUsername);
  const currentPassword = String(req.body.currentPassword || "");

  if (!newUsername || newUsername.length < 3 || newUsername.length > 24) {
    return res.status(400).json({ error: "Username must be 3-24 characters." });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(newUsername)) {
    return res
      .status(400)
      .json({ error: "Username can only use letters, numbers, underscore." });
  }

  const db = readDB();
  const u = db.users.find((x) => x.id === req.session.userId);
  if (!u) return res.status(401).json({ error: "Not logged in" });

  const ok = bcrypt.compareSync(currentPassword, u.passHash);
  if (!ok) return res.status(401).json({ error: "Wrong current password." });

  const key = usernameKey(newUsername);
  if (db.users.some((x) => x.id !== u.id && usernameKey(x.username) === key)) {
    return res.status(409).json({ error: "Username already taken." });
  }

  u.username = newUsername;
  writeDB(db);
  return res.status(200).json({ ok: true, user: publicUser(u) });
});

app.post("/api/account/change-password", requireAuth, (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");

  if (newPassword.length < 6 || newPassword.length > 128) {
    return res.status(400).json({ error: "New password must be 6-128 characters." });
  }

  const db = readDB();
  const u = db.users.find((x) => x.id === req.session.userId);
  if (!u) return res.status(401).json({ error: "Not logged in" });

  const ok = bcrypt.compareSync(currentPassword, u.passHash);
  if (!ok) return res.status(401).json({ error: "Wrong current password." });

  u.passHash = bcrypt.hashSync(newPassword, 10);
  writeDB(db);
  return res.status(200).json({ ok: true });
});

/* ============================================================
   Role requests (Option A approvals: admin only)
   Upgrade path only:
     user -> mod
     mod  -> admin
   ============================================================ */

function roleRank(role) {
  if (role === "user") return 0;
  if (role === "mod") return 1;
  if (role === "admin") return 2;
  return -1;
}

function nextRoleFor(role) {
  if (role === "user") return "mod";
  if (role === "mod") return "admin";
  return null;
}

app.post("/api/requests/role", requireAuth, (req, res) => {
  const db = readDB();
  const u = db.users.find((x) => x.id === req.session.userId);
  if (!u) return res.status(401).json({ error: "Not logged in" });

  const requestedRole = String(req.body.role || "").toLowerCase();
  const expected = nextRoleFor(u.role);

  // Enforce upgrade path only
  if (!expected) {
    return res.status(400).json({ error: "You cannot request a higher role." });
  }
  if (requestedRole !== expected) {
    return res
      .status(400)
      .json({ error: `You can only request: ${expected}` });
  }

  const now = Date.now();

  // Only 1 pending at a time
  const pending = db.roleRequests.find((r) => r.userId === u.id && r.status === "pending");
  if (pending) return res.status(409).json({ error: "You already have a pending request." });

  // Cooldown: 6 hours
  const last = db.roleRequests
    .filter((r) => r.userId === u.id)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];

  if (last) {
    const lastTime = new Date(last.createdAt).getTime();
    const cooldownMs = 6 * 60 * 60 * 1000;
    if (now - lastTime < cooldownMs) {
      const mins = Math.ceil((cooldownMs - (now - lastTime)) / 60000);
      return res
        .status(429)
        .json({ error: `Please wait ${mins} more minutes before requesting again.` });
    }
  }

  // Weekly limit: max 3 per 7 days
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const recentCount = db.roleRequests.filter(
    (r) => r.userId === u.id && now - new Date(r.createdAt).getTime() < weekMs,
  ).length;
  if (recentCount >= 3) {
    return res.status(429).json({ error: "Too many requests. Try again later." });
  }

  const reqObj = {
    id: nextId("req"),
    userId: u.id,
    usernameAtTime: u.username,
    requestedRole,
    status: "pending",
    createdAt: nowISO(),
    decidedAt: null,
    decidedBy: null,
    reason: null,
  };

  db.roleRequests.push(reqObj);
  writeDB(db);
  return res.status(201).json({ ok: true, request: reqObj });
});

// (Optional but useful) user can see their own requests
app.get("/api/requests/my", requireAuth, (req, res) => {
  const db = readDB();
  const list = db.roleRequests
    .filter((r) => r.userId === req.session.userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 50);
  return res.json({ ok: true, requests: list });
});

/* ============================================================
   Admin request listing + decisions (admin only)
   ============================================================ */

app.get("/api/admin/requests", requireAdmin, (req, res) => {
  const status = String(req.query.status || "pending").toLowerCase();
  const db = readDB();

  let list = db.roleRequests.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  if (["pending", "approved", "rejected"].includes(status)) {
    list = list.filter((r) => r.status === status);
  }
  return res.json({ ok: true, requests: list });
});

app.get("/api/admin/requests/pending-count", requireAdmin, (req, res) => {
  const db = readDB();
  const n = db.roleRequests.filter((r) => r.status === "pending").length;
  return res.json({ ok: true, pendingCount: n });
});

app.post("/api/admin/requests/:id/approve", requireAdmin, (req, res) => {
  const id = req.params.id;
  const db = readDB();

  const adminUser = db.users.find((u) => u.id === req.session.userId);
  const r = db.roleRequests.find((x) => x.id === id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.status !== "pending") return res.status(400).json({ error: "Already decided" });

  const u = db.users.find((x) => x.id === r.userId);
  if (!u) return res.status(404).json({ error: "User not found" });

  // If user already has role/higher, approve but don't change role
  if (roleRank(r.requestedRole) <= roleRank(u.role)) {
    r.status = "approved";
    r.decidedAt = nowISO();
    r.decidedBy = adminUser ? adminUser.username : "admin";
    r.reason = "Auto-approved (already had role/higher).";
    writeDB(db);
    return res.json({ ok: true, request: r, user: publicUser(u) });
  }

  u.role = r.requestedRole;
  r.status = "approved";
  r.decidedAt = nowISO();
  r.decidedBy = adminUser ? adminUser.username : "admin";
  r.reason = String(req.body.reason || "") || null;

  writeDB(db);
  return res.json({ ok: true, request: r, user: publicUser(u) });
});

app.post("/api/admin/requests/:id/reject", requireAdmin, (req, res) => {
  const id = req.params.id;
  const db = readDB();

  const adminUser = db.users.find((u) => u.id === req.session.userId);
  const r = db.roleRequests.find((x) => x.id === id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.status !== "pending") return res.status(400).json({ error: "Already decided" });

  r.status = "rejected";
  r.decidedAt = nowISO();
  r.decidedBy = adminUser ? adminUser.username : "admin";
  r.reason = String(req.body.reason || "") || null;

  writeDB(db);
  return res.json({ ok: true, request: r });
});

/* ============================================================
   Health
   ============================================================ */

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("ZeroPoint server listening on port", PORT);
});
