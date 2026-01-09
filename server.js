// server.js (FREE-friendly: Render Free + MongoDB Atlas Free)
// Stores users/role requests in MongoDB (persistent) — no disks needed.
// Sessions are in-memory (they reset when the server sleeps/restarts on free tiers).

const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.set("trust proxy", 1);

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
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

/* =========================
   MongoDB
   ========================= */

const MONGODB_URI = process.env.MONGODB_URI; // REQUIRED
const MONGODB_DB = process.env.MONGODB_DB || "zeropoint";

if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI env var.");
}

const client = new MongoClient(MONGODB_URI || "mongodb://invalid");

let usersCol;
let roleReqCol;

function normalizeUsername(u) {
  return String(u || "").trim();
}

function usernameKey(u) {
  return normalizeUsername(u).toLowerCase();
}

function publicUser(u) {
  return {
    id: String(u._id),
    username: u.username,
    role: u.role,
    createdAt: u.createdAt ? u.createdAt.toISOString() : null,
  };
}

function nextRoleFor(role) {
  if (role === "user") return "mod";
  if (role === "mod") return "admin";
  return null;
}

function reqToClient(r) {
  return {
    id: String(r._id),
    userId: String(r.userId),
    usernameAtTime: r.usernameAtTime || null,
    requestedRole: r.requestedRole,
    status: r.status,
    createdAt: r.createdAt ? r.createdAt.toISOString() : null,
    decidedAt: r.decidedAt ? r.decidedAt.toISOString() : null,
    decidedBy: r.decidedBy || null,
    reason: r.reason || null,
  };
}

async function getUserBySession(req) {
  if (!req.session.userId) return null;
  try {
    const id = new ObjectId(req.session.userId);
    return await usersCol.findOne({ _id: id });
  } catch {
    return null;
  }
}

/* =========================
   Auth middleware
   ========================= */

function requireAuthApi() {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.status(401).json({ error: "Not logged in" });
    req.me = me;
    next();
  };
}

function requireModApi() {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.status(401).json({ error: "Not logged in" });
    if (me.role !== "mod" && me.role !== "admin") {
      return res.status(403).json({ error: "Mod/Admin only" });
    }
    req.me = me;
    next();
  };
}

function requireAdminApi() {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.status(401).json({ error: "Not logged in" });
    if (me.role !== "admin") return res.status(403).json({ error: "Admin only" });
    req.me = me;
    next();
  };
}

function requireRolePage(roles = []) {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.redirect("/login");
    if (!roles.includes(me.role)) return res.status(403).send("Forbidden");
    req.me = me;
    next();
  };
}

/* =========================
   Bootstrap admin
   ========================= */

async function ensureBootstrapAdmin() {
  const adminUsername = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
  const adminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || "951212";

  const hasAdmin = await usersCol.findOne({ role: "admin" });
  if (hasAdmin) return;

  const username = normalizeUsername(adminUsername);
  if (!username || String(adminPassword || "").length < 6) {
    console.warn("[bootstrap] Missing/weak admin credentials; skipping.");
    return;
  }

  const lower = usernameKey(username);
  const existing = await usersCol.findOne({ usernameLower: lower });

  if (existing) {
    await usersCol.updateOne({ _id: existing._id }, { $set: { role: "admin" } });
    console.log("[bootstrap] Upgraded existing user to admin:", existing.username);
    return;
  }

  const passHash = bcrypt.hashSync(adminPassword, 10);
  await usersCol.insertOne({
    username,
    usernameLower: lower,
    passHash,
    role: "admin",
    createdAt: new Date(),
  });

  console.log("[bootstrap] Created admin user:", username);
}

/* =========================
   Page routes (BEFORE static)
   ========================= */

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/index.html", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/register.html", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "register.html")),
);

app.get(
  ["/account", "/account.html"],
  requireRolePage(["user", "mod", "admin"]),
  (req, res) => res.sendFile(path.join(__dirname, "public", "account.html")),
);

app.get(
  ["/admin", "/admin.html"],
  requireRolePage(["admin"]),
  (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")),
);

app.get(
  ["/mod", "/mod.html"],
  requireRolePage(["mod", "admin"]),
  (req, res) => res.sendFile(path.join(__dirname, "public", "mod.html")),
);

// Static last so you can’t bypass protection by visiting /admin.html directly
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

/* =========================
   API: Auth
   ========================= */

app.get("/api/auth/me", async (req, res) => {
  const me = await getUserBySession(req);
  if (!me) return res.status(200).json({ loggedIn: false });
  return res.status(200).json({ loggedIn: true, user: publicUser(me) });
});

app.post("/api/auth/register", async (req, res) => {
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

  const lower = usernameKey(username);
  const exists = await usersCol.findOne({ usernameLower: lower });
  if (exists) return res.status(409).json({ error: "Username already taken." });

  const passHash = bcrypt.hashSync(password, 10);
  const result = await usersCol.insertOne({
    username,
    usernameLower: lower,
    passHash,
    role: "user",
    createdAt: new Date(),
  });

  req.session.userId = String(result.insertedId);
  const me = await usersCol.findOne({ _id: result.insertedId });
  return res.status(201).json({ ok: true, user: publicUser(me) });
});

app.post("/api/auth/login", async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  const lower = usernameKey(username);
  const u = await usersCol.findOne({ usernameLower: lower });
  if (!u) return res.status(401).json({ error: "Invalid username or password." });

  const ok = bcrypt.compareSync(password, u.passHash);
  if (!ok) return res.status(401).json({ error: "Invalid username or password." });

  req.session.userId = String(u._id);
  return res.status(200).json({ ok: true, user: publicUser(u) });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

/* =========================
   API: Account
   ========================= */

app.post("/api/account/change-username", requireAuthApi(), async (req, res) => {
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

  const ok = bcrypt.compareSync(currentPassword, req.me.passHash);
  if (!ok) return res.status(401).json({ error: "Wrong current password." });

  const lower = usernameKey(newUsername);
  const exists = await usersCol.findOne({
    usernameLower: lower,
    _id: { $ne: req.me._id },
  });
  if (exists) return res.status(409).json({ error: "Username already taken." });

  await usersCol.updateOne(
    { _id: req.me._id },
    { $set: { username: newUsername, usernameLower: lower } },
  );

  const me2 = await usersCol.findOne({ _id: req.me._id });
  return res.status(200).json({ ok: true, user: publicUser(me2) });
});

app.post("/api/account/change-password", requireAuthApi(), async (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");

  if (newPassword.length < 6 || newPassword.length > 128) {
    return res.status(400).json({ error: "New password must be 6-128 characters." });
  }

  const ok = bcrypt.compareSync(currentPassword, req.me.passHash);
  if (!ok) return res.status(401).json({ error: "Wrong current password." });

  const newHash = bcrypt.hashSync(newPassword, 10);
  await usersCol.updateOne({ _id: req.me._id }, { $set: { passHash: newHash } });

  return res.status(200).json({ ok: true });
});

/* =========================
   API: Role requests (upgrade path only)
   user -> mod -> admin
   ========================= */

app.post("/api/requests/role", requireAuthApi(), async (req, res) => {
  const requestedRole = String(req.body.role || "").toLowerCase();
  const expected = nextRoleFor(req.me.role);

  if (!expected) return res.status(400).json({ error: "You cannot request a higher role." });
  if (requestedRole !== expected) {
    return res.status(400).json({ error: `You can only request: ${expected}` });
  }

  // Only 1 pending request at a time
  const pending = await roleReqCol.findOne({ userId: req.me._id, status: "pending" });
  if (pending) return res.status(409).json({ error: "You already have a pending request." });

  const now = Date.now();

  // Cooldown: 6 hours between requests
  const lastArr = await roleReqCol
    .find({ userId: req.me._id })
    .sort({ createdAt: -1 })
    .limit(1)
    .toArray();

  if (lastArr[0]?.createdAt) {
    const lastTime = lastArr[0].createdAt.getTime();
    const cooldownMs = 6 * 60 * 60 * 1000;
    if (now - lastTime < cooldownMs) {
      const mins = Math.ceil((cooldownMs - (now - lastTime)) / 60000);
      return res.status(429).json({ error: `Please wait ${mins} more minutes.` });
    }
  }

  // Weekly limit: max 3 per 7 days
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const recentCount = await roleReqCol.countDocuments({
    userId: req.me._id,
    createdAt: { $gte: new Date(now - weekMs) },
  });
  if (recentCount >= 3) return res.status(429).json({ error: "Too many requests. Try later." });

  const doc = {
    userId: req.me._id,
    usernameAtTime: req.me.username,
    requestedRole,
    status: "pending",
    createdAt: new Date(),
    decidedAt: null,
    decidedBy: null,
    reason: null,
  };

  const result = await roleReqCol.insertOne(doc);
  const saved = await roleReqCol.findOne({ _id: result.insertedId });

  return res.status(201).json({ ok: true, request: reqToClient(saved) });
});

app.get("/api/requests/my", requireAuthApi(), async (req, res) => {
  const list = await roleReqCol
    .find({ userId: req.me._id })
    .sort({ createdAt: -1 })
    .limit(50)
    .toArray();

  return res.json({ ok: true, requests: list.map(reqToClient) });
});

/* =========================
   API: Mod (view-only)
   ========================= */

app.get("/api/mod/requests", requireModApi(), async (req, res) => {
  const status = String(req.query.status || "pending").toLowerCase();

  const filter = {};
  if (["pending", "approved", "rejected"].includes(status)) filter.status = status;
  // if status === "all" => no filter

  const list = await roleReqCol.find(filter).sort({ createdAt: -1 }).toArray();
  return res.json({ ok: true, requests: list.map(reqToClient) });
});

app.get("/api/mod/requests/pending-count", requireModApi(), async (req, res) => {
  const n = await roleReqCol.countDocuments({ status: "pending" });
  return res.json({ ok: true, pendingCount: n });
});

/* =========================
   API: Admin (approve/reject)
   ========================= */

app.get("/api/admin/requests", requireAdminApi(), async (req, res) => {
  const status = String(req.query.status || "pending").toLowerCase();

  const filter = {};
  if (["pending", "approved", "rejected"].includes(status)) filter.status = status;
  // if status === "all" => no filter

  const list = await roleReqCol.find(filter).sort({ createdAt: -1 }).toArray();
  return res.json({ ok: true, requests: list.map(reqToClient) });
});

app.get("/api/admin/requests/pending-count", requireAdminApi(), async (req, res) => {
  const n = await roleReqCol.countDocuments({ status: "pending" });
  return res.json({ ok: true, pendingCount: n });
});

app.post("/api/admin/requests/:id/approve", requireAdminApi(), async (req, res) => {
  let rid;
  try {
    rid = new ObjectId(req.params.id);
  } catch {
    return res.status(400).json({ error: "Bad request id" });
  }

  const r = await roleReqCol.findOne({ _id: rid });
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.status !== "pending") return res.status(400).json({ error: "Already decided" });

  const u = await usersCol.findOne({ _id: r.userId });
  if (!u) return res.status(404).json({ error: "User not found" });

  const expected = nextRoleFor(u.role);
  if (expected !== r.requestedRole) {
    await roleReqCol.updateOne(
      { _id: rid },
      {
        $set: {
          status: "rejected",
          decidedAt: new Date(),
          decidedBy: req.me.username,
          reason: "Rejected (role changed / request no longer valid).",
        },
      },
    );
    return res.status(400).json({ error: "User role changed; request no longer valid." });
  }

  await usersCol.updateOne({ _id: u._id }, { $set: { role: r.requestedRole } });

  await roleReqCol.updateOne(
    { _id: rid },
    {
      $set: {
        status: "approved",
        decidedAt: new Date(),
        decidedBy: req.me.username,
        reason: String(req.body.reason || "") || null,
      },
    },
  );

  const r2 = await roleReqCol.findOne({ _id: rid });
  const u2 = await usersCol.findOne({ _id: u._id });

  return res.json({ ok: true, request: reqToClient(r2), user: publicUser(u2) });
});

app.post("/api/admin/requests/:id/reject", requireAdminApi(), async (req, res) => {
  let rid;
  try {
    rid = new ObjectId(req.params.id);
  } catch {
    return res.status(400).json({ error: "Bad request id" });
  }

  const r = await roleReqCol.findOne({ _id: rid });
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.status !== "pending") return res.status(400).json({ error: "Already decided" });

  await roleReqCol.updateOne(
    { _id: rid },
    {
      $set: {
        status: "rejected",
        decidedAt: new Date(),
        decidedBy: req.me.username,
        reason: String(req.body.reason || "") || null,
      },
    },
  );

  const r2 = await roleReqCol.findOne({ _id: rid });
  return res.json({ ok: true, request: reqToClient(r2) });
});

/* =========================
   Health
   ========================= */

app.get("/api/health", (req, res) => res.json({ ok: true }));

/* =========================
   Start AFTER DB connect
   ========================= */

async function start() {
  await client.connect();
  const db = client.db(MONGODB_DB);

  usersCol = db.collection("users");
  roleReqCol = db.collection("role_requests");

  // Unique usernames (case-insensitive)
  await usersCol.createIndex({ usernameLower: 1 }, { unique: true });

  // Helpful indexes for requests
  await roleReqCol.createIndex({ status: 1, createdAt: -1 });
  await roleReqCol.createIndex({ userId: 1, createdAt: -1 });

  await ensureBootstrapAdmin();

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log("Server listening on port", PORT));
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
