const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.set("trust proxy", 1);

app.use(express.json({ limit: "500kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);

/* =========================
   MongoDB
   ========================= */
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "zeropoint";

if (!MONGODB_URI) console.warn("Missing MONGODB_URI env var.");

const client = new MongoClient(MONGODB_URI || "mongodb://invalid");

let dbReady = false;

let usersCol;
let devicesCol;
let commandsCol;
let commandLogsCol;
let visitsCol;
let ipBansCol;

let factsSubmissionsCol;
let factsApprovedCol;

let roleRequestsCol;
let banRequestsCol;

/* =========================
   Helpers
   ========================= */
function safeStr(x, max = 5000) {
  const s = String(x ?? "");
  return s.length > max ? s.slice(0, max) : s;
}
function normalizeUsername(u) {
  return String(u || "").trim();
}
function usernameKey(u) {
  return normalizeUsername(u).toLowerCase();
}
function normalizeFullName(n) {
  return String(n || "").trim();
}
function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.trim()) return xf.split(",")[0].trim();
  const ip = req.ip || "";
  // normalize ::ffff:127.0.0.1
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}
function publicUser(u) {
  return {
    id: String(u._id),
    fullName: u.fullName || "",
    username: u.username,
    role: u.role,
    banned: !!u.banned,
    banReason: u.banReason || null,
    createdAt: u.createdAt ? u.createdAt.toISOString() : null,
    coins: Number(u.coins || 0),
    features: u.features || {}
  };
}
async function getUserBySession(req) {
  if (!req.session.userId) return null;
  try {
    const id = new ObjectId(req.session.userId);
    const u = await usersCol.findOne({ _id: id });
    if (!u) return null;

    const sv = Number(req.session.sessionVersion || 0);
    const uv = Number(u.sessionVersion || 1);
    if (sv !== uv) {
      try { req.session.destroy(() => {}); } catch {}
      return null;
    }
    return u;
  } catch {
    return null;
  }
}
function requireAuthApi() {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.status(401).json({ error: "Not logged in" });
    if (me.banned) return res.status(403).json({ error: "Banned", reason: me.banReason || null });
    req.me = me;
    next();
  };
}
function requireRoleApi(roles = []) {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.status(401).json({ error: "Not logged in" });
    if (me.banned) return res.status(403).json({ error: "Banned", reason: me.banReason || null });
    if (!roles.includes(me.role)) return res.status(403).json({ error: "Forbidden" });
    req.me = me;
    next();
  };
}
function requireAdminApi() {
  return requireRoleApi(["admin"]);
}
function requireModApi() {
  return requireRoleApi(["mod", "admin"]);
}
function requireRolePage(roles = []) {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.redirect("/login");
    if (me.banned) return res.status(403).send("Banned");
    if (!roles.includes(me.role)) return res.status(403).send("Forbidden");
    req.me = me;
    next();
  };
}

/* =========================
   Bootstrap admin
   ========================= */
async function ensureBootstrapAdmin() {
  const adminUsername = process.env.BOOTSTRAP_ADMIN_USERNAME;
  const adminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  const adminFullName = process.env.BOOTSTRAP_ADMIN_FULLNAME || "Admin";

  if (!adminUsername || !adminPassword) {
    console.warn("[bootstrap] BOOTSTRAP_ADMIN_USERNAME/PASSWORD not set; skipping admin bootstrap.");
    return;
  }

  const hasAdmin = await usersCol.findOne({ role: "admin" });
  if (hasAdmin) return;

  const username = normalizeUsername(adminUsername);
  if (!username || String(adminPassword).length < 6) {
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

  const passHash = bcrypt.hashSync(String(adminPassword), 10);
  await usersCol.insertOne({
    fullName: normalizeFullName(adminFullName),
    username,
    usernameLower: lower,
    passHash,
    role: "admin",
    banned: false,
    banReason: null,
    sessionVersion: 1,
    coins: 999999999,
    features: { A: true, B: true, C: true },
    createdAt: new Date()
  });
  console.log("[bootstrap] Created admin user:", username);
}

/* =========================
   IP-ban middleware + visit logs
   ========================= */
app.use(async (req, res, next) => {
  if (!dbReady) return next();
  try {
    const ip = getClientIp(req);
    const ban = await ipBansCol.findOne({ ip });
    if (ban) return res.status(403).send("IP banned.");
  } catch {}
  next();
});

app.use(async (req, res, next) => {
  if (!dbReady) return next();

  // Record visits for HTML loads
  const accept = String(req.headers.accept || "");
  if (req.method === "GET" && accept.includes("text/html")) {
    try {
      const ip = getClientIp(req);
      const me = await getUserBySession(req);
      await visitsCol.insertOne({
        at: new Date(),
        ip,
        path: req.path,
        userId: me ? me._id : null,
        username: me ? me.username : null,
        ua: safeStr(req.headers["user-agent"] || "", 300)
      });
    } catch {}
  }
  next();
});

/* =========================
   SSE (device live connections)
   ========================= */
const liveByDeviceId = new Map(); // deviceId -> Set(res)

function sseSend(res, eventName, dataObj) {
  res.write(`event: ${eventName}\n`);
  res.write(`data: ${JSON.stringify(dataObj)}\n\n`);
}
function attachLive(deviceId, res) {
  if (!liveByDeviceId.has(deviceId)) liveByDeviceId.set(deviceId, new Set());
  liveByDeviceId.get(deviceId).add(res);
}
function detachLive(deviceId, res) {
  const set = liveByDeviceId.get(deviceId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) liveByDeviceId.delete(deviceId);
}
function broadcast(eventName, payload) {
  for (const [, set] of liveByDeviceId.entries()) {
    for (const res of set) sseSend(res, eventName, payload);
  }
}
function sendToDevice(deviceId, eventName, payload) {
  const set = liveByDeviceId.get(deviceId);
  if (!set) return 0;
  for (const res of set) sseSend(res, eventName, payload);
  return set.size;
}

/* =========================
   Pages
   ========================= */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/account", requireRolePage(["user", "mod", "admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "account.html"))
);
app.get("/admin", requireRolePage(["admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html"))
);
app.get("/mod", requireRolePage(["mod", "admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "mod.html"))
);

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

/* =========================
   Auth API (fullName + username + password)
   ========================= */
app.get("/api/auth/me", async (req, res) => {
  if (!dbReady) return res.json({ loggedIn: false });
  const me = await getUserBySession(req);
  if (!me) return res.json({ loggedIn: false });
  if (me.banned) return res.json({ loggedIn: false, banned: true, reason: me.banReason || null });
  return res.json({ loggedIn: true, user: publicUser(me) });
});

app.post("/api/auth/register", async (req, res) => {
  const fullName = normalizeFullName(req.body.fullName);
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  if (!fullName || fullName.length < 2 || fullName.length > 50) {
    return res.status(400).json({ error: "Full name must be 2-50 characters." });
  }
  if (!username || username.length < 3 || username.length > 24) {
    return res.status(400).json({ error: "Username must be 3-24 characters." });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: "Username can only use letters, numbers, underscore." });
  }
  if (password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: "Password must be 6-128 characters." });
  }

  const lower = usernameKey(username);
  const exists = await usersCol.findOne({ usernameLower: lower });
  if (exists) return res.status(409).json({ error: "Username already taken." });

  const passHash = bcrypt.hashSync(password, 10);
  const result = await usersCol.insertOne({
    fullName,
    username,
    usernameLower: lower,
    passHash,
    role: "user",
    banned: false,
    banReason: null,
    sessionVersion: 1,
    coins: 0,
    features: {},
    createdAt: new Date()
  });

  // auto-login after register
  req.session.userId = String(result.insertedId);
  req.session.sessionVersion = 1;

  return res.status(201).json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

  const u = await usersCol.findOne({ usernameLower: usernameKey(username) });
  if (!u) return res.status(401).json({ error: "Invalid username or password." });
  if (u.banned) return res.status(403).json({ error: "Banned", reason: u.banReason || null });

  const ok = bcrypt.compareSync(password, u.passHash);
  if (!ok) return res.status(401).json({ error: "Invalid username or password." });

  req.session.userId = String(u._id);
  req.session.sessionVersion = Number(u.sessionVersion || 1);

  return res.json({ ok: true, user: publicUser(u) });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

/* =========================
   Facts (anyone can read; mods submit; admins approve)
   ========================= */
app.get("/api/facts", async (req, res) => {
  const list = await factsApprovedCol.find({}).sort({ createdAt: -1 }).limit(300).toArray();
  res.json({
    ok: true,
    facts: list.map(f => ({
      id: String(f._id),
      text: f.text,
      createdAt: f.createdAt ? f.createdAt.toISOString() : null,
      approvedAt: f.approvedAt ? f.approvedAt.toISOString() : null,
      approvedBy: f.approvedBy || null
    }))
  });
});

app.post("/api/mod/facts/submit", requireModApi(), async (req, res) => {
  const text = safeStr(req.body.text || "", 2000).trim();
  if (!text || text.length < 8) return res.status(400).json({ error: "Fact too short." });

  const r = await factsSubmissionsCol.insertOne({
    text,
    status: "pending",
    submittedAt: new Date(),
    submittedBy: req.me.username,
    submittedByUserId: req.me._id
  });

  res.status(201).json({ ok: true, id: String(r.insertedId) });
});

app.get("/api/admin/facts/submissions", requireAdminApi(), async (req, res) => {
  const list = await factsSubmissionsCol.find({ status: "pending" }).sort({ submittedAt: -1 }).limit(400).toArray();
  res.json({
    ok: true,
    submissions: list.map(s => ({
      id: String(s._id),
      text: s.text,
      submittedAt: s.submittedAt ? s.submittedAt.toISOString() : null,
      submittedBy: s.submittedBy || null
    }))
  });
});

app.post("/api/admin/facts/submissions/:id/approve", requireAdminApi(), async (req, res) => {
  let sid;
  try { sid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }
  const s = await factsSubmissionsCol.findOne({ _id: sid, status: "pending" });
  if (!s) return res.status(404).json({ error: "Not found" });

  await factsApprovedCol.insertOne({
    text: s.text,
    createdAt: s.submittedAt || new Date(),
    approvedAt: new Date(),
    approvedBy: req.me.username
  });

  await factsSubmissionsCol.updateOne({ _id: sid }, { $set: { status: "approved", approvedAt: new Date(), approvedBy: req.me.username } });
  res.json({ ok: true });
});

app.post("/api/admin/facts/submissions/:id/reject", requireAdminApi(), async (req, res) => {
  let sid;
  try { sid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }
  await factsSubmissionsCol.updateOne(
    { _id: sid, status: "pending" },
    { $set: { status: "rejected", rejectedAt: new Date(), rejectedBy: req.me.username, rejectNote: safeStr(req.body.note || "", 300) } }
  );
  res.json({ ok: true });
});

/* =========================
   Devices + SSE
   ========================= */
app.post("/api/device/ping", requireAuthApi(), async (req, res) => {
  const deviceId = safeStr(req.body.deviceId || "", 120).trim();
  if (!deviceId || deviceId.length < 6) return res.status(400).json({ error: "Bad deviceId" });

  await devicesCol.updateOne(
    { deviceId },
    {
      $set: {
        deviceId,
        userId: req.me._id,
        username: req.me.username,
        ua: safeStr(req.headers["user-agent"] || "", 300),
        lastSeenAt: new Date()
      }
    },
    { upsert: true }
  );

  res.json({ ok: true });
});

app.get("/api/events", requireAuthApi(), async (req, res) => {
  const deviceId = safeStr(req.query.deviceId || "", 120).trim();
  if (!deviceId || deviceId.length < 6) return res.status(400).end();

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  attachLive(deviceId, res);

  await devicesCol.updateOne(
    { deviceId },
    {
      $set: {
        deviceId,
        userId: req.me._id,
        username: req.me.username,
        ua: safeStr(req.headers["user-agent"] || "", 300),
        lastSeenAt: new Date()
      }
    },
    { upsert: true }
  );

  sseSend(res, "hello", { ok: true, deviceId });

  const hb = setInterval(() => sseSend(res, "hb", { t: Date.now() }), 25000);
  req.on("close", () => {
    clearInterval(hb);
    detachLive(deviceId, res);
  });
});

/* =========================
   Commands (custom, admin-defined)
   ========================= */
function cleanCommandName(name) {
  const n = String(name || "").trim();
  if (!/^[a-zA-Z0-9_-]{1,24}$/.test(n)) return null;
  return n.toLowerCase();
}

app.get("/api/commands", requireAuthApi(), async (req, res) => {
  const list = await commandsCol.find({ enabled: true }).sort({ name: 1 }).limit(500).toArray();
  res.json({
    ok: true,
    commands: list.map((c) => ({
      id: String(c._id),
      name: c.name,
      description: c.description || "",
      output: c.output || "",
      enabled: !!c.enabled
    }))
  });
});

/* =========================
   Feature A: Command logs (only for logged-in users)
   ========================= */
app.post("/api/logs/command", requireAuthApi(), async (req, res) => {
  const deviceId = safeStr(req.body.deviceId || "", 120).trim();
  const raw = safeStr(req.body.raw || "", 500);

  if (!deviceId || deviceId.length < 6) return res.status(400).json({ error: "Bad deviceId" });
  if (!raw) return res.status(400).json({ error: "Missing raw command" });

  await commandLogsCol.insertOne({
    kind: "command",
    createdAt: new Date(),
    userId: req.me._id,
    username: req.me.username,
    deviceId,
    raw
  });

  res.json({ ok: true });
});

/* =========================
   Role requests (user->mod, mod->admin)
   ========================= */
app.post("/api/requests/role", requireAuthApi(), async (req, res) => {
  const targetRole = String(req.body.targetRole || "").toLowerCase();
  const note = safeStr(req.body.note || "", 500);

  if (!["mod", "admin"].includes(targetRole)) return res.status(400).json({ error: "targetRole must be mod/admin" });

  if (req.me.role === "user" && targetRole !== "mod") {
    return res.status(400).json({ error: "Users can only apply for mod." });
  }
  if (req.me.role === "mod" && targetRole !== "admin") {
    return res.status(400).json({ error: "Mods can only apply for admin." });
  }
  if (req.me.role === "admin") return res.status(400).json({ error: "Admins do not need to apply." });

  const exists = await roleRequestsCol.findOne({ status: "pending", userId: req.me._id, targetRole });
  if (exists) return res.status(409).json({ error: "You already have a pending request." });

  await roleRequestsCol.insertOne({
    status: "pending",
    createdAt: new Date(),
    userId: req.me._id,
    username: req.me.username,
    fromRole: req.me.role,
    targetRole,
    note
  });

  res.status(201).json({ ok: true });
});

app.get("/api/admin/requests/role", requireAdminApi(), async (req, res) => {
  const list = await roleRequestsCol.find({ status: "pending" }).sort({ createdAt: -1 }).limit(500).toArray();
  res.json({
    ok: true,
    requests: list.map(r => ({
      id: String(r._id),
      createdAt: r.createdAt ? r.createdAt.toISOString() : null,
      username: r.username,
      fromRole: r.fromRole,
      targetRole: r.targetRole,
      note: r.note || ""
    }))
  });
});

app.post("/api/admin/requests/role/:id/approve", requireAdminApi(), async (req, res) => {
  let rid;
  try { rid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }
  const r = await roleRequestsCol.findOne({ _id: rid, status: "pending" });
  if (!r) return res.status(404).json({ error: "Not found" });

  await usersCol.updateOne({ _id: r.userId }, { $set: { role: r.targetRole } });
  await roleRequestsCol.updateOne({ _id: rid }, { $set: { status: "approved", decidedAt: new Date(), decidedBy: req.me.username } });

  res.json({ ok: true });
});

app.post("/api/admin/requests/role/:id/reject", requireAdminApi(), async (req, res) => {
  let rid;
  try { rid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }

  await roleRequestsCol.updateOne(
    { _id: rid, status: "pending" },
    { $set: { status: "rejected", decidedAt: new Date(), decidedBy: req.me.username, note: safeStr(req.body.note || "", 300) } }
  );

  res.json({ ok: true });
});

/* =========================
   Ban requests (mods request; admins approve)
   ========================= */
app.post("/api/mod/ban-requests", requireModApi(), async (req, res) => {
  const username = safeStr(req.body.username || "", 60).trim();
  const ip = safeStr(req.body.ip || "", 80).trim();
  const reason = safeStr(req.body.reason || "", 200).trim() || "Requested by moderator.";

  if (!username && !ip) return res.status(400).json({ error: "Provide username and/or ip." });

  let userId = null;
  let userFoundName = null;

  if (username) {
    const u = await usersCol.findOne({ usernameLower: usernameKey(username) });
    if (!u) return res.status(404).json({ error: "User not found." });
    userId = u._id;
    userFoundName = u.username;
  }

  await banRequestsCol.insertOne({
    status: "pending",
    createdAt: new Date(),
    requestedBy: req.me.username,
    requestedByUserId: req.me._id,
    username: userFoundName,
    userId,
    ip: ip || null,
    reason
  });

  res.status(201).json({ ok: true });
});

app.get("/api/admin/ban-requests", requireAdminApi(), async (req, res) => {
  const list = await banRequestsCol.find({ status: "pending" }).sort({ createdAt: -1 }).limit(500).toArray();
  res.json({
    ok: true,
    requests: list.map(r => ({
      id: String(r._id),
      createdAt: r.createdAt ? r.createdAt.toISOString() : null,
      requestedBy: r.requestedBy,
      username: r.username || null,
      userId: r.userId ? String(r.userId) : null,
      ip: r.ip || null,
      reason: r.reason || ""
    }))
  });
});

async function banUserById(adminMe, uid, reason) {
  const u = await usersCol.findOne({ _id: uid });
  if (!u) return { ok: false, error: "User not found" };
  if (String(u._id) === String(adminMe._id)) return { ok: false, error: "You cannot ban yourself." };

  const nextSv = Number(u.sessionVersion || 1) + 1;
  await usersCol.updateOne(
    { _id: uid },
    { $set: { banned: true, banReason: reason, bannedAt: new Date(), bannedBy: adminMe.username, sessionVersion: nextSv } }
  );
  return { ok: true };
}

app.post("/api/admin/ban-requests/:id/approve", requireAdminApi(), async (req, res) => {
  let rid;
  try { rid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }
  const r = await banRequestsCol.findOne({ _id: rid, status: "pending" });
  if (!r) return res.status(404).json({ error: "Not found" });

  // ban user if included
  if (r.userId) {
    const br = await banUserById(req.me, r.userId, r.reason || "Banned by admin.");
    if (!br.ok) return res.status(400).json({ error: br.error });
  }

  // ban ip if included
  if (r.ip) {
    await ipBansCol.updateOne(
      { ip: r.ip },
      { $set: { ip: r.ip, banned: true, reason: r.reason || "IP banned by admin.", bannedAt: new Date(), bannedBy: req.me.username } },
      { upsert: true }
    );
  }

  await banRequestsCol.updateOne(
    { _id: rid },
    { $set: { status: "approved", decidedAt: new Date(), decidedBy: req.me.username } }
  );

  res.json({ ok: true });
});

app.post("/api/admin/ban-requests/:id/reject", requireAdminApi(), async (req, res) => {
  let rid;
  try { rid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }

  await banRequestsCol.updateOne(
    { _id: rid, status: "pending" },
    { $set: { status: "rejected", decidedAt: new Date(), decidedBy: req.me.username, note: safeStr(req.body.note || "", 300) } }
  );

  res.json({ ok: true });
});

/* =========================
   Admin API: users/devices/commands/logs + Remote control (A/B/C)
   ========================= */
app.get("/api/admin/users", requireAdminApi(), async (req, res) => {
  const q = safeStr(req.query.q || "", 60).trim().toLowerCase();
  const filter = q ? { usernameLower: { $regex: q } } : {};
  const list = await usersCol.find(filter).sort({ createdAt: -1 }).limit(500).toArray();
  res.json({ ok: true, users: list.map(publicUser) });
});

app.post("/api/admin/users/:id/ban", requireAdminApi(), async (req, res) => {
  let uid;
  try { uid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad user id" }); }
  const reason = safeStr(req.body.reason || "Banned by admin.", 200);

  const out = await banUserById(req.me, uid, reason);
  if (!out.ok) return res.status(400).json({ error: out.error });

  const u2 = await usersCol.findOne({ _id: uid });
  res.json({ ok: true, user: publicUser(u2) });
});

app.post("/api/admin/users/:id/unban", requireAdminApi(), async (req, res) => {
  let uid;
  try { uid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad user id" }); }

  const u = await usersCol.findOne({ _id: uid });
  if (!u) return res.status(404).json({ error: "User not found" });

  const nextSv = Number(u.sessionVersion || 1) + 1;
  await usersCol.updateOne(
    { _id: uid },
    { $set: { banned: false, sessionVersion: nextSv }, $unset: { banReason: "", bannedAt: "", bannedBy: "" } }
  );
  const u2 = await usersCol.findOne({ _id: uid });
  res.json({ ok: true, user: publicUser(u2) });
});

app.post("/api/admin/users/:id/role", requireAdminApi(), async (req, res) => {
  let uid;
  try { uid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad user id" }); }
  const role = String(req.body.role || "").toLowerCase();
  if (!["user", "mod", "admin"].includes(role)) return res.status(400).json({ error: "Role must be user/mod/admin" });

  const u = await usersCol.findOne({ _id: uid });
  if (!u) return res.status(404).json({ error: "User not found" });
  if (String(u._id) === String(req.me._id) && role !== "admin") {
    return res.status(400).json({ error: "You cannot downgrade your own admin role." });
  }

  await usersCol.updateOne({ _id: uid }, { $set: { role } });
  const u2 = await usersCol.findOne({ _id: uid });
  res.json({ ok: true, user: publicUser(u2) });
});

app.get("/api/admin/devices", requireAdminApi(), async (req, res) => {
  const list = await devicesCol.find({}).sort({ lastSeenAt: -1 }).limit(1000).toArray();
  res.json({
    ok: true,
    devices: list.map((d) => ({
      deviceId: d.deviceId,
      username: d.username || null,
      lastSeenAt: d.lastSeenAt ? d.lastSeenAt.toISOString() : null,
      ua: d.ua || null
    }))
  });
});

/* Admin: Commands CRUD */
app.get("/api/admin/commands", requireAdminApi(), async (req, res) => {
  const list = await commandsCol.find({}).sort({ name: 1 }).limit(1200).toArray();
  res.json({
    ok: true,
    commands: list.map((c) => ({
      id: String(c._id),
      name: c.name,
      description: c.description || "",
      output: c.output || "",
      enabled: !!c.enabled
    }))
  });
});

app.post("/api/admin/commands", requireAdminApi(), async (req, res) => {
  const name = cleanCommandName(req.body.name);
  if (!name) return res.status(400).json({ error: "Bad command name" });

  const description = safeStr(req.body.description || "", 300);
  const output = safeStr(req.body.output || "", 5000);
  const enabled = req.body.enabled !== false;

  const exists = await commandsCol.findOne({ name });
  if (exists) return res.status(409).json({ error: "Command already exists." });

  const result = await commandsCol.insertOne({
    name, description, output, enabled,
    createdAt: new Date(),
    updatedAt: new Date(),
    createdBy: req.me.username
  });
  res.status(201).json({ ok: true, id: String(result.insertedId) });
});

app.put("/api/admin/commands/:id", requireAdminApi(), async (req, res) => {
  let cid;
  try { cid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }

  const patch = {};
  if (req.body.description !== undefined) patch.description = safeStr(req.body.description || "", 300);
  if (req.body.output !== undefined) patch.output = safeStr(req.body.output || "", 5000);
  if (req.body.enabled !== undefined) patch.enabled = !!req.body.enabled;
  patch.updatedAt = new Date();

  await commandsCol.updateOne({ _id: cid }, { $set: patch });
  res.json({ ok: true });
});

app.delete("/api/admin/commands/:id", requireAdminApi(), async (req, res) => {
  let cid;
  try { cid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad id" }); }
  await commandsCol.deleteOne({ _id: cid });
  res.json({ ok: true });
});

/* Admin: broadcast commands_update to devices (so clients reload custom commands) */
app.post("/api/admin/commands/broadcast", requireAdminApi(), async (req, res) => {
  const target = String(req.body.target || "all").toLowerCase(); // all | device
  const deviceId = safeStr(req.body.deviceId || "", 120).trim();

  if (target !== "all" && target !== "device") return res.status(400).json({ error: "Bad target" });
  if (target === "device" && (!deviceId || deviceId.length < 6)) return res.status(400).json({ error: "Bad deviceId" });

  const payload = { t: Date.now(), by: req.me.username };
  if (target === "all") broadcast("commands_update", payload);
  else sendToDevice(deviceId, "commands_update", payload);

  res.json({ ok: true });
});

/* Feature A (admin view): get command logs */
app.get("/api/admin/logs/commands", requireAdminApi(), async (req, res) => {
  const deviceId = safeStr(req.query.deviceId || "", 120).trim();
  const q = safeStr(req.query.q || "", 120).trim().toLowerCase();
  const limit = Math.max(1, Math.min(500, Number(req.query.limit || 100)));

  const filter = { kind: "command" };
  if (deviceId) filter.deviceId = deviceId;
  if (q) filter.raw = { $regex: q };

  const list = await commandLogsCol.find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
  res.json({
    ok: true,
    logs: list.map((l) => ({
      id: String(l._id),
      at: l.createdAt ? l.createdAt.toISOString() : null,
      username: l.username || null,
      deviceId: l.deviceId,
      raw: l.raw
    }))
  });
});

/* Visits (admin view) */
app.get("/api/admin/visits", requireAdminApi(), async (req, res) => {
  const limit = Math.max(1, Math.min(500, Number(req.query.limit || 200)));
  const list = await visitsCol.find({}).sort({ at: -1 }).limit(limit).toArray();
  res.json({
    ok: true,
    visits: list.map(v => ({
      id: String(v._id),
      at: v.at ? v.at.toISOString() : null,
      ip: v.ip,
      path: v.path,
      username: v.username || null,
      ua: v.ua || null
    }))
  });
});

/* IP bans (admin) */
app.get("/api/admin/ip-bans", requireAdminApi(), async (req, res) => {
  const list = await ipBansCol.find({ banned: true }).sort({ bannedAt: -1 }).limit(500).toArray();
  res.json({ ok: true, bans: list.map(b => ({ ip: b.ip, reason: b.reason || "", bannedAt: b.bannedAt ? b.bannedAt.toISOString() : null, bannedBy: b.bannedBy || null })) });
});

app.post("/api/admin/ip-bans/ban", requireAdminApi(), async (req, res) => {
  const ip = safeStr(req.body.ip || "", 80).trim();
  const reason = safeStr(req.body.reason || "IP banned by admin.", 200);
  if (!ip) return res.status(400).json({ error: "Missing ip" });

  await ipBansCol.updateOne(
    { ip },
    { $set: { ip, banned: true, reason, bannedAt: new Date(), bannedBy: req.me.username } },
    { upsert: true }
  );
  res.json({ ok: true });
});

app.post("/api/admin/ip-bans/unban", requireAdminApi(), async (req, res) => {
  const ip = safeStr(req.body.ip || "", 80).trim();
  if (!ip) return res.status(400).json({ error: "Missing ip" });
  await ipBansCol.updateOne({ ip }, { $set: { banned: false }, $unset: { reason: "", bannedAt: "", bannedBy: "" } }, { upsert: true });
  res.json({ ok: true });
});

/* Feature B: remote run command */
app.post("/api/admin/run-command", requireAdminApi(), async (req, res) => {
  const target = String(req.body.target || "all").toLowerCase(); // all | device
  const deviceId = safeStr(req.body.deviceId || "", 120).trim();
  const commandLine = safeStr(req.body.commandLine || "", 400).trim();
  const typing = !!req.body.typing;

  if (!commandLine) return res.status(400).json({ error: "Missing commandLine" });
  if (target !== "all" && target !== "device") return res.status(400).json({ error: "Bad target" });
  if (target === "device" && (!deviceId || deviceId.length < 6)) return res.status(400).json({ error: "Bad deviceId" });

  const payload = { commandLine, typing, from: req.me.username, at: new Date().toISOString() };
  const delivered = target === "all"
    ? (broadcast("admin_run", payload), "broadcast")
    : sendToDevice(deviceId, "admin_run", payload);

  res.json({ ok: true, delivered });
});

/* Feature C: remote FX control */
app.post("/api/admin/fx", requireAdminApi(), async (req, res) => {
  const target = String(req.body.target || "all").toLowerCase(); // all | device
  const deviceId = safeStr(req.body.deviceId || "", 120).trim();

  if (target !== "all" && target !== "device") return res.status(400).json({ error: "Bad target" });
  if (target === "device" && (!deviceId || deviceId.length < 6)) return res.status(400).json({ error: "Bad deviceId" });

  const fx = {
    matrixOn: req.body.matrixOn,
    rainbow: req.body.rainbow,
    mirror: req.body.mirror,
    scanOpacity: req.body.scanOpacity,
    glitchOpacity: req.body.glitchOpacity,
    from: req.me.username,
    at: new Date().toISOString()
  };

  const payload = Object.fromEntries(Object.entries(fx).filter(([, v]) => v !== undefined));
  const delivered = target === "all"
    ? (broadcast("admin_fx", payload), "broadcast")
    : sendToDevice(deviceId, "admin_fx", payload);

  res.json({ ok: true, delivered });
});

/* Health */
app.get("/api/health", (req, res) => res.json({ ok: true }));

/* Start */
async function start() {
  await client.connect();
  const db = client.db(MONGODB_DB);

  usersCol = db.collection("users");
  devicesCol = db.collection("devices");
  commandsCol = db.collection("commands");
  commandLogsCol = db.collection("command_logs");
  visitsCol = db.collection("visits");
  ipBansCol = db.collection("ip_bans");

  factsSubmissionsCol = db.collection("facts_submissions");
  factsApprovedCol = db.collection("facts_approved");

  roleRequestsCol = db.collection("role_requests");
  banRequestsCol = db.collection("ban_requests");

  await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
  await devicesCol.createIndex({ deviceId: 1 }, { unique: true });
  await devicesCol.createIndex({ lastSeenAt: -1 });
  await commandsCol.createIndex({ name: 1 }, { unique: true });
  await commandLogsCol.createIndex({ createdAt: -1 });
  await commandLogsCol.createIndex({ kind: 1, deviceId: 1, createdAt: -1 });
  await visitsCol.createIndex({ at: -1 });
  await ipBansCol.createIndex({ ip: 1 }, { unique: true });

  await factsSubmissionsCol.createIndex({ status: 1, submittedAt: -1 });
  await factsApprovedCol.createIndex({ createdAt: -1 });

  await roleRequestsCol.createIndex({ status: 1, createdAt: -1 });
  await banRequestsCol.createIndex({ status: 1, createdAt: -1 });

  dbReady = true;

  await ensureBootstrapAdmin();

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log("Server listening on port", PORT));
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
