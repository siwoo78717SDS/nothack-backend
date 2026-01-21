const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.set("trust proxy", 1);

app.use(express.json({ limit: "300kb" }));
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

let usersCol;
let devicesCol;
let commandsCol;
let logsCol;

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
function publicUser(u) {
  return {
    id: String(u._id),
    username: u.username,
    role: u.role,
    banned: !!u.banned,
    banReason: u.banReason || null,
    createdAt: u.createdAt ? u.createdAt.toISOString() : null
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
function requireAdminApi() {
  return async (req, res, next) => {
    const me = await getUserBySession(req);
    if (!me) return res.status(401).json({ error: "Not logged in" });
    if (me.banned) return res.status(403).json({ error: "Banned", reason: me.banReason || null });
    if (me.role !== "admin") return res.status(403).json({ error: "Admin only" });
    req.me = me;
    next();
  };
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
    username,
    usernameLower: lower,
    passHash,
    role: "admin",
    banned: false,
    sessionVersion: 1,
    createdAt: new Date()
  });
  console.log("[bootstrap] Created admin user:", username);
}

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
app.get("/account", requireRolePage(["user","mod","admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "account.html"))
);
app.get("/admin", requireRolePage(["admin"]), (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html"))
);

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

/* =========================
   Auth API (no email)
   ========================= */
app.get("/api/auth/me", async (req, res) => {
  const me = await getUserBySession(req);
  if (!me) return res.json({ loggedIn: false });
  if (me.banned) return res.json({ loggedIn: false, banned: true, reason: me.banReason || null });
  return res.json({ loggedIn: true, user: publicUser(me) });
});

app.post("/api/auth/register", async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");

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
    username,
    usernameLower: lower,
    passHash,
    role: "user",
    banned: false,
    sessionVersion: 1,
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
   Feature A: Command logs
   ========================= */
app.post("/api/logs/command", requireAuthApi(), async (req, res) => {
  const deviceId = safeStr(req.body.deviceId || "", 120).trim();
  const raw = safeStr(req.body.raw || "", 500);

  if (!deviceId || deviceId.length < 6) return res.status(400).json({ error: "Bad deviceId" });
  if (!raw) return res.status(400).json({ error: "Missing raw command" });

  await logsCol.insertOne({
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
   Admin API (users/devices/commands/logs + A/B/C)
   ========================= */
app.get("/api/admin/users", requireAdminApi(), async (req, res) => {
  const q = safeStr(req.query.q || "", 60).trim().toLowerCase();
  const filter = q ? { usernameLower: { $regex: q } } : {};
  const list = await usersCol.find(filter).sort({ createdAt: -1 }).limit(400).toArray();
  res.json({ ok: true, users: list.map(publicUser) });
});

app.post("/api/admin/users/:id/ban", requireAdminApi(), async (req, res) => {
  let uid;
  try { uid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad user id" }); }
  const reason = safeStr(req.body.reason || "Banned by admin.", 200);

  const u = await usersCol.findOne({ _id: uid });
  if (!u) return res.status(404).json({ error: "User not found" });
  if (String(u._id) === String(req.me._id)) return res.status(400).json({ error: "You cannot ban yourself." });

  await usersCol.updateOne(
    { _id: uid },
    { $set: { banned: true, banReason: reason, bannedAt: new Date(), bannedBy: req.me.username } }
  );
  const u2 = await usersCol.findOne({ _id: uid });
  res.json({ ok: true, user: publicUser(u2) });
});

app.post("/api/admin/users/:id/unban", requireAdminApi(), async (req, res) => {
  let uid;
  try { uid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad user id" }); }

  const u = await usersCol.findOne({ _id: uid });
  if (!u) return res.status(404).json({ error: "User not found" });

  await usersCol.updateOne(
    { _id: uid },
    { $set: { banned: false }, $unset: { banReason: "", bannedAt: "", bannedBy: "" } }
  );
  const u2 = await usersCol.findOne({ _id: uid });
  res.json({ ok: true, user: publicUser(u2) });
});

app.post("/api/admin/users/:id/role", requireAdminApi(), async (req, res) => {
  let uid;
  try { uid = new ObjectId(req.params.id); } catch { return res.status(400).json({ error: "Bad user id" }); }
  const role = String(req.body.role || "").toLowerCase();
  if (!["user","mod","admin"].includes(role)) return res.status(400).json({ error: "Role must be user/mod/admin" });

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
  const list = await devicesCol.find({}).sort({ lastSeenAt: -1 }).limit(500).toArray();
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
  const list = await commandsCol.find({}).sort({ name: 1 }).limit(800).toArray();
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
  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 50)));

  const filter = { kind: "command" };
  if (deviceId) filter.deviceId = deviceId;
  if (q) filter.raw = { $regex: q };

  const list = await logsCol.find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
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
  const delivered = target === "all" ? (broadcast("admin_run", payload), "broadcast") : sendToDevice(deviceId, "admin_run", payload);

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

  const payload = Object.fromEntries(Object.entries(fx).filter(([,v]) => v !== undefined));
  const delivered = target === "all" ? (broadcast("admin_fx", payload), "broadcast") : sendToDevice(deviceId, "admin_fx", payload);

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
  logsCol = db.collection("command_logs");

  await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
  await devicesCol.createIndex({ deviceId: 1 }, { unique: true });
  await devicesCol.createIndex({ lastSeenAt: -1 });
  await commandsCol.createIndex({ name: 1 }, { unique: true });
  await logsCol.createIndex({ createdAt: -1 });
  await logsCol.createIndex({ kind: 1, deviceId: 1, createdAt: -1 });

  await ensureBootstrapAdmin();

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log("Server listening on port", PORT));
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
