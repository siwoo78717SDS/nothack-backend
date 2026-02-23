const express = require("express");
const router = express.Router();
const User = require("../models/User");
const { awardAchievement } = require("../services/achievements");
const { loginLimiter } = require("../services/security");

function getClientIp(req) {
  if (!req) return "";

  const xff = req.headers?.["x-forwarded-for"];
  if (typeof xff === "string" && xff.length) {
    return xff.split(",")[0].trim();
  }

  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || "";
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

router.post("/register", async (req, res) => {
  try {
    const { fullName, username, password } = req.body || {};
    if (!fullName || !username || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const u = String(username).trim();
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(u)) {
      return res
        .status(400)
        .json({ error: "Username must be 3-20 chars (letters/numbers/_)" });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    // check both exact and lower (supports older docs)
    const exists = await User.findOne({
      $or: [{ username: u }, { usernameLower: u.toLowerCase() }]
    });
    if (exists) return res.status(400).json({ error: "Username already taken" });

    const now = new Date();
    const ip = getClientIp(req);

    const passHash = await User.hashPassword(String(password));
    const user = await User.create({
      fullName: String(fullName).slice(0, 80),
      username: u,
      passHash, // ✅ MUST be passHash (matches your User model)

      lastLoginAt: now,
      lastSeenAt: now,
      lastIp: ip
    });

    await regenerateSession(req);
    req.session.userId = user._id.toString();
    req.session._lastSeenWriteAt = Date.now();

    return res.json({
      ok: true,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "Missing username/password" });
    }

    const unameRaw = String(username).trim();
    const unameLower = unameRaw.toLowerCase();

    const user = await User.findOne({
      isDeleted: false,
      $or: [
        { usernameLower: unameLower },
        { username: new RegExp("^" + escapeRegExp(unameRaw) + "$", "i") }
      ]
    }).select("+passHash"); // ✅ MUST select passHash (it’s hidden by default)

    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await user.checkPassword(String(password));
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    await regenerateSession(req);
    req.session.userId = user._id.toString();
    req.session._lastSeenWriteAt = Date.now();

    const now = new Date();
    const ip = getClientIp(req);
    await User.updateOne(
      { _id: user._id },
      { $set: { lastLoginAt: now, lastSeenAt: now, lastIp: ip } }
    );

    await awardAchievement(user._id, "FIRST_LOGIN");

    return res.json({
      ok: true,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

router.post("/logout", async (req, res) => {
  try {
    if (!req.session) return res.json({ ok: true });

    req.session.destroy((err) => {
      if (err) {
        console.error("logout destroy error:", err);
        return res.status(500).json({ error: "Server error" });
      }

      res.clearCookie("connect.sid");
      return res.json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

router.get("/me", async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.json({ loggedIn: false });
  }

  const user = await User.findById(req.session.userId);

  if (!user || user.isDeleted) {
    return res.json({ loggedIn: false });
  }

  return res.json({
    loggedIn: true,
    user: {
      id: user._id,
      username: user.username,
      fullName: user.fullName,
      role: user.role,
      level: user.level,
      coins: user.coins,
      statusMessage: user.statusMessage || "",
      theme: user.theme || "classic",
      lastLoginAt: user.lastLoginAt || null,
      lastSeenAt: user.lastSeenAt || null
    }
  });
});

module.exports = router;