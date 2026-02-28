const express = require("express");
const router = express.Router();

const User = require("../models/User");

// OPTIONAL models (so the server doesn’t crash if you haven’t added them yet)
let AuditLog = null;
let IpBan = null;
let CoinTransaction = null;
let CodeQuizAttempt = null;

try {
  // eslint-disable-next-line global-require
  AuditLog = require("../models/AuditLog");
} catch (e) {
  AuditLog = null;
}

try {
  // eslint-disable-next-line global-require
  IpBan = require("../models/IpBan");
} catch (e) {
  IpBan = null;
}

try {
  // eslint-disable-next-line global-require
  CoinTransaction = require("../models/CoinTransaction");
} catch (e) {
  CoinTransaction = null;
}

try {
  // eslint-disable-next-line global-require
  CodeQuizAttempt = require("../models/CodeQuizAttempt");
} catch (e) {
  CodeQuizAttempt = null;
}

const { loadUser, requireAdmin, getClientIp } = require("./_helpers");
const { adminLimiter } = require("../services/security");
const { audit } = require("../services/audit");

/**
 * Admin: list users for "User Profile Database"
 * Returns lastSeenAt / lastLoginAt / lastIp so admin UI can display them.
 */
router.get("/users", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);

    const users = await User.find(
      {},
      {
        username: 1,
        fullName: 1,
        role: 1,
        level: 1,
        coins: 1,
        bans: 1,
        unlocks: 1,
        stats: 1,
        statusMessage: 1,

        // tracking fields
        lastSeenAt: 1,
        lastLoginAt: 1,
        lastIp: 1,

        createdAt: 1,
        achievementPoints: 1,

        // include isDeleted so admin UI can show it
        isDeleted: 1
      }
    )
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ users });
  } catch (err) {
    console.error("GET /admin/users error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * Admin: single user profile (your admin UI calls this)
 * GET /api/admin/users/profile?username=...
 */
router.get("/users/profile", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const username = String(req.query.username || "").trim();
    if (!username) return res.status(400).json({ error: "Missing username" });

    // IMPORTANT: do NOT leak password hashes etc
    const user = await User.findOne(
      { username },
      {
        username: 1,
        fullName: 1,
        role: 1,
        level: 1,
        coins: 1,
        bans: 1,
        unlocks: 1,
        stats: 1,
        statusMessage: 1,
        lastSeenAt: 1,
        lastLoginAt: 1,
        lastIp: 1,
        createdAt: 1,
        achievementPoints: 1,
        isDeleted: 1
      }
    ).lean();

    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ user });
  } catch (err) {
    console.error("GET /admin/users/profile error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Toggle ban flags
router.post("/users/ban-flags", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, chatBan, coinsBan, reason } = req.body || {};
    if (!username) return res.status(400).json({ error: "Missing username" });

    const target = await User.findOne({ username: String(username).trim() });
    if (!target) return res.status(404).json({ error: "User not found" });

    const bans = { ...(target.bans || {}) };

    if (typeof chatBan === "boolean") bans.isBannedFromChat = chatBan;
    if (typeof coinsBan === "boolean") bans.isBannedFromCoins = coinsBan;
    if (typeof reason === "string") bans.reason = reason.slice(0, 200);
    bans.updatedAt = new Date();

    target.bans = bans;
    await target.save();

    await audit({
      actor: req.user,
      action: "ADMIN_SET_BANS",
      targetUsername: target.username,
      details: {
        isBannedFromChat: !!target.bans?.isBannedFromChat,
        isBannedFromCoins: !!target.bans?.isBannedFromCoins,
        reason: target.bans?.reason || ""
      },
      ip: getClientIp(req)
    });

    return res.json({ ok: true, username: target.username, bans: target.bans });
  } catch (err) {
    console.error("POST /admin/users/ban-flags error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Set role
router.post("/users/set-role", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, role } = req.body || {};
    const allowed = ["user", "mod", "admin"];
    if (!username || !allowed.includes(role)) {
      return res.status(400).json({ error: "Invalid request" });
    }

    const target = await User.findOne({ username: String(username).trim() });
    if (!target) return res.status(404).json({ error: "User not found" });

    // prevent removing your own admin accidentally
    if (target._id.toString() === req.user._id.toString() && role !== "admin") {
      return res.status(400).json({ error: "You cannot remove your own admin role" });
    }

    target.role = role;
    await target.save();

    await audit({
      actor: req.user,
      action: "ADMIN_SET_ROLE",
      targetUsername: target.username,
      details: { role },
      ip: getClientIp(req)
    });

    return res.json({ ok: true, username: target.username, role: target.role });
  } catch (err) {
    console.error("POST /admin/users/set-role error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Set level
router.post("/users/set-level", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, level } = req.body || {};
    const lvl = Number(level);

    if (!username || !Number.isInteger(lvl) || lvl < 1 || lvl > 10) {
      return res.status(400).json({ error: "Invalid request" });
    }

    const target = await User.findOne({ username: String(username).trim() });
    if (!target) return res.status(404).json({ error: "User not found" });

    target.level = lvl;
    await target.save();

    await audit({
      actor: req.user,
      action: "ADMIN_SET_LEVEL",
      targetUsername: target.username,
      details: { level: lvl },
      ip: getClientIp(req)
    });

    return res.json({ ok: true, username: target.username, level: target.level });
  } catch (err) {
    console.error("POST /admin/users/set-level error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * Soft delete a user account (admin-only).
 */
router.post("/users/delete", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username } = req.body || {};
    const cleanName = String(username || "").trim();
    if (!cleanName) return res.status(400).json({ error: "Missing username" });

    const target = await User.findOne({ username: cleanName });
    if (!target) return res.status(404).json({ error: "User not found" });

    // prevent deleting yourself
    if (target._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ error: "You cannot delete your own account" });
    }

    target.isDeleted = true;
    target.coins = 0;

    const bans = { ...(target.bans || {}) };
    bans.isBannedFromChat = true;
    bans.isBannedFromCoins = true;
    bans.reason = "Account deleted by admin";
    bans.updatedAt = new Date();
    target.bans = bans;

    const unlocks = { ...(target.unlocks || {}) };
    unlocks.chat = false;
    unlocks.groupChat = false;
    unlocks.createGroup = false;
    unlocks.imageUpload = false;
    target.unlocks = unlocks;

    target.statusMessage = "[DELETED]";
    await target.save();

    await audit({
      actor: req.user,
      action: "ADMIN_DELETE_USER",
      targetUsername: target.username,
      details: {},
      ip: getClientIp(req)
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("POST /admin/users/delete error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * HARD DELETE a user account (admin-only).
 * - Requires { username, confirm } where confirm must equal username
 * - Deletes related collections if their models exist
 * - Deletes the User document
 */
router.post("/users/hard-delete", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, confirm } = req.body || {};
    const cleanName = String(username || "").trim();
    if (!cleanName) return res.status(400).json({ error: "Missing username" });

    if (String(confirm || "").trim() !== cleanName) {
      return res.status(400).json({ error: "Confirmation mismatch (confirm must equal username)." });
    }

    const target = await User.findOne({ username: cleanName });
    if (!target) return res.status(404).json({ error: "User not found" });

    // prevent deleting yourself
    if (target._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ error: "You cannot hard-delete your own account" });
    }

    // SAFETY (recommended): refuse deleting admins
    if (target.role === "admin") {
      return res.status(400).json({ error: "Refusing to hard-delete an admin account." });
    }

    const targetId = target._id;
    const targetUsername = target.username;

    const cleanup = [];

    // clean quiz attempts
    if (CodeQuizAttempt) cleanup.push(CodeQuizAttempt.deleteMany({ userId: targetId }));

    // clean coin transactions (to/from)
    if (CoinTransaction) {
      cleanup.push(CoinTransaction.deleteMany({ toUserId: targetId }));
      cleanup.push(CoinTransaction.deleteMany({ fromUserId: targetId }));
    }

    // clean audit logs if you store targetUsername there (optional)
    if (AuditLog) cleanup.push(AuditLog.deleteMany({ targetUsername }));

    await Promise.allSettled(cleanup);

    await User.deleteOne({ _id: targetId });

    await audit({
      actor: req.user,
      action: "ADMIN_HARD_DELETE_USER",
      targetUsername,
      details: {
        deletedUserId: String(targetId),
        cleanup: {
          codeQuizAttempt: !!CodeQuizAttempt,
          coinTransaction: !!CoinTransaction,
          auditLog: !!AuditLog
        }
      },
      ip: getClientIp(req)
    });

    return res.json({ ok: true, message: `Hard-deleted user ${targetUsername}` });
  } catch (err) {
    console.error("POST /admin/users/hard-delete error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * Full ban (user + IP).
 */
router.post("/users/full-ban", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, reason } = req.body || {};
    const cleanName = String(username || "").trim();
    if (!cleanName) return res.status(400).json({ error: "Missing username" });

    const target = await User.findOne({ username: cleanName });
    if (!target) return res.status(404).json({ error: "User not found" });

    const banReason = reason || "Full ban";

    const bans = { ...(target.bans || {}) };
    bans.isBannedFromChat = true;
    bans.isBannedFromCoins = true;
    bans.reason = String(banReason).slice(0, 200);
    bans.updatedAt = new Date();
    target.bans = bans;

    await target.save();

    const ipToBan = target.lastIp || getClientIp(req);

    if (IpBan && ipToBan) {
      await IpBan.updateOne(
        { ip: ipToBan },
        {
          $set: {
            ip: ipToBan,
            reason: String(banReason).slice(0, 200),
            expiresAt: null
          }
        },
        { upsert: true }
      );
    }

    await audit({
      actor: req.user,
      action: "ADMIN_FULL_BAN",
      targetUsername: target.username,
      details: { reason: banReason, ip: ipToBan || "", ipBanSaved: !!IpBan },
      ip: getClientIp(req)
    });

    return res.json({ ok: true, ipBanned: !!IpBan, ip: ipToBan || "" });
  } catch (err) {
    console.error("POST /admin/users/full-ban error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Audit logs
router.get("/audit", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    if (!AuditLog) {
      return res.json({ logs: [], warning: "AuditLog model not found (create models/AuditLog.js)" });
    }
    const logs = await AuditLog.find({}).sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ logs });
  } catch (err) {
    console.error("GET /admin/audit error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;