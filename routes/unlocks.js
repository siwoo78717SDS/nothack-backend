const express = require("express");
const router = express.Router();

const User = require("../models/User");
const Transaction = require("../models/Transaction");
const { loadUser } = require("./_helpers");
const { coinLimiter } = require("../services/security");

const UNLOCK_PRICES = {
  chat: 100,
  groupChat: 200,
  createGroup: 300,
  imageUpload: 150
};

function requireNotDeleted(req, res, next) {
  if (req.user?.isDeleted) return res.status(403).json({ error: "Account deleted" });
  next();
}

router.get("/prices", (req, res) => {
  res.json({ prices: UNLOCK_PRICES });
});

// NEW: GET /api/unlocks
// Used by the terminal to know which features are unlocked.
router.get("/", loadUser, requireNotDeleted, async (req, res) => {
  try {
    const user = await User.findById(req.user._id, { unlocks: 1 }).lean();
    const u = user?.unlocks || {};

    res.json({
      chat: !!u.chat,
      groupChat: !!u.groupChat,
      createGroup: !!u.createGroup,
      imageUpload: !!u.imageUpload
    });
  } catch (err) {
    console.error("GET /api/unlocks error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/unlocks/me
router.get("/me", loadUser, requireNotDeleted, (req, res) => {
  res.json({
    username: req.user.username,
    coins: req.user.coins || 0,
    unlocks: req.user.unlocks || {},
    prices: UNLOCK_PRICES
  });
});

// POST /api/unlocks/buy  { key: "chat" }
router.post("/buy", coinLimiter, loadUser, requireNotDeleted, async (req, res) => {
  try {
    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    const key = String(req.body?.key || "").trim();
    const cost = UNLOCK_PRICES[key];

    if (!cost) return res.status(400).json({ error: "Invalid unlock key" });

    const unlocks = req.user.unlocks || {};
    if (unlocks[key]) return res.status(400).json({ error: "Already unlocked" });

    if ((req.user.coins || 0) < cost) {
      return res.status(400).json({ error: "Not enough coins" });
    }

    req.user.coins = (req.user.coins || 0) - cost;
    req.user.unlocks = { ...unlocks, [key]: true };
    await req.user.save();

    await Transaction.create({
      type: "shop:unlock",
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      toUserId: req.user._id,
      toUsername: req.user.username,
      amount: cost,
      description: `Bought unlock: ${key}`,
      meta: { key, cost }
    });

    res.json({
      ok: true,
      coins: req.user.coins,
      unlocks: req.user.unlocks,
      prices: UNLOCK_PRICES
    });
  } catch (err) {
    console.error("POST /api/unlocks/buy error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;