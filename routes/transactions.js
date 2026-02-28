const express = require("express");
const router = express.Router();

const CoinTransaction = require("../models/CoinTransaction");
const { loadUser, requireAdmin } = require("./_helpers");
const { adminLimiter } = require("../services/security");

// GET /api/transactions/me
router.get("/me", loadUser, async (req, res) => {
  try {
    const tx = await CoinTransaction.find({
      $or: [{ fromUserId: req.user._id }, { toUserId: req.user._id }]
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json({ transactions: tx });
  } catch (err) {
    console.error("GET /api/transactions/me error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/transactions/admin/all?username=Lemon78717
router.get("/admin/all", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const username = req.query?.username ? String(req.query.username).trim() : "";
    const filter = {};

    if (username) {
      filter.$or = [{ fromUsername: username }, { toUsername: username }];
    }

    const tx = await CoinTransaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(200)
      .lean();

    res.json({ transactions: tx });
  } catch (err) {
    console.error("GET /api/transactions/admin/all error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;