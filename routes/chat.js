const express = require("express");
const router = express.Router();
const User = require("../models/User");
const ChatMessage = require("../models/ChatMessage");
const CoinTransaction = require("../models/CoinTransaction");
const { loadUser } = require("./_helpers");
const { chatLimiter } = require("../services/security");
const { recordFeatureAction } = require("../services/featureProgress");

// ---------- unlock middlewares ----------

// User must have chat unlocked to use DM features
function requireChatUnlocked(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  if (!req.user.unlocks || !req.user.unlocks.chat) {
    return res.status(403).json({
      error: "Chat feature is locked. Unlock it in the Feature Shop."
    });
  }
  next();
}

// User must have imageUpload unlocked to send images in DM
function requireImageUploadUnlocked(req, res, next) {
  const { imageUrl } = req.body || {};
  const hasImage = !!(imageUrl && String(imageUrl).trim());
  if (!hasImage) return next(); // no image, no check

  if (!req.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  if (!req.user.unlocks || !req.user.unlocks.imageUpload) {
    return res.status(403).json({
      error: "Image Upload feature is locked. Unlock it in the Feature Shop."
    });
  }
  next();
}

// ---------- routes ----------

// GET /api/chat/history?with=username
router.get("/history", loadUser, requireChatUnlocked, async (req, res) => {
  try {
    const withUsername = String(req.query.with || "").trim();
    if (!withUsername) {
      return res.status(400).json({ error: "Missing ?with=username" });
    }

    const other = await User.findOne({ username: withUsername });
    if (!other) return res.status(404).json({ error: "User not found" });

    // Receiver must also have chat unlocked
    if (!other.unlocks || !other.unlocks.chat) {
      return res.status(403).json({
        error: "The other user has not unlocked chat yet."
      });
    }

    const filter = {
      $or: [
        { fromUserId: req.user._id, toUserId: other._id },
        { fromUserId: other._id, toUserId: req.user._id }
      ]
    };

    const messages = await ChatMessage.find(filter)
      .sort({ createdAt: 1 })
      .limit(200);
    res.json({ messages });
  } catch (err) {
    console.error("GET /dm/history error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/chat/send
router.post(
  "/send",
  chatLimiter,
  loadUser,
  requireChatUnlocked,
  requireImageUploadUnlocked,
  async (req, res) => {
    try {
      if (req.user.bans?.isBannedFromChat) {
        return res
          .status(403)
          .json({ error: "You are banned from chat" });
      }

      const { toUsername, text, imageUrl, coinsToSend } = req.body || {};
      const coins = Number(coinsToSend) || 0;

      if (!toUsername) {
        return res.status(400).json({ error: "Missing toUsername" });
      }

      const target = await User.findOne({
        username: String(toUsername).trim()
      });
      if (!target) {
        return res
          .status(404)
          .json({ error: "Target user not found" });
      }
      if (target.username === req.user.username) {
        return res
          .status(400)
          .json({ error: "Cannot chat with yourself here" });
      }

      // Target must also have chat unlocked
      if (!target.unlocks || !target.unlocks.chat) {
        return res.status(403).json({
          error: "The other user has not unlocked chat yet."
        });
      }

      const hasImage = !!(imageUrl && String(imageUrl).trim());
      if (hasImage && req.user.level < 2) {
        return res.status(403).json({
          error: "Level 2 required to send images"
        });
      }

      // optional coins transfer via DM
      if (coins > 0) {
        if (req.user.bans?.isBannedFromCoins) {
          return res
            .status(403)
            .json({ error: "You are banned from coins" });
        }
        if (req.user.coins < coins) {
          return res
            .status(400)
            .json({ error: "Not enough coins" });
        }

        req.user.coins -= coins;
        await req.user.save();

        if (!target.bans?.isBannedFromCoins) {
          target.coins += coins;
        }
        await target.save();

        await CoinTransaction.create({
          type: "transfer",
          fromUserId: req.user._id,
          toUserId: target._id,
          fromUsername: req.user.username,
          toUsername: target.username,
          amount: coins,
          description: "DM transfer"
        });
      }

      const msg = await ChatMessage.create({
        fromUserId: req.user._id,
        toUserId: target._id,
        fromUsername: req.user.username,
        toUsername: target.username,
        text: String(text || "").slice(0, 2000),
        imageUrl: hasImage ? String(imageUrl).slice(0, 300) : "",
        coinsSent: coins > 0 ? coins : 0
      });

      // AP + stats: one DM sent, maybe one image
      await recordFeatureAction(
        req.user._id,
        "chat",
        "dmMessagesSent",
        1
      );
      if (hasImage) {
        await recordFeatureAction(
          req.user._id,
          "imageUpload",
          "imagesSent",
          1
        );
      }

      // ---- SOCKET.IO BROADCAST ----
      const io = req.app.get("io");
      const dmRoomName = req.app.get("dmRoomName");
      if (io && dmRoomName) {
        const room = dmRoomName(req.user.username, target.username);
        io.to(room).emit("dm_message", {
          _id: msg._id,
          fromUsername: msg.fromUsername,
          toUsername: msg.toUsername,
          text: msg.text,
          imageUrl: msg.imageUrl,
          coinsSent: msg.coinsSent,
          createdAt: msg.createdAt
        });
      }
      // ------------------------------

      res.json({ ok: true, message: msg, coins: req.user.coins });
    } catch (err) {
      console.error("POST /dm/send error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

module.exports = router;