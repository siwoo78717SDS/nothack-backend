const express = require("express");
const router = express.Router();
const Group = require("../models/Group");
const GroupMessage = require("../models/GroupMessage");
const User = require("../models/User");
const { loadUser, requireModOrAdmin } = require("./_helpers");
const { chatLimiter } = require("../services/security");

// NEW: AP/stat progress helper
const { recordFeatureAction } = require("../services/featureProgress");

// ---------- unlock middlewares ----------

function requireCreateGroupUnlocked(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });
  if (!req.user.unlocks?.createGroup) {
    return res.status(403).json({
      error: "Create Group feature is locked. Unlock it in the Feature Shop."
    });
  }
  next();
}

function requireGroupChatUnlocked(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });
  if (!req.user.unlocks?.groupChat) {
    return res.status(403).json({
      error: "Group Chat feature is locked. Unlock it in the Feature Shop."
    });
  }
  next();
}

function requireImageUploadUnlocked(req, res, next) {
  const { imageUrl } = req.body || {};
  const hasImage = !!(imageUrl && String(imageUrl).trim());
  if (!hasImage) return next();

  if (!req.user) return res.status(401).json({ error: "Not logged in" });
  if (!req.user.unlocks?.imageUpload) {
    return res.status(403).json({
      error: "Image Upload feature is locked. Unlock it in the Feature Shop."
    });
  }
  next();
}

// Create group: requires level 3 AND mod/admin AND createGroup unlock
router.post(
  "/create",
  loadUser,
  requireModOrAdmin,
  requireCreateGroupUnlocked,
  async (req, res) => {
    try {
      if (req.user.level < 3) {
        return res.status(403).json({ error: "Level 3 required to create groups" });
      }

      const { name, description, isPublic } = req.body || {};
      const n = String(name || "").trim();
      if (!n || n.length < 3 || n.length > 40) {
        return res.status(400).json({ error: "Group name must be 3-40 characters" });
      }

      const group = await Group.create({
        name: n,
        description: String(description || "").slice(0, 300),
        isPublic: typeof isPublic === "boolean" ? isPublic : true,
        ownerUserId: req.user._id,
        ownerUsername: req.user.username,
        members: [{ userId: req.user._id, username: req.user.username, roleInGroup: "owner" }],
        invites: []
      });

      // NEW: AP/stat progress
      await recordFeatureAction(req.user._id, "createGroup", "groupsCreated", 1);

      res.json({ ok: true, group });
    } catch (err) {
      console.error("POST /groups/create error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// List public groups (for /groups page)
router.get("/public", loadUser, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const filter = { isPublic: true };
    if (q) {
      filter.name = { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), $options: "i" };
    }

    const groups = await Group.find(
      filter,
      "name description isPublic ownerUsername createdAt lastActivityAt members"
    )
      .sort({ lastActivityAt: -1 })
      .limit(50);

    const mapped = groups.map(g => ({
      _id: g._id,
      name: g.name,
      description: g.description,
      ownerUsername: g.ownerUsername,
      createdAt: g.createdAt,
      lastActivityAt: g.lastActivityAt,
      memberCount: (g.members || []).length
    }));

    res.json({ groups: mapped });
  } catch (err) {
    console.error("GET /groups/public error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get group info (member list, public info). Anyone logged-in can view public; private only if member/invited/admin.
router.get("/:id", loadUser, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ error: "Group not found" });

    const isMember = (group.members || []).some(
      m => m.userId.toString() === req.user._id.toString()
    );
    const isInvited = (group.invites || []).includes(req.user.username);
    const isAdmin = req.user.role === "admin";

    if (!group.isPublic && !isMember && !isInvited && !isAdmin) {
      return res.status(403).json({ error: "Private group" });
    }

    res.json({
      group: {
        _id: group._id,
        name: group.name,
        description: group.description,
        isPublic: group.isPublic,
        ownerUsername: group.ownerUsername,
        members: (group.members || []).map(m => ({
          username: m.username,
          roleInGroup: m.roleInGroup
        })),
        invites:
          isAdmin || group.ownerUsername === req.user.username
            ? (group.invites || [])
            : undefined
      },
      viewer: {
        isMember,
        isOwner: group.ownerUsername === req.user.username,
        isAdmin
      }
    });
  } catch (err) {
    console.error("GET /groups/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Join group: anyone can join if public; private requires invite
router.post("/:id/join", loadUser, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ error: "Group not found" });

    const already = (group.members || []).some(
      m => m.userId.toString() === req.user._id.toString()
    );
    if (already) return res.json({ ok: true, joined: true });

    if (!group.isPublic) {
      const invited = (group.invites || []).includes(req.user.username);
      if (!invited && req.user.role !== "admin") {
        return res.status(403).json({ error: "Invite required" });
      }
      // if invited, remove invite
      group.invites = (group.invites || []).filter(u => u !== req.user.username);
    }

    group.members.push({
      userId: req.user._id,
      username: req.user.username,
      roleInGroup: "member"
    });

    group.lastActivityAt = new Date();
    await group.save();

    res.json({ ok: true, joined: true });
  } catch (err) {
    console.error("POST /groups/:id/join error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/:id/leave", loadUser, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ error: "Group not found" });

    // owner can't leave (would orphan group)
    if (group.ownerUsername === req.user.username) {
      return res.status(400).json({ error: "Owner cannot leave the group" });
    }

    group.members = (group.members || []).filter(
      m => m.userId.toString() !== req.user._id.toString()
    );
    group.lastActivityAt = new Date();
    await group.save();

    res.json({ ok: true });
  } catch (err) {
    console.error("POST /groups/:id/leave error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Invite (only owner or admin)
router.post("/:id/invite", loadUser, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ error: "Group not found" });

    const isOwner = group.ownerUsername === req.user.username;
    const isAdmin = req.user.role === "admin";
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ error: "Only owner or admin can invite" });
    }

    const { username } = req.body || {};
    const u = String(username || "").trim();
    if (!u) return res.status(400).json({ error: "Missing username" });

    const target = await User.findOne({ username: u });
    if (!target) return res.status(404).json({ error: "User not found" });

    if (group.isPublic) {
      return res.status(400).json({ error: "This group is public; no invite needed" });
    }

    if ((group.invites || []).includes(u)) return res.json({ ok: true });

    group.invites.push(u);
    await group.save();

    res.json({ ok: true });
  } catch (err) {
    console.error("POST /groups/:id/invite error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// History: only members (or admin) + groupChat unlock
router.get("/:id/history", loadUser, requireGroupChatUnlocked, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ error: "Group not found" });

    const isMember = (group.members || []).some(
      m => m.userId.toString() === req.user._id.toString()
    );
    const isAdmin = req.user.role === "admin";
    if (!isMember && !isAdmin) {
      return res.status(403).json({ error: "Join the group first" });
    }

    const messages = await GroupMessage.find({ groupId: group._id })
      .sort({ createdAt: 1 })
      .limit(200);

    res.json({ messages });
  } catch (err) {
    console.error("GET /groups/:id/history error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Send message: only members; images require level2; user must not be chat-banned
// + groupChat unlock + (if image) imageUpload unlock
router.post(
  "/:id/send",
  chatLimiter,
  loadUser,
  requireGroupChatUnlocked,
  requireImageUploadUnlocked,
  async (req, res) => {
    try {
      if (req.user.bans?.isBannedFromChat) {
        return res.status(403).json({ error: "You are banned from chat" });
      }

      const group = await Group.findById(req.params.id);
      if (!group) return res.status(404).json({ error: "Group not found" });

      const isMember = (group.members || []).some(
        m => m.userId.toString() === req.user._id.toString()
      );
      const isAdmin = req.user.role === "admin";
      if (!isMember && !isAdmin) {
        return res.status(403).json({ error: "Join the group first" });
      }

      const { text, imageUrl } = req.body || {};
      const hasImage = !!(imageUrl && String(imageUrl).trim());
      if (hasImage && req.user.level < 2) {
        return res.status(403).json({ error: "Level 2 required to send images" });
      }

      const msg = await GroupMessage.create({
        groupId: group._id,
        fromUserId: req.user._id,
        fromUsername: req.user.username,
        text: String(text || "").slice(0, 2000),
        imageUrl: hasImage ? String(imageUrl).slice(0, 300) : ""
      });

      group.lastActivityAt = new Date();
      await group.save();

      // NEW: AP/stat progress
      await recordFeatureAction(req.user._id, "groupChat", "groupMessagesSent", 1);
      if (hasImage) {
        await recordFeatureAction(req.user._id, "imageUpload", "imagesSent", 1);
      }

      // NEW: Socket.IO broadcast to group room
      const io = req.app.get("io");
      if (io) {
        io.to(`group:${group._id}`).emit("group_message", {
          _id: msg._id,
          groupId: group._id,
          fromUsername: msg.fromUsername,
          text: msg.text,
          imageUrl: msg.imageUrl,
          createdAt: msg.createdAt
        });
      }

      res.json({ ok: true, message: msg });
    } catch (err) {
      console.error("POST /groups/:id/send error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

module.exports = router;