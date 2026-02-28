const express = require("express");
const router = express.Router();
const User = require("../models/User");
const CoinTransaction = require("../models/CoinTransaction");
const { loadUser, requireAdmin } = require("./_helpers");
const { awardAchievement } = require("../services/achievements");
const { coinLimiter, adminLimiter } = require("../services/security");
const { audit } = require("../services/audit");

// ----------------- helpers -----------------

async function dailyLimitsOK(userId, maxTransfers, maxCoins) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const transfersCount = await CoinTransaction.countDocuments({
    type: "transfer",
    fromUserId: userId,
    createdAt: { $gte: since }
  });
  if (transfersCount >= maxTransfers) {
    return { ok: false, reason: "Daily transfer count limit reached" };
  }

  const tx = await CoinTransaction.find(
    {
      type: "transfer",
      fromUserId: userId,
      createdAt: { $gte: since }
    },
    "amount"
  );

  const sum = tx.reduce((a, t) => a + (t.amount || 0), 0);
  if (sum >= maxCoins) {
    return { ok: false, reason: "Daily coin sending limit reached" };
  }

  return { ok: true };
}

// For simple internal coin awards from games, etc.
async function addCoins(user, amount, type, description, extra = {}) {
  user.coins = (user.coins || 0) + amount;
  await user.save();

  await CoinTransaction.create({
    type,
    toUserId: user._id,
    toUsername: user.username,
    amount,
    description,
    ...extra
  });

  return user.coins;
}

// ---------- ME ----------

router.get("/me", loadUser, async (req, res) => {
  res.json({
    username: req.user.username,
    coins: req.user.coins,
    level: req.user.level,
    role: req.user.role,
    bans: req.user.bans || {},
    achievementPoints: req.user.achievementPoints || 0,
    unlocks: req.user.unlocks || {},
    statusMessage: req.user.statusMessage || ""
  });
});

// ---------- USER COIN ACTIONS ----------

router.post("/transfer", coinLimiter, loadUser, async (req, res) => {
  try {
    const { toUsername, amount } = req.body || {};
    const amt = Number(amount);

    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    if (!toUsername || !Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "Invalid request" });
    }

    const target = await User.findOne({ username: String(toUsername).trim() });
    if (!target) return res.status(404).json({ error: "Target user not found" });
    if (target.username === req.user.username) {
      return res.status(400).json({ error: "Cannot send coins to yourself" });
    }

    // daily limits for non-admin
    if (req.user.role !== "admin") {
      const lim = await dailyLimitsOK(req.user._id, 20, 2000);
      if (!lim.ok) return res.status(429).json({ error: lim.reason });
    }

    if (req.user.coins < amt) return res.status(400).json({ error: "Not enough coins" });

    req.user.coins -= amt;
    await req.user.save();

    // If target is coin-banned, they don't receive coins (still logs transfer)
    if (!target.bans?.isBannedFromCoins) {
      target.coins += amt;
    }
    await target.save();

    await CoinTransaction.create({
      type: "transfer",
      fromUserId: req.user._id,
      toUserId: target._id,
      fromUsername: req.user.username,
      toUsername: target.username,
      amount: amt,
      description: "User transfer"
    });

    res.json({ ok: true, fromCoins: req.user.coins, toCoins: target.coins });
  } catch (err) {
    console.error("POST /coins/transfer error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/level-up", coinLimiter, loadUser, async (req, res) => {
  try {
    const { targetLevel } = req.body || {};
    const lvl = Number(targetLevel);

    if (!Number.isFinite(lvl) || !Number.isInteger(lvl) || lvl <= req.user.level || lvl > 10) {
      return res.status(400).json({ error: "Invalid target level" });
    }

    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    const diff = lvl - req.user.level;
    const cost = diff * 100;

    // admin can level-up free (optional)
    if (req.user.role !== "admin") {
      if (req.user.coins < cost) return res.status(400).json({ error: "Not enough coins" });
      req.user.coins -= cost;
    }

    const oldLevel = req.user.level;
    req.user.level = lvl;
    await req.user.save();

    await CoinTransaction.create({
      type: "level_up",
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      amount: cost,
      description: `Level up ${oldLevel} -> ${lvl}`
    });

    if (lvl >= 2) await awardAchievement(req.user._id, "LEVEL2_UNLOCKED");
    if (lvl >= 3) await awardAchievement(req.user._id, "LEVEL3_UNLOCKED");

    res.json({ ok: true, level: req.user.level, coins: req.user.coins });
  } catch (err) {
    console.error("POST /coins/level-up error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- FEATURE SHOP ----------

const FEATURE_PRICES = {
  chat: 100,
  groupChat: 200,
  createGroup: 300,
  imageUpload: 150
};

router.post("/buy-feature", coinLimiter, loadUser, async (req, res) => {
  try {
    const { featureKey } = req.body || {};
    const key = String(featureKey || "");

    if (!FEATURE_PRICES[key]) {
      return res.status(400).json({ error: "Invalid feature" });
    }

    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    const unlocks = req.user.unlocks || {};
    if (unlocks[key]) {
      return res.status(400).json({ error: "Feature already unlocked" });
    }

    const cost = FEATURE_PRICES[key];
    if (req.user.coins < cost) {
      return res.status(400).json({ error: "Not enough coins" });
    }

    req.user.coins -= cost;
    req.user.unlocks = {
      ...unlocks,
      [key]: true
    };
    await req.user.save();

    await CoinTransaction.create({
      type: "feature_purchase",
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      amount: cost,
      description: `Feature purchase: ${key}`
    });

    res.json({
      ok: true,
      coins: req.user.coins,
      unlocks: req.user.unlocks
    });
  } catch (err) {
    console.error("POST /coins/buy-feature error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- GAME REWARDS ----------

// Wordle
router.post("/wordle-claim", coinLimiter, loadUser, async (req, res) => {
  try {
    const { solved, guesses } = req.body || {};
    if (!solved) {
      return res.status(400).json({ error: "Not solved" });
    }

    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    const reward = 5;
    const newBalance = await addCoins(
      req.user,
      reward,
      "game_wordle",
      `Solved Wordle in ${Array.isArray(guesses) ? guesses.length : "?"} guesses`
    );

    res.json({ ok: true, reward, coins: newBalance });
  } catch (err) {
    console.error("POST /coins/wordle-claim error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Simple coding quiz
const QUIZ_QUESTIONS = [
  {
    id: "q1",
    question: "What does 'const' do in JavaScript?",
    choices: [
      "Declares a constant variable",
      "Declares a global function",
      "Imports a module",
      "Creates a class"
    ],
    answerIndex: 0
  },
  {
    id: "q2",
    question: "Which HTML tag is used to include JavaScript?",
    choices: ["<js>", "<script>", "<javascript>", "<code>"],
    answerIndex: 1
  }
];

router.get("/quiz-coding", coinLimiter, loadUser, (req, res) => {
  const safe = QUIZ_QUESTIONS.map(q => ({
    id: q.id,
    question: q.question,
    choices: q.choices
  }));
  res.json({ questions: safe });
});

router.post("/quiz-coding-submit", coinLimiter, loadUser, async (req, res) => {
  try {
    const { answers } = req.body || {};
    let correct = 0;

    for (const q of QUIZ_QUESTIONS) {
      if (answers && answers[q.id] === q.answerIndex) correct++;
    }

    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    const reward = correct;
    let newBalance = req.user.coins;

    if (reward > 0) {
      newBalance = await addCoins(
        req.user,
        reward,
        "game_quiz_coding",
        `Coding quiz: ${correct}/${QUIZ_QUESTIONS.length} correct`
      );
    }

    res.json({
      ok: true,
      correct,
      total: QUIZ_QUESTIONS.length,
      reward,
      coins: newBalance
    });
  } catch (err) {
    console.error("POST /coins/quiz-coding-submit error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN ----------

router.get("/users", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const users = await User.find(
      {},
      "username role level coins bans statusMessage theme achievementPoints isDeleted"
    )
      .sort({ username: 1 })
      .limit(2000);

    const mapped = users.map(u => ({
      username: u.username,
      role: u.role,
      level: u.level,
      coins: u.coins,
      bans: u.bans || {},
      theme: u.theme || "",
      achievementPoints: u.achievementPoints || 0,
      statusMessage: u.statusMessage || "",
      statusMsg: u.statusMessage || "",
      isDeleted: !!u.isDeleted
    }));

    res.json({ users: mapped });
  } catch (err) {
    console.error("GET /coins/users error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/adjust", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, delta, reason } = req.body || {};
    const d = Number(delta);
    if (!username || !Number.isFinite(d)) return res.status(400).json({ error: "Invalid request" });

    const target = await User.findOne({ username: String(username).trim() });
    if (!target) return res.status(404).json({ error: "User not found" });

    target.coins = Math.max(0, target.coins + d);
    await target.save();

    await CoinTransaction.create({
      type: "admin_adjust",
      toUserId: target._id,
      toUsername: target.username,
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      amount: Math.abs(d),
      description: `Admin adjust (${d >= 0 ? "+" : ""}${d})${
        reason ? " — " + String(reason).slice(0, 200) : ""
      }`
    });

    await audit({
      actor: req.user,
      action: "ADMIN_ADJUST_COINS",
      targetUsername: target.username,
      details: { delta: d, reason: reason || "" },
      ip: req.ip
    });

    res.json({ ok: true, username: target.username, coins: target.coins });
  } catch (err) {
    console.error("POST /coins/adjust error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/set-role", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, role } = req.body || {};
    const cleanName = String(username || "").trim();
    const r = String(role || "").trim();

    if (!cleanName) return res.status(400).json({ error: "Missing username" });
    if (!["user", "mod", "admin"].includes(r)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const target = await User.findOne({ username: cleanName });
    if (!target) return res.status(404).json({ error: "User not found" });

    const oldRole = target.role;
    target.role = r;
    await target.save();

    await CoinTransaction.create({
      type: "admin_set_role",
      toUserId: target._id,
      toUsername: target.username,
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      amount: 0,
      description: `Admin set role ${oldRole} -> ${r}`
    });

    await audit({
      actor: req.user,
      action: "ADMIN_SET_ROLE",
      targetUsername: target.username,
      details: { oldRole, newRole: r },
      ip: req.ip
    });

    res.json({ ok: true, username: target.username, role: target.role });
  } catch (err) {
    console.error("POST /coins/set-role error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/set-level", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, level } = req.body || {};
    const cleanName = String(username || "").trim();
    const lvl = Number(level);

    if (!cleanName) return res.status(400).json({ error: "Missing username" });
    if (!Number.isFinite(lvl) || !Number.isInteger(lvl) || lvl < 1 || lvl > 10) {
      return res.status(400).json({ error: "Invalid level" });
    }

    const target = await User.findOne({ username: cleanName });
    if (!target) return res.status(404).json({ error: "User not found" });

    const oldLevel = target.level;
    target.level = lvl;
    await target.save();

    await CoinTransaction.create({
      type: "admin_set_level",
      toUserId: target._id,
      toUsername: target.username,
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      amount: 0,
      description: `Admin set level ${oldLevel} -> ${lvl}`
    });

    await audit({
      actor: req.user,
      action: "ADMIN_SET_LEVEL",
      targetUsername: target.username,
      details: { oldLevel, newLevel: lvl },
      ip: req.ip
    });

    res.json({ ok: true, username: target.username, level: target.level });
  } catch (err) {
    console.error("POST /coins/set-level error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/set-bans", adminLimiter, loadUser, requireAdmin, async (req, res) => {
  try {
    const { username, chatBan, coinsBan, reason } = req.body || {};
    const cleanName = String(username || "").trim();
    if (!cleanName) return res.status(400).json({ error: "Missing username" });

    const target = await User.findOne({ username: cleanName });
    if (!target) return res.status(404).json({ error: "User not found" });

    target.bans = target.bans || {};
    const old = {
      isBannedFromChat: !!target.bans.isBannedFromChat,
      isBannedFromCoins: !!target.bans.isBannedFromCoins
    };

    if (typeof chatBan === "boolean") target.bans.isBannedFromChat = chatBan;
    if (typeof coinsBan === "boolean") target.bans.isBannedFromCoins = coinsBan;

    if (typeof reason === "string") target.bans.reason = reason.slice(0, 200);
    target.bans.updatedAt = new Date();

    await target.save();

    await CoinTransaction.create({
      type: "admin_set_bans",
      toUserId: target._id,
      toUsername: target.username,
      fromUserId: req.user._id,
      fromUsername: req.user.username,
      amount: 0,
      description: `Admin set bans chat=${target.bans.isBannedFromChat} coins=${target.bans.isBannedFromCoins}`
    });

    await audit({
      actor: req.user,
      action: "ADMIN_SET_BANS",
      targetUsername: target.username,
      details: {
        old,
        new: {
          isBannedFromChat: !!target.bans.isBannedFromChat,
          isBannedFromCoins: !!target.bans.isBannedFromCoins
        },
        reason: target.bans.reason || ""
      },
      ip: req.ip
    });

    res.json({ ok: true, username: target.username, bans: target.bans });
  } catch (err) {
    console.error("POST /coins/set-bans error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;