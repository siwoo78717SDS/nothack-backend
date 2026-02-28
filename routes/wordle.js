const express = require("express");
const crypto = require("crypto");
const router = express.Router();

const Transaction = require("../models/Transaction");
const WordleGame = require("../models/WordleGame");

const { loadUser } = require("./_helpers");
const { coinLimiter } = require("../services/security");

// Answer list (local file)
const ANSWERS = require("../data/wordle_answers.json");

// Optional API validation
let isValidEnglishWord = null;
try {
  ({ isValidEnglishWord } = require("../services/wordApi"));
} catch (e) {
  isValidEnglishWord = null;
}

// Daily reset hour (0–23). 8 = 8AM local server time.
const RESET_HOUR = 8;

// "Day key" based on 8AM reset boundary
function getDayKeyWithReset(d = new Date()) {
  // shift back RESET_HOUR hours so day changes at RESET_HOUR
  const shifted = new Date(d.getTime() - RESET_HOUR * 3600 * 1000);
  const y = shifted.getFullYear();
  const m = String(shifted.getMonth() + 1).padStart(2, "0");
  const day = String(shifted.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

// Numeric day index from a fixed epoch, using same 8AM rule
function getDayIndexWithReset(d = new Date()) {
  const epoch = new Date(2022, 0, 1, RESET_HOUR, 0, 0, 0); // Jan 1 2022, 8AM local
  const shifted = new Date(d.getTime() - RESET_HOUR * 3600 * 1000);
  return Math.floor((shifted.getTime() - epoch.getTime()) / 86400000);
}

function startOfRewardWindow(d = new Date()) {
  // This defines the "today" window for claiming rewards (same as Wordle day)
  const key = getDayKeyWithReset(d); // "YYYY-MM-DD"
  const [yyyy, mm, dd] = key.split("-").map((x) => parseInt(x, 10));
  return new Date(yyyy, mm - 1, dd, RESET_HOUR, 0, 0, 0);
}

function computeAnswerIndex(dayIndex) {
  if (!Array.isArray(ANSWERS) || ANSWERS.length === 0) {
    throw new Error("Wordle answers list is empty. Fill data/wordle_answers.json");
  }
  const salt = process.env.WORDLE_SALT || "dev-salt-change-me";
  const hash = crypto.createHash("sha256").update(`${dayIndex}:${salt}`).digest();
  const num = hash.readUInt32BE(0);
  return num % ANSWERS.length;
}

function scoreGuess(guess, answer) {
  // returns "g/y/b" string length 5
  const g = guess.split("");
  const a = answer.split("");

  const res = Array(5).fill("b");
  const counts = {};

  // first pass: greens + count remaining answer letters
  for (let i = 0; i < 5; i++) {
    if (g[i] === a[i]) {
      res[i] = "g";
    } else {
      counts[a[i]] = (counts[a[i]] || 0) + 1;
    }
  }

  // second pass: yellows
  for (let i = 0; i < 5; i++) {
    if (res[i] === "g") continue;
    const ch = g[i];
    if (counts[ch] > 0) {
      res[i] = "y";
      counts[ch] -= 1;
    }
  }

  return res.join("");
}

function requireNotDeleted(req, res, next) {
  if (req.user?.isDeleted) return res.status(403).json({ error: "Account deleted" });
  next();
}

async function getOrCreateTodayGame(userId) {
  const dayKey = getDayKeyWithReset();
  const dayIndex = getDayIndexWithReset();
  const answerIndex = computeAnswerIndex(dayIndex);

  let game = await WordleGame.findOne({ userId, dayKey });
  if (game) return { game, dayKey, dayIndex, answerIndex };

  game = await WordleGame.create({
    userId,
    dayKey,
    answerIndex,
    guesses: [],
    solved: false,
    claimed: false
  });

  return { game, dayKey, dayIndex, answerIndex };
}

// GET /api/games/wordle/status
router.get("/status", coinLimiter, loadUser, requireNotDeleted, async (req, res) => {
  try {
    const { game, dayKey } = await getOrCreateTodayGame(req.user._id);

    res.json({
      ok: true,
      dayKey,
      guesses: game.guesses,
      solved: game.solved,
      claimed: game.claimed,
      remaining: Math.max(0, 6 - (game.guesses?.length || 0))
    });
  } catch (err) {
    console.error("GET /api/games/wordle/status error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/games/wordle/validate  { word }
router.post("/validate", coinLimiter, loadUser, requireNotDeleted, async (req, res) => {
  try {
    const w = String(req.body?.word || "").toLowerCase().trim();
    if (!/^[a-z]{5}$/.test(w)) return res.json({ ok: false });

    if (!isValidEnglishWord) return res.json({ ok: true });

    const useApi = String(process.env.WORDLE_USE_API_VALIDATE || "0") === "1";
    if (!useApi) return res.json({ ok: true });

    const ok = await isValidEnglishWord(w);
    return res.json({ ok });
  } catch (err) {
    console.error("POST /api/games/wordle/validate error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/games/wordle/guess  { guess }
router.post("/guess", coinLimiter, loadUser, requireNotDeleted, async (req, res) => {
  try {
    const guess = String(req.body?.guess || "").toLowerCase().trim();
    if (!/^[a-z]{5}$/.test(guess)) return res.status(400).json({ error: "Guess must be 5 letters" });

    const { game, dayKey, answerIndex } = await getOrCreateTodayGame(req.user._id);

    if (game.solved) return res.status(400).json({ error: "Already solved today" });
    if ((game.guesses?.length || 0) >= 6) return res.status(400).json({ error: "No guesses left" });

    const useApi = String(process.env.WORDLE_USE_API_VALIDATE || "0") === "1";
    if (useApi && isValidEnglishWord) {
      const ok = await isValidEnglishWord(guess);
      if (!ok) return res.status(400).json({ error: "Not a valid English word" });
    }

    const answer = String(ANSWERS[answerIndex] || "").toLowerCase();
    const result = scoreGuess(guess, answer);

    game.guesses.push({ word: guess, result });

    if (guess === answer) game.solved = true;

    await game.save();

    res.json({
      ok: true,
      dayKey,
      guess,
      result,
      solved: game.solved,
      remaining: Math.max(0, 6 - game.guesses.length)
    });
  } catch (err) {
    console.error("POST /api/games/wordle/guess error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/games/wordle/claim
router.post("/claim", coinLimiter, loadUser, requireNotDeleted, async (req, res) => {
  try {
    if (req.user.bans?.isBannedFromCoins) {
      return res.status(403).json({ error: "You are banned from using coins" });
    }

    const { game } = await getOrCreateTodayGame(req.user._id);

    if (!game.solved) return res.status(400).json({ error: "Not solved" });
    if (game.claimed) return res.status(429).json({ error: "Already claimed today" });

    // Reward window boundary
    const since = startOfRewardWindow();
    const already = await Transaction.findOne({
      type: "game:wordle",
      toUserId: req.user._id,
      createdAt: { $gte: since }
    }).lean();

    if (already) {
      game.claimed = true;
      await game.save();
      return res.status(429).json({ error: "Already claimed today" });
    }

    const reward = 20;

    req.user.coins = (req.user.coins || 0) + reward;
    await req.user.save();

    await Transaction.create({
      type: "game:wordle",
      toUserId: req.user._id,
      toUsername: req.user.username,
      amount: reward,
      description: "Wordle reward",
      meta: { guessesCount: game.guesses.length, solved: true }
    });

    game.claimed = true;
    await game.save();

    res.json({ ok: true, reward, coins: req.user.coins });
  } catch (err) {
    console.error("POST /api/games/wordle/claim error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;