const path = require("path");
const express = require("express");

const User = require("../models/User");
const CoinTransaction = require("../models/CoinTransaction");
const CodeQuizAttempt = require("../models/CodeQuizAttempt");

const router = express.Router();

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}

// Local-date day key (server time)
function getDayKey() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

// small deterministic hash
function hashStringToSeed(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

// deterministic RNG
function mulberry32(seed) {
  return function () {
    let t = (seed += 0x6D2B79F5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ✅ 5 random questions/day + shuffled order (deterministic per dayKey)
function pickDailyQuestionIds(dayKey, count, bankLen) {
  const rng = mulberry32(hashStringToSeed(dayKey));
  const picked = [];
  const used = new Set();

  while (picked.length < Math.min(count, bankLen)) {
    const id = Math.floor(rng() * bankLen);
    if (!used.has(id)) {
      used.add(id);
      picked.push(id);
    }
  }

  // shuffle picked order (deterministic per dayKey)
  for (let i = picked.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [picked[i], picked[j]] = [picked[j], picked[i]];
  }

  return picked;
}

// question bank
const BANK = require(path.join(__dirname, "..", "data", "codequiz_questions.json"));

const QUESTIONS_PER_DAY = 5;

// Reward table by score (0..5 correct)
const REWARD_TABLE = [0, 2, 5, 10, 20, 35];

function rewardForScore(score) {
  const s = Math.max(0, Math.min(QUESTIONS_PER_DAY, Number(score) || 0));
  return REWARD_TABLE[s] ?? 0;
}

function buildReview(attempt, answers) {
  return attempt.questionIds.map((qid, i) => {
    const q = BANK[qid];
    const yourIndex = Number(answers[i]);
    const correctIndex = Number(q.answerIndex);

    return {
      i,
      prompt: q.prompt,
      choices: q.choices,
      yourIndex,
      correctIndex,
      yourText: q.choices[yourIndex] ?? "(no answer)",
      correctText: q.choices[correctIndex],
      isCorrect: yourIndex === correctIndex
    };
  });
}

router.get("/codequiz/today", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const dayKey = getDayKey();

    let attempt = await CodeQuizAttempt.findOne({ userId, dayKey });

    if (!attempt) {
      const questionIds = pickDailyQuestionIds(dayKey, QUESTIONS_PER_DAY, BANK.length);
      attempt = await CodeQuizAttempt.create({
        userId,
        dayKey,
        questionIds,
        max: questionIds.length
      });
    }

    const questions = attempt.questionIds.map((qid, i) => {
      const q = BANK[qid];
      return {
        i,
        prompt: q.prompt,
        choices: q.choices
      };
    });

    const payload = {
      dayKey,
      questions,
      attempt: {
        completed: Boolean(attempt.completedAt),
        score: attempt.score,
        max: attempt.max,
        passed: attempt.passed,
        claimed: attempt.claimed
      },
      rules: {
        questionsPerDay: QUESTIONS_PER_DAY,
        rewardTable: REWARD_TABLE
      }
    };

    if (attempt.completedAt) {
      payload.review = buildReview(attempt, attempt.answers || []);
      payload.rewardEstimate = rewardForScore(attempt.score);
    }

    return res.json(payload);
  } catch (e) {
    console.error("codequiz/today error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

router.post("/codequiz/submit", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const dayKey = getDayKey();

    const attempt = await CodeQuizAttempt.findOne({ userId, dayKey });
    if (!attempt) return res.status(400).json({ error: "No quiz for today." });
    if (attempt.completedAt) return res.status(400).json({ error: "Already submitted today." });

    const answers = Array.isArray(req.body.answers) ? req.body.answers : [];
    if (answers.length !== attempt.questionIds.length) {
      return res.status(400).json({ error: "Answer count mismatch." });
    }

    let score = 0;
    for (let i = 0; i < attempt.questionIds.length; i++) {
      const qid = attempt.questionIds[i];
      const correct = BANK[qid].answerIndex;
      if (Number(answers[i]) === Number(correct)) score++;
    }

    attempt.answers = answers.map((x) => Number(x));
    attempt.score = score;
    attempt.max = attempt.questionIds.length;

    // keep passed as a fun flag (optional)
    attempt.passed = score >= 4;

    attempt.completedAt = new Date();
    await attempt.save();

    const review = buildReview(attempt, attempt.answers);
    const rewardEstimate = rewardForScore(attempt.score);

    return res.json({
      ok: true,
      score: attempt.score,
      max: attempt.max,
      passed: attempt.passed,
      claimed: attempt.claimed,
      canClaim: attempt.completedAt && !attempt.claimed,
      rewardEstimate,
      review
    });
  } catch (e) {
    console.error("codequiz/submit error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

router.post("/codequiz/claim", requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const dayKey = getDayKey();

    const attempt = await CodeQuizAttempt.findOne({ userId, dayKey });
    if (!attempt) return res.status(400).json({ error: "No quiz for today." });
    if (!attempt.completedAt) return res.status(400).json({ error: "Submit first." });
    if (attempt.claimed) return res.status(400).json({ error: "Already claimed." });

    const user = await User.findById(userId);
    if (!user) return res.status(400).json({ error: "User not found." });

    const reward = rewardForScore(attempt.score);

    if (reward > 0) {
      user.coins = Number(user.coins || 0) + reward;
      await user.save();

      await CoinTransaction.create({
        type: "game_reward",
        toUserId: user._id,
        toUsername: user.username,
        amount: reward,
        description: `CodeQuiz reward (${dayKey}) score=${attempt.score}/${attempt.max}`
      });
    }

    attempt.claimed = true;
    await attempt.save();

    return res.json({
      ok: true,
      coins: user.coins,
      reward
    });
  } catch (e) {
    console.error("codequiz/claim error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;