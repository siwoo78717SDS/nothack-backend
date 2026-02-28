const mongoose = require("mongoose");

const codeQuizAttemptSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  dayKey: { type: String, required: true, index: true }, // e.g. "2026-02-25"

  questionIds: { type: [Number], default: [] }, // indices into question bank
  answers: { type: [Number], default: [] },     // answerIndex chosen per question
  score: { type: Number, default: 0 },
  max: { type: Number, default: 0 },
  passed: { type: Boolean, default: false },

  completedAt: { type: Date, default: null },
  claimed: { type: Boolean, default: false },

  createdAt: { type: Date, default: Date.now }
});

codeQuizAttemptSchema.index({ userId: 1, dayKey: 1 }, { unique: true });

module.exports = mongoose.model("CodeQuizAttempt", codeQuizAttemptSchema);