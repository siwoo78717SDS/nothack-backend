const mongoose = require("mongoose");

const wordleGuessSchema = new mongoose.Schema(
  {
    word: { type: String, required: true },     // "crane"
    result: { type: String, required: true }    // e.g. "bgybb" (b=gray, y=yellow, g=green)
  },
  { _id: false }
);

const wordleGameSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    dayKey: { type: String, required: true, index: true }, // "2026-02-24" (UTC)
    answerIndex: { type: Number, required: true },

    guesses: { type: [wordleGuessSchema], default: [] },
    solved: { type: Boolean, default: false },
    claimed: { type: Boolean, default: false }
  },
  { timestamps: true }
);

wordleGameSchema.index({ userId: 1, dayKey: 1 }, { unique: true });

module.exports = mongoose.models.WordleGame || mongoose.model("WordleGame", wordleGameSchema);