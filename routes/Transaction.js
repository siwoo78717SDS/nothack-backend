const mongoose = require("mongoose");

const TransactionSchema = new mongoose.Schema(
  {
    type: { type: String, required: true, index: true },
    // examples:
    // "game:wordle", "game:quiz:coding", "shop:unlock", "transfer", "admin:adjust"

    fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null, index: true },
    fromUsername: { type: String, default: "" },

    toUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null, index: true },
    toUsername: { type: String, default: "" },

    amount: { type: Number, required: true }, // positive number of coins moved/awarded
    description: { type: String, default: "" },

    meta: { type: Object, default: {} },

    createdAt: { type: Date, default: Date.now, index: true }
  },
  { minimize: false }
);

module.exports = mongoose.model("Transaction", TransactionSchema);