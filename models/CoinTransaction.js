const mongoose = require("mongoose");

const coinTransactionSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: [
      "transfer",
      "admin_adjust",
      "level_up",
      "achievement_reward",
      "admin_set_level",
      "admin_set_bans" 
    ],
    required: true,
    index: true
  },

  fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  toUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  fromUsername: { type: String, default: "" },
  toUsername: { type: String, default: "" },

  amount: { type: Number, required: true }, // positive number
  description: { type: String, default: "" },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("CoinTransaction", coinTransactionSchema);