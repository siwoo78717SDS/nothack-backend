const mongoose = require("mongoose");

const chatMessageSchema = new mongoose.Schema({
  fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  toUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  fromUsername: { type: String, required: true, index: true },
  toUsername: { type: String, required: true, index: true },

  text: { type: String, default: "" },
  imageUrl: { type: String, default: "" },

  coinsSent: { type: Number, default: 0, min: 0 },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("ChatMessage", chatMessageSchema);
