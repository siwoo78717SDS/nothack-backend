const mongoose = require("mongoose");

const groupMessageSchema = new mongoose.Schema({
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: "Group", required: true, index: true },
  fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  fromUsername: { type: String, required: true },

  text: { type: String, default: "" },
  imageUrl: { type: String, default: "" },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("GroupMessage", groupMessageSchema);
