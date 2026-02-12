const mongoose = require("mongoose");

const memberSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  username: { type: String, required: true },
  roleInGroup: { type: String, enum: ["owner", "member"], default: "member" },
  joinedAt: { type: Date, default: Date.now }
}, { _id: false });

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, index: true },
  description: { type: String, default: "" },
  isPublic: { type: Boolean, default: true },

  ownerUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  ownerUsername: { type: String, required: true },

  members: { type: [memberSchema], default: [] },

  invites: { type: [String], default: [] }, // usernames invited (for private groups)

  createdAt: { type: Date, default: Date.now },
  lastActivityAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Group", groupSchema);
