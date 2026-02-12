const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const achievementSchema = new mongoose.Schema(
  {
    code: { type: String, required: true },
    title: { type: String, required: true },
    earnedAt: { type: Date, default: Date.now }
  },
  { _id: false }
);

const bansSchema = new mongoose.Schema(
  {
    isBannedFromChat: { type: Boolean, default: false },
    isBannedFromCoins: { type: Boolean, default: false },
    reason: { type: String, default: "" },
    updatedAt: { type: Date, default: Date.now }
  },
  { _id: false }
);

const userSchema = new mongoose.Schema({
  // NOTE: your existing admin document may not have fullName, so don't require it
  fullName: { type: String, default: "" },

  username: { type: String, unique: true, required: true, index: true },
  usernameLower: { type: String, unique: true, index: true },

  // IMPORTANT: your DB uses passHash (and we hide it by default)
  passHash: { type: String, required: true, select: false },

  role: { type: String, enum: ["user", "mod", "admin"], default: "user" },

  coins: { type: Number, default: 0, min: 0 },
  level: { type: Number, default: 1, min: 1 },

  statusMessage: { type: String, default: "" },
  theme: { type: String, default: "classic" }, // classic|green|amber

  achievements: { type: [achievementSchema], default: [] },
  bans: { type: bansSchema, default: () => ({}) },

  unlocks: {
    chat: { type: Boolean, default: false },
    groupChat: { type: Boolean, default: false },
    createGroup: { type: Boolean, default: false },
    imageUpload: { type: Boolean, default: false }
  },

  stats: {
    dmMessagesSent: { type: Number, default: 0 },
    groupMessagesSent: { type: Number, default: 0 },
    groupsCreated: { type: Number, default: 0 },
    imagesSent: { type: Number, default: 0 }
  },

  awardedAchievements: { type: [String], default: [] },
  achievementPoints: { type: Number, default: 0 },

  lastSeenAt: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null },
  lastIp: { type: String, default: "" },

  // NEW: soft delete flag (admin-only)
  isDeleted: { type: Boolean, default: false },

  createdAt: { type: Date, default: Date.now }
});

// auto-fill usernameLower
userSchema.pre("validate", function (next) {
  if (this.username) this.usernameLower = String(this.username).trim().toLowerCase();
  next();
});

userSchema.methods.checkPassword = async function (plain) {
  if (!this.passHash) return false;
  return bcrypt.compare(String(plain), this.passHash);
};

userSchema.statics.hashPassword = async function (password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(String(password), salt);
};

module.exports = mongoose.model("User", userSchema);