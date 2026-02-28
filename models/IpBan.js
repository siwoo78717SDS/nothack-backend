// models/IpBan.js
const mongoose = require("mongoose");

const ipBanSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, unique: true, index: true, trim: true },
    reason: { type: String, default: "" },
    expiresAt: { type: Date, default: null, index: true } // null = permanent
  },
  { timestamps: true }
);

module.exports = mongoose.models.IpBan || mongoose.model("IpBan", ipBanSchema);