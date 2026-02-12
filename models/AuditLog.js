const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema({
  actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  actorUsername: { type: String, required: true },
  actorRole: { type: String, required: true },

  action: { type: String, required: true, index: true }, // e.g. "ADMIN_ADJUST_COINS"
  targetUsername: { type: String, default: "" },

  details: { type: Object, default: {} },

  ip: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("AuditLog", auditLogSchema);
