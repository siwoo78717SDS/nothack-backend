const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema(
  {
    actorUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
      index: true
    },
    actorUsername: { type: String, default: "" },
    actorRole: { type: String, default: "" },

    action: { type: String, required: true, index: true }, // e.g. "ADMIN_ADJUST_COINS"
    targetUsername: { type: String, default: "", index: true },

    details: { type: Object, default: {} },
    ip: { type: String, default: "" }
  },
  {
    timestamps: true, // createdAt + updatedAt
    minimize: false
  }
);

auditLogSchema.index({ createdAt: -1 });

module.exports =
  mongoose.models.AuditLog || mongoose.model("AuditLog", auditLogSchema);