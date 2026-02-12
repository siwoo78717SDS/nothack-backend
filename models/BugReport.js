const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema(
  {
    fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fromUsername: { type: String, required: true },
    roleAtTime: { type: String, required: true },
    text: { type: String, required: true }
  },
  { timestamps: true }
);

const bugReportSchema = new mongoose.Schema(
  {
    creatorUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    creatorUsername: { type: String, required: true, index: true },

    title: { type: String, required: true },
    description: { type: String, required: true },

    status: {
      type: String,
      enum: ["open", "in-progress", "resolved", "closed"],
      default: "open"
    },

    screenshotUrl: { type: String, default: "" },

    messages: { type: [messageSchema], default: [] },
    lastUpdatedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

module.exports = mongoose.model("BugReport", bugReportSchema);
