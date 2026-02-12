// Milestones for AP rewards.
// Keys must match: recordFeatureAction(userId, featureKey, statKey, delta)

const FEATURE_MILESTONES = {
  chat: {
    dmMessagesSent: [
      { count: 1, ap: 1, code: "CHAT_DM_1" },
      { count: 10, ap: 5, code: "CHAT_DM_10" },
      { count: 50, ap: 15, code: "CHAT_DM_50" }
    ]
  },

  groupChat: {
    groupMessagesSent: [
      { count: 1, ap: 1, code: "GROUP_MSG_1" },
      { count: 25, ap: 10, code: "GROUP_MSG_25" }
    ]
  },

  createGroup: {
    groupsCreated: [{ count: 1, ap: 10, code: "GROUP_CREATE_1" }]
  },

  imageUpload: {
    imagesSent: [{ count: 1, ap: 2, code: "IMG_SENT_1" }]
  }
};

module.exports = { FEATURE_MILESTONES };