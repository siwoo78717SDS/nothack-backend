// resetAdmin.js
require("dotenv").config();
const mongoose = require("mongoose");
const User = require("./models/User");

const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017";
const MONGODB_DB = process.env.MONGODB_DB || "zeropoint";

async function run() {
  try {
    await mongoose.connect(MONGODB_URI, { dbName: MONGODB_DB });
    console.log("Connected to MongoDB");

    const username = process.env.BOOTSTRAP_ADMIN_USERNAME;
    const newPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;

    if (!username || !newPass) {
      console.log("Missing BOOTSTRAP_ADMIN_USERNAME or BOOTSTRAP_ADMIN_PASSWORD in .env");
      process.exit(1);
    }

    console.log("Resetting password for", username);

    const user = await User.findOne({
      $or: [{ username }, { usernameLower: username.toLowerCase() }]
    });

    if (!user) {
      console.log("Admin user not found:", username);
      process.exit(0);
    }

    user.passHash = await User.hashPassword(String(newPass));
    await user.save();

    console.log("Admin password reset OK for:", username);
    process.exit(0);
  } catch (e) {
    console.error("resetAdmin error:", e);
    process.exit(1);
  }
}

run();