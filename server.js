require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const cors = require("cors"); // ⬅️ NEW

const User = require("./models/User");
const IpBan = require("./models/IpBan"); // IP ban model

const authRoutes = require("./routes/auth");
const profileRoutes = require("./routes/profile");
const coinsRoutes = require("./routes/coins");
const achievementsRoutes = require("./routes/achievements");
const chatRoutes = require("./routes/chat");
const groupsRoutes = require("./routes/groups");
const peopleRoutes = require("./routes/people");
const uploadRoutes = require("./routes/upload");
const bugsRoutes = require("./routes/bugs");
const announcementsRoutes = require("./routes/announcements");
const transactionsRoutes = require("./routes/transactions");
const adminRoutes = require("./routes/admin");

const { getClientIp } = require("./routes/_helpers"); // shared helper

const app = express();

// IMPORTANT: makes req.ip work correctly behind proxies (Render/Vercel/Nginx/etc.)
app.set("trust proxy", 1);

// ⬅️ CORS MUST COME EARLY, BEFORE SESSIONS / ROUTES
app.use(
  cors({
    origin: "https://nothack.vercel.app", // your frontend origin
    credentials: true
  })
);

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017";
const MONGODB_DB = process.env.MONGODB_DB || "zeropoint";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";
const IS_PROD = process.env.NODE_ENV === "production";

/**
 * Global IP-ban check.
 * Blocks any request from an IP that exists in IpBan and is not expired.
 */
async function checkIpBan(req, res, next) {
  try {
    const ip = getClientIp(req);
    if (!ip) return next();

    const ban = await IpBan.findOne({ ip }).lean();
    if (!ban) return next();

    if (ban.expiresAt && ban.expiresAt < new Date()) {
      // expired ban, let them through
      return next();
    }

    return res.status(403).json({ error: "This IP is banned." });
  } catch (err) {
    console.error("checkIpBan error:", err.message);
    // IMPORTANT: don't send a 500 JSON here, just skip the check
    // so we don't break login/register with "bad JSON" if something fails
    return next();
  }
}

async function start() {
  await mongoose.connect(MONGODB_URI, { dbName: MONGODB_DB });
  console.log("Connected to MongoDB");

  // bootstrap admin
  const bootUser = process.env.BOOTSTRAP_ADMIN_USERNAME;
  const bootPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (bootUser && bootPass) {
    const exists = await User.findOne({ username: bootUser });
    if (!exists) {
      const passwordHash = await User.hashPassword(String(bootPass));
      await User.create({
        fullName: "Administrator",
        username: String(bootUser),
        passwordHash,
        role: "admin",
        level: 10,
        coins: 999999
      });
      console.log("Bootstrapped admin:", bootUser);
    }
  }

  // Security middlewares
  app.use(
    helmet({
      contentSecurityPolicy: false // keep simple for local dev; tighten later
    })
  );
  app.use(mongoSanitize());

  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true }));

  // IP-ban check BEFORE sessions & routes
  app.use(checkIpBan);

  // sessions
  app.use(
    session({
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: IS_PROD // requires trust proxy when behind HTTPS proxy
      },
      store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        dbName: MONGODB_DB,
        collectionName: "sessions"
      })
    })
  );

  // --- GLOBAL "last online" tracker ---
  // Updates lastSeenAt/lastIp for ANY request while logged in.
  // Throttled to once per 60 seconds per session to avoid DB spam.
  app.use((req, _res, next) => {
    try {
      if (!req.session?.userId) return next();

      const nowMs = Date.now();
      const lastWriteMs = Number(req.session._lastSeenWriteAt || 0);

      if (!lastWriteMs || nowMs - lastWriteMs >= 60 * 1000) {
        const ip = getClientIp(req);

        User.updateOne(
          { _id: req.session.userId },
          {
            $set: {
              lastSeenAt: new Date(nowMs),
              lastIp: ip
            }
          }
        ).catch((err) =>
          console.error("lastSeenAt/lastIp update error:", err.message)
        );

        req.session._lastSeenWriteAt = nowMs;
      }
    } catch (e) {
      console.error("activity tracker error:", e.message);
      // never block request because of tracking
    }
    next();
  });

  // uploads
  app.use("/uploads", express.static(path.join(__dirname, "uploads")));
  // public static
  app.use(express.static(path.join(__dirname, "public")));

  // API routes
  app.use("/api/auth", authRoutes);
  app.use("/api/profile", profileRoutes);
  app.use("/api/coins", coinsRoutes);
  app.use("/api/achievements", achievementsRoutes);
  app.use("/api/chat", chatRoutes);
  app.use("/api/groups", groupsRoutes);
  app.use("/api/people", peopleRoutes);
  app.use("/api/upload", uploadRoutes);
  app.use("/api/bugs", bugsRoutes);
  app.use("/api/announcements", announcementsRoutes);
  app.use("/api/transactions", transactionsRoutes);
  app.use("/api/admin", adminRoutes);

  // Pretty URLs
  app.get("/login", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "login.html"))
  );
  app.get("/register", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "register.html"))
  );
  app.get("/account", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "account.html"))
  );
  app.get("/mypage", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "mypage.html"))
  );
  app.get("/chat", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "chat.html"))
  );
  app.get("/people", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "people.html"))
  );
  app.get("/groups", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "groups.html"))
  );
  app.get("/group/:id", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "group.html"))
  );
  app.get("/admin", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "admin.html"))
  );
  app.get("/levels", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "levels.html"))
  );
  app.get("/level/:num", (req, res) => {
    const n = Number(req.params.num);
    if (!Number.isInteger(n) || n < 1 || n > 10)
      return res.status(404).send("Not found");
    return res.sendFile(path.join(__dirname, "public", `level${n}.html`));
  });

  // NEW: Feature shop pages
  app.get("/shop", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "shop.html"))
  );
  app.get("/how-to-get-coins", (_req, res) =>
    res.sendFile(
      path.join(__dirname, "public", "how-to-get-coins.html")
    )
  );

  // redirects from old .html urls (optional convenience)
  app.get("/levels.html", (_req, res) => res.redirect(301, "/levels"));
  app.get("/mypage.html", (_req, res) => res.redirect(301, "/mypage"));
  app.get("/people.html", (_req, res) => res.redirect(301, "/people"));
  app.get("/groups.html", (_req, res) => res.redirect(301, "/groups"));
  app.get("/admin.html", (_req, res) => res.redirect(301, "/admin"));
  app.get("/chat.html", (_req, res) => res.redirect(301, "/chat"));
  app.get("/account.html", (_req, res) => res.redirect(301, "/account"));

  app.listen(PORT, () =>
    console.log("Server running on http://localhost:" + PORT)
  );
}

start().catch((err) => {
  console.error(err);
  process.exit(1);
});
