require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const cors = require("cors");
const http = require("http");              // NEW
const { Server } = require("socket.io");   // NEW

const User = require("./models/User");
const IpBan = require("./models/IpBan");

// routes
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

// NEW routes
const unlocksRoutes = require("./routes/unlocks");
const wordleRoutes = require("./routes/wordle");
const quizRoutes = require("./routes/quiz");

const { getClientIp } = require("./routes/_helpers");

const app = express();
const server = http.createServer(app);      // NEW: wrap Express in HTTP server

// trust proxy for correct req.ip / secure cookies
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017";
const MONGODB_DB = process.env.MONGODB_DB || "zeropoint";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";
const IS_PROD = process.env.NODE_ENV === "production";

/**
 * CORS
 */
const DEFAULT_CORS_ORIGINS = [
  "https://nothack.vercel.app",
  "https://nothack-six.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173"
];

const CORS_ORIGINS = (process.env.CORS_ORIGINS || DEFAULT_CORS_ORIGINS.join(","))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// CORS early
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // same-origin / curl

      if (!IS_PROD) return cb(null, true); // dev: allow all

      if (CORS_ORIGINS.includes(origin)) return cb(null, true);

      return cb(null, false);
    },
    credentials: true
  })
);

/**
 * Global IP-ban check.
 */
async function checkIpBan(req, res, next) {
  try {
    const ip = getClientIp(req);
    if (!ip) return next();

    const ban = await IpBan.findOne({ ip }).lean();
    if (!ban) return next();

    if (ban.expiresAt && ban.expiresAt < new Date()) {
      return next();
    }

    return res.status(403).json({ error: "This IP is banned." });
  } catch (err) {
    console.error("checkIpBan error:", err.message);
    return next();
  }
}

// ----- Socket.IO setup -----
function dmRoomName(a, b) {
  const [u1, u2] = [String(a), String(b)].sort();
  return `dm:${u1}:${u2}`;
}

const io = new Server(server, {
  cors: {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (!IS_PROD) return cb(null, true);
      if (CORS_ORIGINS.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    credentials: true
  }
});

// simple connection handler
io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("join_dm", ({ me, withUser }) => {
    if (!me || !withUser) return;
    const room = dmRoomName(me, withUser);
    socket.join(room);
  });

  socket.on("join_group", ({ groupId }) => {
    if (!groupId) return;
    const room = `group:${groupId}`;
    socket.join(room);
  });

  socket.on("disconnect", () => {
    // optional log
  });
});

// expose io + dmRoomName to routes
app.set("io", io);
app.set("dmRoomName", dmRoomName);
// ----------------------------

async function start() {
  await mongoose.connect(MONGODB_URI, { dbName: MONGODB_DB });
  console.log("Connected to MongoDB");

  // bootstrap admin (FIX: uses passHash, not passwordHash)
  const bootUser = process.env.BOOTSTRAP_ADMIN_USERNAME;
  const bootPass = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (bootUser && bootPass) {
    const exists = await User.findOne({ username: bootUser });
    if (!exists) {
      const passHash = await User.hashPassword(String(bootPass));
      await User.create({
        fullName: "Administrator",
        username: String(bootUser),
        passHash,        // <-- correct field name
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
      contentSecurityPolicy: false
    })
  );
  app.use(mongoSanitize());

  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true }));

  // IP-ban BEFORE sessions & routes
  app.use(checkIpBan);

  /**
   * Sessions
   */
  app.use(
    session({
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: IS_PROD ? "none" : "lax",
        secure: IS_PROD
      },
      store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        dbName: MONGODB_DB,
        collectionName: "sessions"
      })
    })
  );

  // last online tracker
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
    }
    next();
  });

  // static
  app.use("/uploads", express.static(path.join(__dirname, "uploads")));
  app.use(express.static(path.join(__dirname, "public")));

  // API routes
  app.use("/api/auth", authRoutes);
  app.use("/api/profile", profileRoutes);

  // coins + transactions
  app.use("/api/coins", coinsRoutes);
  app.use("/api/transactions", transactionsRoutes);

  // NEW routes
  app.use("/api/unlocks", unlocksRoutes);
  app.use("/api/games/wordle", wordleRoutes);
  app.use("/api/quizzes", quizRoutes);

  // other APIs
  app.use("/api/achievements", achievementsRoutes);
  app.use("/api/chat", chatRoutes);
  app.use("/api/groups", groupsRoutes);
  app.use("/api/people", peopleRoutes);
  app.use("/api/upload", uploadRoutes);
  app.use("/api/bugs", bugsRoutes);
  app.use("/api/announcements", announcementsRoutes);
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

  // ✅ both URLs open the same Groups page
  app.get(["/groups", "/group"], (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "groups.html"))
  );

  // ✅ specific group page
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
    if (!Number.isInteger(n) || n < 1 || n > 10) return res.status(404).send("Not found");
    return res.sendFile(path.join(__dirname, "public", `level${n}.html`));
  });

  // Feature shop + games pages
  app.get("/shop", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "shop.html"))
  );
  app.get("/how-to-get-coins", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "how-to-get-coins.html"))
  );
  app.get("/wordle", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "wordle.html"))
  );
  app.get("/codequiz", (_req, res) =>
    res.sendFile(path.join(__dirname, "public", "codequiz.html"))
  );

  // redirects from old .html urls
  app.get("/levels.html", (_req, res) => res.redirect(301, "/levels"));
  app.get("/mypage.html", (_req, res) => res.redirect(301, "/mypage"));
  app.get("/people.html", (_req, res) => res.redirect(301, "/people"));
  app.get("/groups.html", (_req, res) => res.redirect(301, "/groups"));
  app.get("/admin.html", (_req, res) => res.redirect(301, "/admin"));
  app.get("/chat.html", (_req, res) => res.redirect(301, "/chat"));
  app.get("/account.html", (_req, res) => res.redirect(301, "/account"));

  // use server.listen instead of app.listen
  server.listen(PORT, () =>
    console.log("Server running on http://localhost:" + PORT)
  );
}

start().catch((err) => {
  console.error(err);
  process.exit(1);
});