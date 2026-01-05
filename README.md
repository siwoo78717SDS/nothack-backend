# ZeroPoint Backend (Node.js)

Features:
- User accounts: fullName + username + password (bcrypt hash)
- Roles: user / mod / admin (default user)
- Facts: anyone can read; mods submit; admins approve
- Bans: mods request bans; admins approve; ban by user or IP
- Visit log: records who opened the website (IP + timestamp)
- Command log: only for logged-in users
- Admin control room: /admin (full page)
- Mod panel: /mod (full page)
- Remote control (SSE): clients connect; admin can send to one clientId or all

## Run
npm install
npm start
Open http://localhost:3000/

## Bootstrap admin
Copy .env.example -> .env (optional). If no admin exists, one is created from env vars.

## Frontend integration
Paste the snippets from /admin into your big ZeroPoint HTML (inside your IIFE).
