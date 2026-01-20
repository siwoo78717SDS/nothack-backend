(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  function getDeviceId() {
    let id = localStorage.getItem("zp_device_id");
    if (!id) {
      id =
        (crypto && crypto.randomUUID)
          ? crypto.randomUUID()
          : "dev_" + Math.random().toString(16).slice(2) + Date.now();
      localStorage.setItem("zp_device_id", id);
    }
    return id;
  }

  async function apiMe() {
    const r = await fetch("/api/auth/me", { credentials: "include" });
    return r.json();
  }

  async function apiLogout() {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
  }

  async function apiDevicePing(deviceId) {
    await fetch("/api/device/ping", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ deviceId })
    });
  }

  function ensurePushOverlay() {
    if ($("zpPushOverlay")) return;

    const wrap = document.createElement("div");
    wrap.id = "zpPushOverlay";
    wrap.style.cssText =
      "position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,0.65);z-index:999999;padding:16px;";

    const box = document.createElement("div");
    box.style.cssText =
      "width:min(680px,96vw);background:rgba(8,12,18,0.96);border:1px solid rgba(120,255,200,0.35);border-radius:14px;padding:16px;color:#d6ffe9;font-family:ui-monospace,monospace;";

    box.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <div style="font-weight:700;letter-spacing:0.08em;" id="zpPushTitle">MESSAGE</div>
        <button id="zpPushClose" style="padding:10px 12px;border-radius:10px;border:1px solid rgba(120,255,200,0.35);background:rgba(120,255,200,0.08);color:#d6ffe9;">Close</button>
      </div>
      <pre id="zpPushBody" style="white-space:pre-wrap;margin:12px 0 0;font-size:13px;line-height:1.35;opacity:0.95;"></pre>
      <div style="margin-top:10px;font-size:11px;opacity:0.7;" id="zpPushMeta"></div>
    `;

    wrap.appendChild(box);
    document.body.appendChild(wrap);

    $("zpPushClose").onclick = () => (wrap.style.display = "none");
    wrap.addEventListener("click", (e) => {
      if (e.target === wrap) wrap.style.display = "none";
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") wrap.style.display = "none";
    });
  }

  function printToTermIfPossible(line) {
    const term = $("term");
    if (!term) return;

    const cursor = term.querySelector(".cursor");
    const div = document.createElement("div");
    div.textContent = line;

    if (cursor && cursor.parentNode === term) term.insertBefore(div, cursor);
    else term.appendChild(div);

    term.scrollTop = term.scrollHeight;
  }

  function showPush(data) {
    ensurePushOverlay();

    const title = String(data.title || "ADMIN");
    const body = String(data.body || "");
    const from = String(data.from || "admin");
    const createdAt = String(data.createdAt || "");

    if (data.asShell) printToTermIfPossible(`[${title}] ${body}`);

    $("zpPushTitle").textContent = title;
    $("zpPushBody").textContent = body;
    $("zpPushMeta").textContent = `from: ${from} • at: ${createdAt}`;
    $("zpPushOverlay").style.display = "flex";
  }

  async function initAuthUI() {
    const loginBtn = $("loginBtn");
    const registerBtn = $("registerBtn");
    const myPageBtn = $("myPageBtn");
    const logoutBtn = $("logoutBtn");
    const statusUser = $("statusUser");

    const me = await apiMe();

    // expose for your main UI
    window.ZP_AUTH = { loggedIn: !!me.loggedIn, user: me.loggedIn ? me.user : null };

    if (me.banned) {
      if (loginBtn) loginBtn.style.display = "none";
      if (registerBtn) registerBtn.style.display = "none";
      if (myPageBtn) myPageBtn.style.display = "none";
      if (logoutBtn) logoutBtn.style.display = "none";
      printToTermIfPossible(`BANNED: ${me.reason || "no reason provided"}`);
      if (statusUser) statusUser.textContent = "BANNED";
      return;
    }

    const loggedIn = !!me.loggedIn;

    if (loginBtn) loginBtn.style.display = loggedIn ? "none" : "";
    if (registerBtn) registerBtn.style.display = loggedIn ? "none" : "";
    if (myPageBtn) myPageBtn.style.display = loggedIn ? "" : "none";
    if (logoutBtn) logoutBtn.style.display = loggedIn ? "" : "none";

    if (loginBtn) loginBtn.onclick = () => (location.href = "/login");
    if (registerBtn) registerBtn.onclick = () => (location.href = "/register");
    if (myPageBtn) myPageBtn.onclick = () => (location.href = "/account");

    if (logoutBtn) {
      logoutBtn.onclick = async () => {
        await apiLogout();
        location.href = "/";
      };
    }

    // SSE for admin push popups
    if (loggedIn) {
      const deviceId = getDeviceId();
      try {
        await apiDevicePing(deviceId);
      } catch {}
      const es = new EventSource(`/api/events?deviceId=${encodeURIComponent(deviceId)}`);
      es.addEventListener("push", (ev) => {
        try {
          showPush(JSON.parse(ev.data));
        } catch {}
      });
    }
  }

  window.Zeropoint = { getDeviceId, initAuthUI };
})();
