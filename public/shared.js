window.ZeroPoint = window.ZeroPoint || {};

// ---------- basic helpers ----------

// IMPORTANT:
// Use same-origin API so Vercel can proxy /api/* → Render.
// Do NOT hardcode https://nothack.onrender.com here.
const API_BASE = "";

/**
 * Escape HTML to avoid XSS when inserting user-provided text into the DOM.
 */
ZeroPoint.escapeHtml = function (str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

ZeroPoint.api = {};

/**
 * JSON helper for calling the backend.
 *
 * Example:
 *   const me = await ZeroPoint.api.json("/api/auth/me", { method: "GET" });
 */
ZeroPoint.api.json = async function (url, options = {}) {
  const opts = {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json" },
    credentials: "include" // keep cookies for auth
  };

  if (options.body !== undefined) {
    opts.body = JSON.stringify(options.body);
  }

  // Always go through same-origin URL.
  // When API_BASE == "", "/api/..." stays "/api/...",
  // and vercel.json rewrites it to https://nothack.onrender.com/api/...
  const finalUrl = url.startsWith("http")
    ? url
    : `${API_BASE}${url}`;

  const res = await fetch(finalUrl, opts);
  let data = null;

  try {
    data = await res.json();
  } catch (e) {
    data = { error: "Bad JSON response" };
  }

  if (!res.ok && !data.error) {
    data.error = "Request failed";
  }

  return data;
};

/**
 * Log out current user.
 * POST /api/auth/logout
 */
ZeroPoint.logout = async function () {
  await ZeroPoint.api.json("/api/auth/logout", { method: "POST" });
};

/**
 * Get a path segment from the URL, counting from the end.
 * Example:
 *   /users/123/profile  -> getPathParam(0) = "profile"
 *                         getPathParam(1) = "123"
 */
ZeroPoint.getPathParam = function (indexFromEnd) {
  const parts = location.pathname.split("/").filter(Boolean);
  return parts[parts.length - 1 - (indexFromEnd || 0)];
};

// ---------- UI status helper ----------

/**
 * Show a status message in a small element.
 * type: "info" | "success" | "error"
 *
 * Example:
 *   ZeroPoint.showStatus(msgEl, "Saved!", "success");
 */
ZeroPoint.showStatus = function (el, msg, type) {
  if (!el) return;
  el.textContent = msg || "";
  el.classList.remove("zp-status-info", "zp-status-success", "zp-status-error");

  let cls = "zp-status-info";
  if (type === "success") cls = "zp-status-success";
  else if (type === "error") cls = "zp-status-error";

  el.classList.add(cls);
};

// Inject minimal default styles for .zp-status-*
// (If you already have these in CSS, you can delete this block.)
(function injectZeroPointStatusStyles() {
  if (document.getElementById("zp-status-style")) return;
  const style = document.createElement("style");
  style.id = "zp-status-style";
  style.textContent = `
    .zp-status-info { color: #888; }
    .zp-status-success { color: #1a7f37; }
    .zp-status-error { color: #d73a49; }
  `;
  document.head.appendChild(style);
})();

// ---------- Feature unlock helpers (Feature Shop) ----------

ZeroPoint.unlocks = ZeroPoint.unlocks || {};

/**
 * Load current unlock info for the logged-in user.
 * GET /api/unlocks
 */
ZeroPoint.unlocks.load = async function () {
  return await ZeroPoint.api.json("/api/unlocks", { method: "GET" });
};

/**
 * Buy/unlock a feature by key.
 * POST /api/unlocks/buy  { key }
 */
ZeroPoint.unlocks.buy = async function (key) {
  return await ZeroPoint.api.json("/api/unlocks/buy", {
    method: "POST",
    body: { key }
  });
};