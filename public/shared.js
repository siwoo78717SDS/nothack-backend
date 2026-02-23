window.ZeroPoint = window.ZeroPoint || {};

// ---------- basic helpers ----------

// Backend API base (Render)
const API_BASE = "https://nothack.onrender.com";

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
ZeroPoint.api.json = async function (url, options = {}) {
  const opts = {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json" },
    credentials: "include"
  };
  if (options.body !== undefined) opts.body = JSON.stringify(options.body);

  // prepend API_BASE if url starts with "/"
  const finalUrl = url.startsWith("http")
    ? url
    : `${API_BASE}${url}`;

  const res = await fetch(finalUrl, opts);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = { error: "Bad JSON response" };
  }
  if (!res.ok && !data.error) data.error = "Request failed";
  return data;
};

ZeroPoint.logout = async function () {
  await ZeroPoint.api.json("/api/auth/logout", { method: "POST" });
};

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

// Optional minimal styles (only if you want to rely on them globally).
// If you already style .zp-status-* in your CSS, you can delete this block.
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