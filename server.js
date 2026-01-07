<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Register</title>
  <style>
    body{margin:0;background:#02060c;color:#eaffee;font-family:ui-monospace,Consolas,monospace}
    .wrap{max-width:520px;margin:0 auto;padding:18px}
    .card{border:1px solid rgba(0,255,160,.35);border-radius:14px;padding:14px;background:rgba(0,0,0,.35);margin:12px 0}
    h1{margin:0 0 10px;letter-spacing:.14em;text-transform:uppercase;color:#9bffd4}
    input{width:100%;padding:10px;border-radius:10px;border:1px solid rgba(0,247,255,.22);background:rgba(0,0,0,.35);color:#eaffee;outline:none;margin-top:10px}
    button{padding:10px 14px;border-radius:12px;border:1px solid rgba(0,255,160,.55);background:rgba(0,0,0,.55);color:#eaffee;cursor:pointer;margin-top:10px;width:100%}
    .muted{opacity:.75}
    a{color:#7df3ff}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Register</h1>
    <div class="card">
      <div class="muted">
        Tip (optional): Set <code>ADMIN_EMAIL</code> in Secrets to auto-make that email an admin.
      </div>

      <input id="name" placeholder="Full name" autocomplete="name" />
      <input id="email" placeholder="Email" autocomplete="email" />
      <input id="username" placeholder="Username" autocomplete="username" />
      <input id="pw" type="password" placeholder="Password" autocomplete="new-password" />
      <button id="btn">Create account</button>

      <div class="muted" style="margin-top:10px">
        Already have an account? <a href="/login">Login</a>
      </div>

      <div class="muted" id="msg" style="margin-top:10px"></div>
    </div>
  </div>

<script>
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { "Content-Type": "application/json" },
      credentials: "include"
    });
    const data = await res.json().catch(()=>({}));
    return { res, data };
  }

  document.getElementById("btn").onclick = async () => {
    const fullName = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("pw").value;
    const msg = document.getElementById("msg");
    msg.textContent = "…";

    const {res, data} = await api("/api/auth/register", {
      method:"POST",
      body: JSON.stringify({ fullName, email, username, password })
    });

    if(!res.ok){
      msg.textContent = data.error || data.message || ("Register failed ("+res.status+")");
      return;
    }

    msg.textContent = "Account created. Redirecting...";
    setTimeout(() => location.href = "/login", 400);
  };
</script>
</body>
</html>
