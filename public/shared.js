/* global helper for ZeroPoint pages (login/register/account/admin/mod/index) */
(function(){
  const DEVICE_KEY = "zp_deviceId_v1";

  function makeId(len=20){
    const chars="abcdefghijklmnopqrstuvwxyz0123456789";
    let out="";
    for(let i=0;i<len;i++) out += chars[Math.floor(Math.random()*chars.length)];
    return out;
  }

  function getDeviceId(){
    let d = localStorage.getItem(DEVICE_KEY);
    if(!d || d.length < 6){
      d = "dev_" + makeId(18);
      localStorage.setItem(DEVICE_KEY, d);
    }
    return d;
  }

  async function apiJson(url, opts={}){
    const res = await fetch(url, {
      credentials: "include",
      headers: { "Content-Type": "application/json", ...(opts.headers||{}) },
      ...opts
    });
    const data = await res.json().catch(()=> ({}));
    if(!res.ok) {
      const err = new Error(data.error || "Request failed");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  async function logout(){
    await fetch("/api/auth/logout", { method:"POST", credentials:"include" });
  }

  window.ZeroPoint = {
    getDeviceId,
    logout,
    api: { json: apiJson }
  };
})();
