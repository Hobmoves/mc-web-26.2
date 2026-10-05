import init, { game_version, protocol_version, status_handshake, StatusReader } from "./pkg/mc_web.js";

const $ = (id) => document.getElementById(id);
let session = sessionStorageGet("mcweb.session");

function sessionStorageGet(k) { try { return sessionStorage.getItem(k); } catch { return null; } }
function sessionStorageSet(k, v) { try { sessionStorage.setItem(k, v); } catch {} }

async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: { "content-type": "application/json", ...(session ? { authorization: `Bearer ${session}` } : {}) },
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}

function showUser(u) {
  const el = $("auth-out");
  if (u.owns_java) {
    el.className = "ok";
    el.textContent = `Signed in as ${u.name} — Minecraft: Java Edition ownership verified.`;
    $("ping").disabled = false;
    $("ping-out").textContent = "Enter a server and press Ping.";
  } else {
    el.className = "err";
    el.textContent = u.name
      ? `Signed in as ${u.name}, but this account does not own Minecraft: Java Edition.`
      : "Signed in, but this Microsoft account has no Minecraft: Java Edition profile.";
    $("ping").disabled = true;
  }
}

async function signIn() {
  const el = $("auth-out");
  $("signin").disabled = true;
  try {
    const d = await api("/api/auth/start", { method: "POST" });
    el.className = "";
    el.innerHTML = "";
    const p = document.createElement("div");
    p.append("Open ");
    const a = Object.assign(document.createElement("a"), { href: d.verification_uri, target: "_blank", rel: "noopener", textContent: d.verification_uri });
    p.append(a, " and enter:");
    const code = Object.assign(document.createElement("div"), { className: "code", textContent: d.user_code });
    el.append(p, code);

    let interval = d.interval * 1000;
    const deadline = Date.now() + d.expires_in * 1000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, interval));
      const r = await api("/api/auth/poll", { method: "POST", body: JSON.stringify({ device_code: d.device_code }) });
      if (r.status === "slow_down") interval += 5000;
      if (r.status === "done") {
        session = r.session;
        sessionStorageSet("mcweb.session", session);
        showUser(r);
        return;
      }
    }
    throw new Error("sign-in code expired");
  } catch (e) {
    el.className = "err";
    el.textContent = e.message;
  } finally {
    $("signin").disabled = false;
  }
}

function ping() {
  const host = $("host").value.trim();
  const port = Number($("port").value) || 25565;
  const out = $("ping-out");
  if (!host) { out.textContent = "Enter a host."; return; }
  out.className = "muted";
  out.textContent = "Connecting…";
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws?` + new URLSearchParams({ session, host, port }));
  ws.binaryType = "arraybuffer";
  const reader = new StatusReader();
  let done = false;
  ws.onopen = () => ws.send(status_handshake(host, port));
  ws.onmessage = (ev) => {
    try {
      const json = reader.push(new Uint8Array(ev.data));
      if (json !== undefined && json !== null) {
        done = true;
        const s = JSON.parse(json);
        const ok = s.version?.protocol === protocol_version();
        out.className = ok ? "ok" : "muted";
        out.textContent = `${s.version?.name ?? "?"} (protocol ${s.version?.protocol}) — ${s.players?.online ?? "?"}/${s.players?.max ?? "?"} players` +
          (ok ? "" : `\nThis client speaks ${game_version()} (protocol ${protocol_version()}).`);
        ws.close();
      }
    } catch (e) { done = true; out.className = "err"; out.textContent = String(e); ws.close(); }
  };
  ws.onerror = () => { if (!done) { out.className = "err"; out.textContent = "Bridge connection failed (not signed in, or target refused)."; } };
  ws.onclose = () => { if (!done && out.className !== "err") out.textContent = "Connection closed before a status reply."; };
}

(async () => {
  await init();
  $("ver").textContent = `for Java ${game_version()}`;
  const cfg = await api("/api/config");
  if (!cfg.auth_configured) {
    $("auth-out").className = "err";
    $("auth-out").textContent = "Server has no MS_CLIENT_ID configured (see README).";
    $("signin").disabled = true;
  }
  $("signin").onclick = signIn;
  $("ping").onclick = ping;
  if (session) {
    try { showUser(await api("/api/auth/me")); } catch { session = null; }
  }
})();
