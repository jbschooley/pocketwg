"use strict";
const $ = (id) => document.getElementById(id);
const api = async (path, opts) => {
  const r = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));
  let body = {};
  try { body = await r.json(); } catch (e) {}
  return { ok: r.ok, status: r.status, body };
};
const show = (id) => {
  for (const v of ["view-setup", "view-login", "view-app"]) $(v).classList.add("hidden");
  $(id).classList.remove("hidden");
  $("logout").classList.toggle("hidden", id !== "view-app");
};

async function route() {
  const { body } = await api("/api/auth");
  if (body.setup_needed) return show("view-setup");
  if (!body.authed) return show("view-login");
  show("view-app");
  refresh();
}

// ---- setup / login ----
$("su-go").onclick = async () => {
  $("su-err").textContent = "";
  const { ok, body } = await api("/api/setup", { method: "POST",
    body: JSON.stringify({ User: $("su-user").value, Password: $("su-pass").value }) });
  if (!ok) return ($("su-err").textContent = body.error || "error");
  // auto-login after setup
  await api("/api/login", { method: "POST",
    body: JSON.stringify({ User: $("su-user").value, Password: $("su-pass").value }) });
  route();
};
$("li-go").onclick = async () => {
  $("li-err").textContent = "";
  const { ok, body } = await api("/api/login", { method: "POST",
    body: JSON.stringify({ User: $("li-user").value, Password: $("li-pass").value }) });
  if (!ok) return ($("li-err").textContent = body.error || "error");
  route();
};
$("logout").onclick = async () => { await api("/api/logout", { method: "POST" }); route(); };

// ---- tunnels ----
// name of the tunnel whose edit form is currently open; refresh() skips just this
// one card so the poll keeps updating all the others without wiping the open form.
let editing = null;
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtAgo(sec) {
  if (!sec) return "never";
  // boringtun's userspace `wg show dump` reports the handshake as seconds-SINCE-handshake
  // (a small value that resets to 0 at each rekey), while the kernel / real wg reports an
  // absolute Unix epoch. So: a large value is an epoch (subtract from now); a small value
  // is already the age in seconds.
  const d = sec >= 1000000000 ? Math.floor(Date.now() / 1000) - sec : sec;
  if (d < 0) return "just now";
  if (d < 60) return d + "s ago";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago";
  return Math.floor(d / 86400) + "d ago";
}

// Reconcile the tunnel list in place: update only the live fields on existing cards,
// add/remove cards as tunnels appear/disappear, and never touch a card being edited.
// This lets stats keep refreshing without wiping an open edit form.
async function refresh() {
  const { ok, body } = await api("/api/tunnels");
  if (!ok) { if (body.error === "unauthorized") route(); return; }
  const box = $("tunnels");
  const list = body.tunnels || [];
  if (!list.length) { box.innerHTML = '<div class="card muted">No tunnels yet — add one below.</div>'; return; }
  if (box.querySelector(".muted")) box.innerHTML = ""; // drop the empty-state placeholder
  const seen = new Set();
  for (const t of list) {
    seen.add(t.name);
    let card = null;
    box.querySelectorAll(".card[data-tunnel]").forEach((c) => { if (c.dataset.tunnel === t.name) card = c; });
    if (!card) { card = buildCard(t); box.appendChild(card); }
    if (editing === t.name) continue;                       // being edited — leave the form alone
    if (card.querySelector(".ed-conf")) {                   // stale edit form (cancelled/saved) — restore
      const fresh = buildCard(t); box.replaceChild(fresh, card); card = fresh;
    }
    updateCard(card, t);
  }
  box.querySelectorAll(".card[data-tunnel]").forEach((c) => { if (!seen.has(c.dataset.tunnel)) c.remove(); });
}

// build a fresh card with a stable structure; handlers are wired once (not re-attached each poll)
function buildCard(t) {
  const card = document.createElement("div");
  card.className = "card";
  card.dataset.tunnel = t.name;
  card.innerHTML = `
    <div class="row">
      <div><span class="tname">${t.name}</span>
        <span class="badge down">down</span></div>
      <label class="switch"><input type="checkbox" data-n="${t.name}">
        <span class="slider"></span></label>
    </div>
    <div class="meta"></div>
    <div class="row" style="margin-top:10px; justify-content:flex-end; gap:8px">
      <button class="ghost" data-edit="${t.name}">Edit</button>
      <button class="danger" data-del="${t.name}">Delete</button>
    </div>`;
  card.querySelector("button[data-edit]").onclick = () => editTunnel(t.name, card);
  card.querySelector("button[data-del]").onclick = async () => {
    if (!confirm(`Delete tunnel ${t.name}?`)) return;
    await api(`/api/tunnels/${t.name}`, { method: "DELETE" });
    refresh();
  };
  card.querySelector("input[data-n]").onchange = async (e) => {
    const cb = e.target; cb.disabled = true;
    const { ok, body } = await api(`/api/tunnels/${t.name}/${cb.checked ? "enable" : "disable"}`, { method: "POST" });
    if (!ok) alert(body.error || "failed");
    cb.disabled = false;
    refresh();
  };
  return card;
}

// update only the mutable fields of an existing card — no innerHTML rebuild, no lost handlers
function updateCard(card, t) {
  const st = t.status || {}; const up = !!st.up;
  const peer = (st.peers && st.peers[0]) || {};
  const badge = card.querySelector(".badge");
  badge.className = "badge " + (up ? "up" : "down");
  badge.textContent = up ? "up" : "down";
  card.querySelector(".meta").innerHTML =
    `${peer.endpoint ? `endpoint <code>${peer.endpoint}</code> · ` : ""}` +
    `handshake ${fmtAgo(peer.last_handshake)} · ↓ ${fmtBytes(peer.rx_bytes)} ↑ ${fmtBytes(peer.tx_bytes)}`;
  const cb = card.querySelector("input[data-n]");
  if (cb && !cb.disabled) cb.checked = t.enabled; // don't fight an in-flight toggle
}

// ---- edit an existing tunnel ----
async function editTunnel(name, card) {
  editing = name; // mark before the fetch so a concurrent poll won't rebuild this card
  const { ok, body } = await api(`/api/tunnels/${name}/config`);
  if (!ok) { editing = null; return; }
  card.innerHTML = `
    <div class="tname">Edit ${name}</div>
    <textarea class="ed-conf" spellcheck="false"></textarea>
    <div class="err ed-err"></div>
    <div class="row" style="margin-top:10px; justify-content:flex-end; gap:8px">
      <button class="ghost ed-cancel">Cancel</button>
      <button class="ed-save">Save &amp; re-apply</button>
    </div>`;
  const ta = card.querySelector(".ed-conf");
  ta.value = body.conf; // set via value to avoid HTML escaping issues
  card.querySelector(".ed-cancel").onclick = () => { editing = null; refresh(); };
  card.querySelector(".ed-save").onclick = async () => {
    const r = await api(`/api/tunnels/${name}`, { method: "PUT", body: JSON.stringify({ Conf: ta.value }) });
    if (!r.ok) { card.querySelector(".ed-err").textContent = r.body.error || "error"; return; } // stay open on error
    editing = null;
    refresh();
  };
}

// ---- import ----
$("im-file").onchange = (e) => {
  const f = e.target.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    $("im-conf").value = r.result;
    if (!$("im-name").value) $("im-name").value = f.name.replace(/\.conf$/i, "").slice(0, 15);
  };
  r.readAsText(f);
};
$("im-go").onclick = async () => {
  $("im-err").textContent = "";
  const { ok, body } = await api("/api/tunnels", { method: "POST",
    body: JSON.stringify({ Name: $("im-name").value.trim(), Conf: $("im-conf").value }) });
  if (!ok) return ($("im-err").textContent = body.error || "error");
  $("im-name").value = ""; $("im-conf").value = ""; $("im-file").value = "";
  refresh();
};
$("im-key").onclick = async () => {
  const { ok, body } = await api("/api/genkey");
  if (!ok) return;
  const out = $("im-keyout");
  out.classList.remove("hidden");
  out.innerHTML = `PrivateKey <code>${body.private_key}</code><br>PublicKey <code>${body.public_key}</code>`;
};

// poll status while on the app view — refresh() updates cards in place and skips the
// one being edited, so live stats keep flowing without disturbing an open edit form
setInterval(() => { if (!$("view-app").classList.contains("hidden")) refresh(); }, 5000);
route();
