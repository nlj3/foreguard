// The fleet dashboard — a single self-contained HTML page (no external assets, CSP
// friendly). It holds no secret itself: the viewer pastes an admin token, which the
// page keeps in memory and sends as a Bearer header to the JSON API. Untrusted values
// (instance ids and the like) are rendered with textContent, never innerHTML.

export function dashboardHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Foreguard — Fleet Control Plane</title>
<style>
  :root { color-scheme: light dark; --fg: #1a1a1a; --bg: #ffffff; --muted: #666; --line: #e2e2e2; --accent: #b45309; --card: #fafafa; }
  @media (prefers-color-scheme: dark) { :root { --fg: #e8e8e8; --bg: #141414; --muted: #999; --line: #2c2c2c; --accent: #f59e0b; --card: #1c1c1c; } }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; color: var(--fg); background: var(--bg); }
  header { padding: 20px 24px; border-bottom: 1px solid var(--line); display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
  h1 { font-size: 18px; margin: 0; }
  .tag { color: var(--muted); font-size: 13px; }
  main { padding: 24px; max-width: 1100px; margin: 0 auto; }
  .bar { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
  input, button { font: inherit; padding: 8px 12px; border-radius: 8px; border: 1px solid var(--line); background: var(--card); color: var(--fg); }
  input { flex: 1; min-width: 220px; }
  button { cursor: pointer; border-color: var(--accent); color: var(--accent); background: transparent; }
  button:hover { background: var(--accent); color: var(--bg); }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
  .card .n { font-size: 24px; font-weight: 600; }
  .card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  .scroll { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
  th, td { text-align: right; padding: 8px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
  th:first-child, td:first-child { text-align: left; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; }
  .msg { color: var(--muted); }
  .err { color: #dc2626; }
  code { color: var(--accent); }
</style>
</head>
<body>
<header>
  <h1>🛡 Foreguard</h1><span class="tag">fleet control plane</span>
</header>
<main>
  <div class="bar">
    <input id="tok" type="password" placeholder="admin token" autocomplete="off" />
    <button id="load">Load fleet</button>
  </div>
  <div id="cards" class="cards"></div>
  <div class="scroll"><table id="tbl" hidden>
    <thead><tr>
      <th>instance</th><th>last seen</th><th>spend</th><th>total</th>
      <th>executed</th><th>dry-run</th><th>denied</th><th>policy-denied</th><th>forwarded</th><th>seq</th>
    </tr></thead>
    <tbody></tbody>
  </table></div>
  <p id="msg" class="msg">Paste an admin token and load the fleet.</p>
</main>
<script>
  const $ = (id) => document.getElementById(id);
  const money = (c) => "$" + (c / 100).toFixed(2);
  const when = (ms) => ms ? new Date(ms).toLocaleString() : "—";
  function card(label, n) {
    const d = document.createElement("div"); d.className = "card";
    const a = document.createElement("div"); a.className = "n"; a.textContent = n;
    const b = document.createElement("div"); b.className = "l"; b.textContent = label;
    d.append(a, b); return d;
  }
  function cell(v, tag = "td") { const el = document.createElement(tag); el.textContent = String(v); return el; }
  async function load() {
    const token = $("tok").value.trim();
    if (!token) { $("msg").textContent = "Enter a token first."; return; }
    $("msg").className = "msg"; $("msg").textContent = "Loading…";
    let data;
    try {
      const res = await fetch("/v1/fleet", { headers: { authorization: "Bearer " + token } });
      if (!res.ok) { $("msg").className = "err"; $("msg").textContent = "Error " + res.status + " — check the token."; return; }
      data = await res.json();
    } catch (e) { $("msg").className = "err"; $("msg").textContent = "Network error."; return; }

    const cards = $("cards"); cards.replaceChildren();
    cards.append(
      card("instances", data.instance_count),
      card("fleet spend", money(data.total_spend_cents)),
      card("total actions", data.instances.reduce((s, r) => s + r.total, 0)),
      card("policy-blocked", data.instances.reduce((s, r) => s + r.policy_denied, 0)),
    );
    const tb = $("tbl").querySelector("tbody"); tb.replaceChildren();
    for (const r of data.instances) {
      const tr = document.createElement("tr");
      tr.append(
        cell(r.id, "th"), cell(when(r.last_seen)), cell(money(r.spent_cents)),
        cell(r.total), cell(r.executed), cell(r.dry_run), cell(r.denied),
        cell(r.policy_denied), cell(r.forwarded), cell(r.last_seq),
      );
      tb.appendChild(tr);
    }
    $("tbl").hidden = data.instances.length === 0;
    $("msg").textContent = data.instances.length ? "" : "No instances have reported yet.";
  }
  $("load").addEventListener("click", load);
  $("tok").addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
</script>
</body>
</html>`;
}
