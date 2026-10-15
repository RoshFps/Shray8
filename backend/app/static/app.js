// Fetches data from the backend API and fills in the dashboard.

async function getJSON(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
}

// Builds an element with text, never raw HTML, so data can't inject markup.
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function loadSummary() {
  const s = await getJSON("/api/summary");
  document.getElementById("total").textContent = s.total_endpoints;
  document.getElementById("online").textContent = s.online;
  document.getElementById("offline").textContent = s.offline;
  document.getElementById("av").textContent = `${s.av_coverage_percent}%`;
  const n = s.av_needs_attention.length;
  document.getElementById("av-attention").textContent =
    n ? `${n} endpoint(s) need attention: ${s.av_needs_attention.join(", ")}` : "All endpoints protected";
}

async function loadPatches() {
  const p = await getJSON("/api/patches");
  const box = document.getElementById("patches");
  box.replaceChildren();
  for (const [label, value] of [["Critical", p.critical], ["Security", p.security], ["Optional", p.optional]]) {
    const row = el("div", undefined, "bar-row");
    row.append(el("span", label, "bar-label"));
    const bar = el("div", undefined, "bar");
    const fill = el("div", undefined, "bar-fill");
    fill.style.width = `${value}%`;
    bar.append(fill);
    row.append(bar, el("span", `${value}%`, "bar-value"));
    box.append(row);
  }
  const missing = p.systems_missing_critical;
  document.getElementById("patch-warning").textContent =
    missing.length ? `⚠ ${missing.length} systems missing critical patches: ${missing.join(", ")}` : "";
}

async function loadProcesses() {
  const rows = await getJSON("/api/suspicious-processes");
  const body = document.getElementById("processes");
  body.replaceChildren();
  for (const p of rows) {
    const tr = el("tr");
    const time = new Date(p.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    tr.append(el("td", time), el("td", p.hostname), el("td", p.command_line, "mono"), el("td", p.reason));
    body.append(tr);
  }
}

async function loadSoftware() {
  const items = await getJSON("/api/unauthorized-software");
  const list = document.getElementById("software");
  list.replaceChildren();
  for (const s of items) {
    const li = el("li");
    li.append(el("strong", s.software), ` on ${s.hostname} (${s.department})`);
    if (s.severity === "high") li.append(el("span", "Investigate!", "tag"));
    list.append(li);
  }
}

Promise.all([loadSummary(), loadPatches(), loadProcesses(), loadSoftware()])
  .catch((err) => console.error("Failed to load dashboard data:", err));
