"use strict";
const token = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
const PRESENT = new Set(["available", "needs_params"]);
let profile = null;
let submitUrl = "";

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function badge(t, c) { return `<span class="badge ${escapeHtml(c)}">${escapeHtml(t)}</span>`; }

function renderProfile(p) {
  const parts = [];
  for (const service of Object.keys(p.services).sort()) {
    const methods = p.services[service];
    const rows = [];
    for (const m of Object.keys(methods).sort()) {
      const rec = methods[m];
      let cov = "";
      if (rec.covered_by) cov = badge(`gli4py: ${rec.covered_by}`, "cov-yes");
      else if (PRESENT.has(rec.status)) cov = badge("not yet wrapped", "cov-no");
      rows.push(`<div class="method"><code>${escapeHtml(m)}</code>${badge(rec.status, "st-" + rec.status)}${badge(rec.risk, "rk-" + rec.risk)}${cov}</div>`);
    }
    parts.push(`<section class="service"><h3>${escapeHtml(service)}</h3>${rows.join("")}</section>`);
  }
  return parts.join("");
}

async function onCapture(e) {
  e.preventDefault();
  $("status").textContent = "Enumerating… this can take a moment.";
  $("result").innerHTML = ""; $("banner").innerHTML = ""; $("actions").hidden = true;
  try {
    const res = await fetch("api/enumerate", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Profiler-Token": token },
      body: JSON.stringify({
        host: $("host").value.trim(),
        username: $("username").value.trim() || "root",
        password: $("password").value,
        ssh: $("ssh").checked,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const data = await res.json();
    profile = data.profile; submitUrl = data.submit_url || "";
    $("status").textContent = "";
    $("banner").innerHTML = data.lookup
      ? `<div class="known">✅ <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is already in the registry.</div>`
      : `<div class="new">🆕 <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is new — please contribute it!</div>`;
    $("result").innerHTML = renderProfile(profile);
    $("actions").hidden = false;
    $("submit").classList.toggle("primary", !data.lookup);
  } catch (err) {
    $("status").textContent = "";
    $("result").innerHTML = `<p class="error">${escapeHtml(err.message || err)}</p>`;
  }
}

function onDownload() {
  const blob = new Blob([JSON.stringify(profile, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = `${profile.id}.json`; a.click();
  URL.revokeObjectURL(a.href);
}

function onSubmit() { if (submitUrl) window.open(submitUrl, "_blank", "noopener"); }

$("form").addEventListener("submit", onCapture);
$("download").addEventListener("click", onDownload);
$("submit").addEventListener("click", onSubmit);
