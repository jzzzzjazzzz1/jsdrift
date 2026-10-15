"use strict";
// All DOM is built with createElement/textContent. Data originates from untrusted target JavaScript,
// so markup is never parsed from strings anywhere in this file.

const SEVS = ["info", "low", "medium", "high", "critical"];
const KINDS = ["secret", "endpoint", "param", "host", "graphql", "route", "sourcemap", "sourcefile"];
const st = { token: "", targets: [], target: "", tab: "changes", run: 0, runs: [], minConf: 60, minSev: "low",
             showFp: false, kind: "", q: "", offset: 0, filesOpen: null };

const h = (tag, props, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;   // CSSOM is allowed by our strict CSP; a style attribute is not
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) e.append(kid.nodeType ? kid : String(kid));
  return e;
};

async function api(path, params, body) {
  const qs = params ? "?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null)) : "";
  const r = await fetch(path + qs, {
    method: body ? "POST" : "GET",
    headers: { "X-JSDrift-Token": st.token, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) throw new Error("Unauthorized: open the full URL printed by `jsdrift serve` (it contains the access token).");
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function boot() {
  const m = location.hash.match(/token=([0-9a-f]+)/);
  try { if (m) sessionStorage.setItem("jsdrift-token", m[1]); st.token = m ? m[1] : sessionStorage.getItem("jsdrift-token") || ""; }
  catch (_) { st.token = m ? m[1] : ""; }
  if (m) history.replaceState(null, "", location.pathname);
  init();
}

async function init() {
  const root = document.getElementById("app");
  try {
    st.targets = await api("/api/targets");
  } catch (e) { root.replaceChildren(h("main", {}, h("div", { class: "notice warn" }, e.message))); return; }
  if (!st.targets.length) { root.replaceChildren(h("main", {}, h("div", { class: "empty" }, "No scans yet. Run `jsdrift scan` first."))); return; }
  if (!st.target || !st.targets.find(t => t.name === st.target)) st.target = st.targets[0].name;
  st.runs = await api("/api/runs", { target: st.target });
  if (!st.run || !st.runs.find(r => r.id === st.run)) st.run = st.runs.length ? st.runs[0].id : 0;
  draw();
}

function sevChips(counts) {
  return h("div", { class: "chips" }, SEVS.slice().reverse().filter(s => counts.by_severity[s]).map(s =>
    h("span", { class: "chip sev-" + s }, `${counts.by_severity[s]} ${s}`)));
}

async function draw() {
  const root = document.getElementById("app");
  const cur = st.targets.find(t => t.name === st.target);
  const header = h("header", {},
    h("div", { class: "brand" }, "js", h("b", {}, "drift")),
    h("select", { onchange: async e => { st.target = e.target.value; st.run = 0; st.offset = 0; await init(); } },
      st.targets.map(t => h("option", { value: t.name, selected: t.name === st.target }, t.name))),
    h("nav", {}, [["changes", "Changes"], ["findings", "Findings"], ["files", "Files"], ["runs", "Runs"]].map(([k, label]) =>
      h("button", { class: st.tab === k ? "on" : "", onclick: () => { st.tab = k; st.offset = 0; draw(); } }, label))),
    h("div", { class: "spacer" }),
    cur ? sevChips(cur.counts) : null);
  const main = h("main", {}, h("p", { class: "boot" }, "loading…"));
  root.replaceChildren(header, main);
  try {
    const view = await ({ changes: viewChanges, findings: viewFindings, files: viewFiles, runs: viewRuns })[st.tab]();
    main.replaceChildren(view);
  } catch (e) { main.replaceChildren(h("div", { class: "notice warn" }, e.message)); }
}

// ---------------------------------------------------------------------------------------- shared bits
function filterBar(onchange, { kinds = false, search = false } = {}) {
  return h("div", { class: "bar" },
    h("label", {}, "min confidence",
      h("input", { type: "number", min: 0, max: 99, value: st.minConf, style: "width:64px",
                   onchange: e => { st.minConf = +e.target.value || 0; st.offset = 0; onchange(); } })),
    h("label", {}, "min severity",
      h("select", { onchange: e => { st.minSev = e.target.value; st.offset = 0; onchange(); } },
        SEVS.map(s => h("option", { value: s, selected: s === st.minSev }, s)))),
    kinds ? h("label", {}, "kind", h("select", { onchange: e => { st.kind = e.target.value; st.offset = 0; onchange(); } },
      [["", "all"], ...KINDS.map(k => [k, k])].map(([v, l]) => h("option", { value: v, selected: v === st.kind }, l)))) : null,
    search ? h("input", { type: "text", placeholder: "search value / rule / hint", value: st.q, style: "min-width:220px",
      onchange: e => { st.q = e.target.value; st.offset = 0; onchange(); } }) : null,
    h("label", {}, h("input", { type: "checkbox", checked: st.showFp, onchange: e => { st.showFp = e.target.checked; onchange(); } }),
      "show false positives"));
}

function findingCard(f, onGone) {
  const valEl = h("div", { class: "val" }, f.value);
  let revealed = false;
  const card = h("div", { class: `card sev-${f.severity}` + (f.triage === "false_positive" ? " fp" : "") });
  const triageBtns = [["confirmed", "Confirmed"], ["reported", "Reported"], ["false_positive", "False positive"], ["new", "Reset"]].map(([k, label]) =>
    h("button", { class: "btn" + (k === "false_positive" ? " fpbtn" : "") + (f.triage === k ? " on" : ""), onclick: async () => {
      await api("/api/triage", null, { target: st.target, id: f.id, triage: k });
      f.triage = k; card.classList.toggle("fp", k === "false_positive");
      for (const b of card.querySelectorAll(".btn")) b.classList.remove("on");
      if (k !== "new") card.querySelector(`[data-t="${k}"]`)?.classList.add("on");
      if (k === "false_positive" && !st.showFp && onGone) onGone(card);
    }, "data-t": k }, label));
  const actions = h("div", { class: "actions" },
    f.kind === "secret" ? h("button", { class: "btn", onclick: async e => {
      revealed = !revealed;
      const full = revealed ? (await api("/api/finding", { id: f.id, reveal: 1 })).value : f.value;
      valEl.textContent = full; e.target.textContent = revealed ? "Hide" : "Reveal";
    } }, "Reveal") : null,
    h("button", { class: "btn", onclick: async e => {
      try {
        const v = revealed || f.kind !== "secret" ? valEl.textContent : (await api("/api/finding", { id: f.id, reveal: 1 })).value;
        await navigator.clipboard.writeText(v); e.target.textContent = "Copied";
        setTimeout(() => e.target.textContent = "Copy", 1200);
      } catch (_) { e.target.textContent = "Copy failed"; }
    } }, "Copy"),
    triageBtns);
  card.append(...[
    h("div", { class: "row1" },
      h("span", { class: "badge " + f.severity }, f.severity.slice(0, 4).toUpperCase()),
      h("span", { class: "kind" }, f.kind), valEl,
      h("div", { class: "conf" }, f.confidence, h("i", {}, h("s", { style: `width:${f.confidence}%` })))),
    h("div", { class: "meta" },
      f.hint ? h("span", {}, f.hint) : null,
      h("span", {}, "rule ", h("code", {}, f.rule)),
      h("span", {}, "first seen run #", f.first_run),
      h("span", {}, "fingerprint ", h("code", {}, f.fp)),
      f.triage !== "new" ? h("span", {}, "triage: ", f.triage) : null),
    h("div", { class: "meta" }, h("span", {}, "in: ", f.found_in || f.sources.slice(0, 3).join(", "),
      !f.found_in && f.sources.length > 3 ? ` (+${f.sources.length - 3})` : "")),
    f.meta && f.meta.note ? h("div", { class: "meta" }, "note: " + f.meta.note) : null,
    f.why.length ? h("details", {}, h("summary", {}, `why this confidence (${f.why.length})`), h("ul", {}, f.why.map(w => h("li", {}, w)))) : null,
    f.context ? h("div", { class: "ctx" }, f.context) : null,
    actions].filter(Boolean));
  return card;
}

function dropCard(card) { card.style.transition = "opacity .25s"; card.style.opacity = 0; setTimeout(() => card.remove(), 250); }

// ---------------------------------------------------------------------------------------- views
async function viewChanges() {
  if (!st.run) return h("div", { class: "empty" }, "No runs yet.");
  const rep = await api("/api/report", { run: st.run, min_conf: st.minConf, min_sev: st.minSev, include_fp: st.showFp ? 1 : 0 });
  const wrap = h("div", {});
  wrap.append(h("div", { class: "bar" },
    h("label", {}, "run", h("select", { onchange: e => { st.run = +e.target.value; draw(); } },
      st.runs.map(r => h("option", { value: r.id, selected: r.id === st.run }, `#${r.id}  ${r.started.replace("T", " ").slice(0, 16)}  ${r.status}${r.baseline ? "  (baseline)" : ""}`))))));
  wrap.append(filterBar(draw));
  if (rep.run.baseline) wrap.append(h("div", { class: "notice" }, "Baseline run: this was the first scan, so everything counts as 'new'. Alerts start from the next run."));
  const cr = rep.stats.crawl || {};
  if (cr.complete === false) wrap.append(h("div", { class: "notice warn" }, "Partial scan: some fetches failed or the file limit was hit. Removals are not reported and earlier findings were kept."));
  if (cr.n_third_party || cr.n_blocked) wrap.append(h("div", { class: "notice" }, `Scope guard: ${cr.n_third_party || 0} out-of-scope script URLs skipped, ${cr.n_blocked || 0} other requests blocked. None were sent.`));
  const hid = rep.hidden || {};
  if (hid.below_threshold || hid.false_positive) wrap.append(h("div", { class: "notice" },
    `Hidden: ${hid.below_threshold || 0} below thresholds, ${hid.false_positive || 0} marked false positive.`));
  let any = false;
  for (const [title, key] of [["New", "new"], ["Reappeared", "reappeared"], ["Removed", "removed"]]) {
    if (!rep[key].length) continue; any = true;
    wrap.append(h("h2", {}, title, " ", h("span", { class: "n" }, rep[key].length)));
    rep[key].forEach(f => wrap.append(findingCard(f, dropCard)));
  }
  for (const [title, key] of [["New JS files", "added"], ["Changed JS files", "changed"], ["JS files gone", "removed"]]) {
    const items = rep.files[key]; if (!items.length) continue; any = true;
    wrap.append(h("h2", {}, title, " ", h("span", { class: "n" }, items.length)));
    wrap.append(h("table", {}, h("tbody", {}, items.map(x => h("tr", {},
      h("td", { class: "mono" }, x.file),
      h("td", {}, key === "changed" ? `+${x.findings_added} / -${x.findings_removed} findings, ${x.old_size} → ${x.new_size} bytes` : (x.size ? x.size + " bytes" : "")))))));
  }
  if (!any) wrap.append(h("div", { class: "empty" }, "No drift above the thresholds in this run."));
  return wrap;
}

async function viewFindings() {
  const wrap = h("div", {});
  wrap.append(filterBar(draw, { kinds: true, search: true }));
  const r = await api("/api/findings", { target: st.target, state: "active", kind: st.kind, min_conf: st.minConf, min_sev: st.minSev,
    triage: st.showFp ? "" : "new,confirmed,reported", q: st.q, limit: 100, offset: st.offset });
  wrap.append(h("div", { class: "bar" }, `${r.total} active findings match`));
  if (!r.items.length) wrap.append(h("div", { class: "empty" }, "Nothing matches these filters."));
  r.items.forEach(f => wrap.append(findingCard(f, dropCard)));
  if (r.total > st.offset + r.items.length)
    wrap.append(h("button", { class: "btn", onclick: () => { st.offset += 100; draw(); } }, "Next 100"));
  if (st.offset) wrap.append(h("button", { class: "btn", onclick: () => { st.offset = Math.max(0, st.offset - 100); draw(); } }, "Previous"));
  return wrap;
}

async function viewFiles() {
  const files = (await api("/api/files", { target: st.target })).filter(f => f.kind === "js" || f.kind === "inline" || f.kind === "map");
  const wrap = h("div", {}, h("div", { class: "bar" }, `${files.length} tracked files (identity ignores build hashes in file names)`));
  const detail = h("div", {});
  wrap.append(h("table", {}, h("thead", {}, h("tr", {}, ["File", "Kind", "State", "Size", "Findings", "Versions", "Last changed"].map(x => h("th", {}, x)))),
    h("tbody", {}, files.map(f => h("tr", { class: "click", onclick: () => showVersions(f, detail) },
      h("td", { class: "mono" }, f.fkey), h("td", {}, f.kind), h("td", {}, f.state), h("td", {}, f.size),
      h("td", {}, f.n_findings), h("td", {}, f.n_versions), h("td", {}, "run #" + f.changed_run))))));
  wrap.append(detail);
  return wrap;
}

async function showVersions(f, box) {
  const vs = (await api("/api/versions", { file_id: f.id })).filter(v => v.has_content);
  if (vs.length < 2) { box.replaceChildren(h("h2", {}, "Diff"), h("div", { class: "notice" }, vs.length ? "Only one stored version so far: nothing to diff yet." : "No stored content for this file.")); return; }
  const mk = (sel) => h("select", {}, vs.map((v, i) => h("option", { value: v.id, selected: i === sel }, `run #${v.run_id}  ${v.sha.slice(0, 10)}  ${v.size}B`)));
  const a = mk(vs.length - 2), b = mk(vs.length - 1), out = h("div", { class: "diff" });
  const go = async () => {
    const r = await api("/api/filediff", { from: a.value, to: b.value });
    out.replaceChildren(...r.lines.map(l => h("div", { class: l.startsWith("+++") || l.startsWith("---") ? "hunk" : l.startsWith("@@") ? "hunk" : l[0] === "+" ? "add" : l[0] === "-" ? "del" : "" }, l || " ")));
  };
  box.replaceChildren(h("h2", {}, "Diff: ", f.fkey), h("div", { class: "bar" }, h("label", {}, "from", a), h("label", {}, "to", b), h("button", { class: "btn", onclick: go }, "Show diff")), out);
  go();
}

async function viewRuns() {
  const runs = await api("/api/runs", { target: st.target });
  return h("div", {}, h("table", {}, h("thead", {}, h("tr", {}, ["Run", "Started", "Status", "Files", "+Findings", "-Findings", "Requests"].map(x => h("th", {}, x)))),
    h("tbody", {}, runs.map(r => h("tr", { class: "click", onclick: () => { st.run = r.id; st.tab = "changes"; draw(); } },
      h("td", {}, "#" + r.id + (r.baseline ? " (baseline)" : "")), h("td", {}, r.started.replace("T", " ")),
      h("td", { class: "status-" + r.status }, r.status),
      h("td", {}, r.stats.files ? `${r.stats.files.total} (${r.stats.files.analyzed} analysed)` : ""),
      h("td", {}, r.stats.findings ? r.stats.findings.added : ""), h("td", {}, r.stats.findings ? r.stats.findings.removed : ""),
      h("td", {}, r.stats.requests ?? ""))))));
}

boot();
