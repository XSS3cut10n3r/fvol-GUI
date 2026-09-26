// The process spine: an interactive process tree (with lifelines on the capture's time axis
// and "find evil" hints) and the per-process view that pivots every relevant plugin to one PID.

import { store, on, emit, el, clear, runPlugin, whenDone, allRows, cellText, parseTime, fmtTime, fmtCount, copy, shortName, prefs } from './core.js';
import { PROCLIST, PCOLS, PIVOTS, CMDLINE, WIN_PARENTS, WIN_SINGLETONS, SUSPICIOUS_CHILDREN, blurb } from './catalog.js';
import { ResultPanel, captureTime, relToCapture, hexTarget } from './result.js';


const tree = { nodes: [], byPid: new Map(), roots: [], expanded: new Set(), cursor: 0, flat: [], filter: '', selected: null, loadedFor: null };

function pick(cols, names) {
  for (const n of names) { const i = cols.findIndex(c => c.name === n); if (i >= 0) return i; }
  return -1;
}

export function plugin(name) { return store.pluginMap.get(name); }
export function firstPlugin(cands) { return cands.find(n => store.pluginMap.has(n)); }

/** Load the process list for the current session (runs pslist once, cached server-side). */
export function loadProcs() {
  const s = store.session;
  if (!s || s.state !== 'ready' || !s.os) return Promise.resolve();
  if (tree.loadedFor === s.id && tree.loading) return tree.loading;
  tree.loadedFor = s.id;
  tree.loading = loadProcsFor(s);
  return tree.loading;
}

async function loadProcsFor(s) {
  const name = firstPlugin(PROCLIST[s.os] || []);
  const treeEl = document.getElementById('tree');
  if (!name) { treeEl.replaceChildren(el('div.tree-empty', { text: 'No process list plugin for this OS in this build.' })); return; }
  treeEl.replaceChildren(el('div.tree-empty', {}, el('span.spinner', { style: { display: 'inline-block', verticalAlign: '-3px', marginRight: '8px' } }), 'Walking the process list…'));
  let run;
  try {
    run = await runPlugin(name, {}, { reuse: true, origin: 'spine' });
  } catch (e) {
    treeEl.replaceChildren(el('div.tree-empty', { text: 'Could not list processes: ' + e.message }));
    return;
  }
  store.procRun = run.id;
  const done = await whenDone(run.id);
  if (done.status !== 'done') {
    treeEl.replaceChildren(el('div.tree-empty', {}, el('b', { text: (done.error && done.error.title) || 'The process list failed.' }), el('br'), done.error ? done.error.message : ''));
    return;
  }
  const rows = await allRows(run.id);
  const cols = done.cols;
  const ix = Object.fromEntries(Object.entries(PCOLS).map(([k, names]) => [k, pick(cols, names)]));
  const g = (row, k) => (ix[k] >= 0 ? row[ix[k] + 2] : null);
  const procs = rows.map((row, i) => {
    const pid = Number(cellText(g(row, 'pid')));
    const create = parseTime(g(row, 'create'));
    const exit = parseTime(g(row, 'exit'));
    return {
      i, pid, ppid: Number(cellText(g(row, 'ppid'))), name: cellText(g(row, 'name')),
      create, exit, offset: g(row, 'offset'), threads: g(row, 'threads'), handles: g(row, 'handles'),
      session: g(row, 'session'), wow64: g(row, 'wow64'), uid: g(row, 'uid'), row, cols, flags: [],
    };
  });
  store.procs = procs;
  build(procs);
  emit('procs', procs);
  // enrich with image paths / command lines from pstree (windows) in the background
  const pst = s.os === 'windows' && firstPlugin(['windows.pstree.PsTree']);
  if (pst) {
    runPlugin(pst, {}, { reuse: true, origin: 'spine' }).then(r => whenDone(r.id)).then(async r => {
      if (r.status !== 'done') return;
      const prow = await allRows(r.id);
      const pi = pick(r.cols, ['PID']), path = pick(r.cols, ['Path']), cmd = pick(r.cols, ['Cmd']);
      for (const row of prow) {
        const p = tree.byPid.get(Number(row[pi + 2]));
        if (!p) continue;
        if (path >= 0 && typeof row[path + 2] === 'string') p.path = row[path + 2];
        if (cmd >= 0 && typeof row[cmd + 2] === 'string') p.cmd = row[cmd + 2];
      }
      emit('procs', procs);
    }).catch(() => {});
  }
}

function build(procs) {
  tree.byPid = new Map();
  for (const p of procs) if (!tree.byPid.has(p.pid) || (p.exit === null)) tree.byPid.set(p.pid, p);
  for (const p of procs) { p.kids = []; p.parent = null; }
  for (const p of procs) {
    const par = p.ppid !== 0 || p.pid === 0 ? tree.byPid.get(p.ppid) : null;
    if (par && par !== p && !isAncestor(p, par)) { p.parent = par; par.kids.push(p); }
  }
  for (const p of procs) p.kids.sort((a, b) => (a.create ?? 0) - (b.create ?? 0) || a.pid - b.pid);
  tree.roots = procs.filter(p => !p.parent).sort((a, b) => (a.create ?? 0) - (b.create ?? 0) || a.pid - b.pid);
  // time axis: first process creation .. capture time
  const times = procs.flatMap(p => [p.create, p.exit]).filter(t => t !== null && t > 0);
  const cap = captureTime() || (times.length ? Math.max(...times) : null);
  store.captureGuess = cap;
  const starts = procs.map(p => p.create).filter(t => t !== null && t > 0);
  tree.t0 = starts.length ? Math.min(...starts) : null;
  tree.t1 = cap;
  triage(procs);
  const saved = prefs.get('expanded:' + (store.session && store.session.image), null);
  tree.expanded = new Set(saved || procs.filter(p => p.kids.length && depth(p) < 2).map(p => p.i));
  if (!saved) for (const p of procs) if (p.flags.length) for (let a = p.parent; a; a = a.parent) tree.expanded.add(a.i);
  document.getElementById('proc-count').textContent = fmtCount(procs.length);
  renderAxis();
  renderTree();
}

function isAncestor(a, b) { for (let x = b, n = 0; x && n < 512; x = x.parent, n++) if (x === a) return true; return false; }
function depth(p) { let d = 0; for (let x = p.parent; x && d < 512; x = x.parent) d++; return d; }

/** "Find evil" hints (Windows): unexpected parents, duplicated singletons, shells spawned by services, recent starts. */
function triage(procs) {
  const s = store.session;
  const cap = tree.t1;
  const uptime = tree.t0 && cap ? cap - tree.t0 : 0;
  const recentWin = Math.min(3600, Math.max(60, uptime * 0.1));
  for (const p of procs) {
    p.flags = [];
    if (cap && p.create && cap - p.create >= 0 && cap - p.create < recentWin && p.create - tree.t0 > Math.min(300, uptime * 0.3) && p.exit === null) p.flags.push(`started ${relToCapture(p.create, cap)}`);
  }
  if (s.os !== 'windows') return;
  const lower = n => (n || '').toLowerCase();
  const counts = new Map();
  for (const p of procs) if (p.exit === null) counts.set(lower(p.name), (counts.get(lower(p.name)) || 0) + 1);
  for (const p of procs) {
    const exp = Object.entries(WIN_PARENTS).find(([k]) => lower(k) === lower(p.name));
    if (exp && p.parent && !exp[1].some(n => lower(n) === lower(p.parent.name))) p.flags.push(`unexpected parent ${p.parent.name} (${p.ppid})`);
    if (exp && !p.parent && lower(p.name) === 'svchost.exe') p.flags.push(`parent ${p.ppid} not in the process list`);
    if (WIN_SINGLETONS.some(n => lower(n) === lower(p.name)) && counts.get(lower(p.name)) > 1 && p.exit === null) p.flags.push(`${counts.get(lower(p.name))} instances of a normally unique process`);
    if (SUSPICIOUS_CHILDREN.test(p.name) && p.parent && !/^(explorer|cmd|powershell|pwsh|conhost|windowsterminal|code)\.exe$/i.test(p.parent.name)) p.flags.push(`${p.name} spawned by ${p.parent.name}`);
  }
}

// ------------------------------------------------------------------ rendering
/** Position of time t on the lifeline axis: log scale of "time before capture", so boot-time
 * processes share the left edge and the minutes before capture get most of the width. */
export function lifePos(t) {
  if (tree.t0 === null || tree.t1 === null || t === null) return null;
  const up = Math.max(2, tree.t1 - tree.t0);
  const before = Math.max(0, tree.t1 - t);
  return Math.max(0, Math.min(1, 1 - Math.log1p(before) / Math.log1p(up)));
}

function lifeBar(p) {
  const bar = el('span.life', { 'aria-hidden': 'true' });
  if (tree.t0 === null || tree.t1 === null || p.create === null || p.create <= 0) return bar;
  const a = lifePos(p.create);
  const b = lifePos(p.exit ?? tree.t1);
  const i = el('i', { class: p.exit !== null ? 'dead' : p.flags.some(f => f.startsWith('started')) ? 'recent' : '' });
  i.style.left = (a * 100).toFixed(2) + '%';
  i.style.width = Math.max(0, (b - a) * 100).toFixed(2) + '%';
  bar.append(i);
  return bar;
}

function renderAxis() {
  const ax = document.getElementById('lifeaxis');
  clear(ax);
  if (tree.t0 === null || tree.t1 === null) return;
  // ticks over the 58px lifeline column at the right edge of the tree
  const up = tree.t1 - tree.t0;
  const ticks = [[tree.t0, 'boot']];
  for (const [s, l] of [[86400, '-1d'], [3600, '-1h'], [600, '-10m'], [60, '-1m']]) if (s < up * 0.7) ticks.push([tree.t1 - s, l]);
  const track = el('span.ticks');
  for (const [t, l] of ticks) {
    const x = lifePos(t);
    const s = el('span', { text: l });
    s.style.left = `calc(${(x * 100).toFixed(1)}% - ${l === 'boot' ? 0 : 8}px)`;
    track.append(s);
  }
  ax.append(track);
  ax.title = `Process lifelines, log scale: boot ${fmtTime(tree.t0)} → capture ${fmtTime(tree.t1)} UTC (${Math.round(up / 60)} min uptime)`;
}

function matches(p, q) {
  return String(p.pid) === q || String(p.pid).startsWith(q) || p.name.toLowerCase().includes(q) || (p.path || '').toLowerCase().includes(q);
}

export function renderTree() {
  const treeEl = document.getElementById('tree');
  const q = tree.filter.trim().toLowerCase();
  const show = new Set();
  if (q) {
    for (const p of store.procs || []) if (matches(p, q)) for (let x = p; x; x = x.parent) show.add(x);
  }
  tree.flat = [];
  const walk = (p, lvl) => {
    if (q && !show.has(p)) return;
    tree.flat.push({ p, lvl });
    if (p.kids.length && (q || tree.expanded.has(p.i))) for (const k of p.kids) walk(k, lvl + 1);
  };
  for (const r of tree.roots) walk(r, 0);
  const frag = document.createDocumentFragment();
  tree.flat.forEach(({ p, lvl }, k) => {
    const open = q ? true : tree.expanded.has(p.i);
    const isMatch = q && matches(p, q);
    const node = el('div.tnode', {
      role: 'treeitem', 'aria-level': lvl + 1, 'aria-expanded': p.kids.length ? String(open) : undefined,
      'aria-selected': String(tree.selected === p.pid), id: 'tn-' + k,
      class: 'tnode' + (p.exit !== null ? ' exited' : '') + (p.flags.length > (p.flags.some(f => f.startsWith('started')) ? 1 : 0) ? ' flag' : '') + (q && !isMatch ? ' ctx' : '') + (k === tree.cursor ? ' cursor' : ''),
      title: `${p.name} (PID ${p.pid}, PPID ${p.ppid})${p.create ? '\nstarted ' + fmtTime(p.create) : ''}${p.exit !== null ? '\nexited ' + fmtTime(p.exit) : ''}${p.path ? '\n' + p.path : ''}${p.flags.length ? '\n⚑ ' + p.flags.join('\n⚑ ') : ''}`,
      dataset: { k },
    },
    el('span.tl', {}, el('span.tw', { text: p.kids.length ? (open ? '▾' : '▸') : '' }), el('span.nm', { text: p.name || '(no name)' }), el('span.pid', { text: String(p.pid) })),
    lifeBar(p));
    node.style.setProperty('--lvl', lvl);
    frag.append(node);
  });
  treeEl.replaceChildren(frag);
  if (!tree.flat.length) treeEl.append(el('div.tree-empty', { text: q ? `No process matches “${tree.filter}”.` : 'No processes.' }));
  if (tree.flat[tree.cursor]) treeEl.setAttribute('aria-activedescendant', 'tn-' + tree.cursor);
}

function moveCursor(k, scroll = true) {
  if (!tree.flat.length) return;
  tree.cursor = Math.max(0, Math.min(tree.flat.length - 1, k));
  const treeEl = document.getElementById('tree');
  for (const n of treeEl.querySelectorAll('.tnode.cursor')) n.classList.remove('cursor');
  const n = treeEl.querySelector(`[data-k="${tree.cursor}"]`);
  if (n) { n.classList.add('cursor'); if (scroll) n.scrollIntoView({ block: 'nearest' }); }
  treeEl.setAttribute('aria-activedescendant', 'tn-' + tree.cursor);
}

export function selectPid(pid, reveal = true) {
  tree.selected = pid;
  const p = tree.byPid.get(pid);
  if (p && reveal) {
    for (let a = p.parent; a; a = a.parent) tree.expanded.add(a.i);
    renderTree();
    const k = tree.flat.findIndex(x => x.p === p);
    if (k >= 0) moveCursor(k);
  } else {
    renderTree();
  }
}

function saveExpanded() { prefs.set('expanded:' + (store.session && store.session.image), [...tree.expanded]); }

export function initTree() {
  const treeEl = document.getElementById('tree');
  const filter = document.getElementById('proc-filter');
  filter.addEventListener('input', () => { tree.filter = filter.value; tree.cursor = 0; renderTree(); });
  filter.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); treeEl.focus(); moveCursor(tree.cursor); if (e.key === 'Enter' && tree.flat[tree.cursor]) emit('nav', { kind: 'proc', pid: tree.flat[tree.cursor].p.pid }); }
    if (e.key === 'Escape') { filter.value = ''; tree.filter = ''; renderTree(); treeEl.focus(); e.stopPropagation(); }
  });
  treeEl.addEventListener('click', e => {
    const n = e.target.closest('.tnode');
    if (!n) return;
    const k = +n.dataset.k;
    const { p } = tree.flat[k];
    tree.cursor = k;
    if (e.target.closest('.tw') && p.kids.length) { toggle(p); return; }
    emit('nav', { kind: 'proc', pid: p.pid });
  });
  let typeBuf = '', typeT = 0;
  treeEl.addEventListener('keydown', e => {
    const cur = tree.flat[tree.cursor];
    const p = cur && cur.p;
    switch (e.key) {
      case 'ArrowDown': moveCursor(tree.cursor + 1); break;
      case 'ArrowUp': moveCursor(tree.cursor - 1); break;
      case 'PageDown': moveCursor(tree.cursor + 15); break;
      case 'PageUp': moveCursor(tree.cursor - 15); break;
      case 'Home': moveCursor(0); break;
      case 'End': moveCursor(tree.flat.length - 1); break;
      case 'ArrowRight':
        if (!p) break;
        if (p.kids.length && !tree.expanded.has(p.i) && !tree.filter) toggle(p);
        else moveCursor(tree.cursor + 1);
        break;
      case 'ArrowLeft':
        if (!p) break;
        if (p.kids.length && tree.expanded.has(p.i) && !tree.filter) toggle(p);
        else if (p.parent) { const k = tree.flat.findIndex(x => x.p === p.parent); if (k >= 0) moveCursor(k); }
        break;
      case 'Enter': case ' ': if (p) emit('nav', { kind: 'proc', pid: p.pid }); break;
      case '*': expandAll(true); break;
      default:
        if (e.key.length === 1 && /\S/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const now = Date.now();
          typeBuf = now - typeT > 700 ? e.key.toLowerCase() : typeBuf + e.key.toLowerCase();
          typeT = now;
          const n = tree.flat.length;
          for (let j = 1; j <= n; j++) {
            const k = (tree.cursor + (typeBuf.length > 1 ? 0 : j)) % n;
            if (tree.flat[k].p.name.toLowerCase().startsWith(typeBuf) || String(tree.flat[k].p.pid).startsWith(typeBuf)) { moveCursor(k); break; }
          }
          break;
        }
        return;
    }
    e.preventDefault();
  });
  treeEl.addEventListener('focus', () => moveCursor(tree.cursor, false));
  document.getElementById('tree-expand').addEventListener('click', () => expandAll(true));
  document.getElementById('tree-collapse').addEventListener('click', () => expandAll(false));
}

function toggle(p) {
  if (tree.expanded.has(p.i)) tree.expanded.delete(p.i); else tree.expanded.add(p.i);
  saveExpanded();
  const k = tree.cursor;
  renderTree();
  moveCursor(k, false);
}

function expandAll(open) {
  tree.expanded = open ? new Set((store.procs || []).filter(p => p.kids.length).map(p => p.i)) : new Set();
  saveExpanded();
  renderTree();
}

export function resetTree() {
  tree.loadedFor = null;
  tree.loading = null;
  tree.selected = null;
  store.procs = null;
  document.getElementById('proc-count').textContent = '';
  clear(document.getElementById('lifeaxis'));
}

export function procByPid(pid) { return tree.byPid.get(pid); }
export function treeTimes() { return { t0: tree.t0, t1: tree.t1 }; }

// ------------------------------------------------------------------ process view
export class ProcessTab {
  constructor(pid) {
    this.pid = pid;
    this.pane = el('div.pane');
    this.head = el('div.pv-head');
    this.sub = el('div.subtabs', { role: 'tablist', 'aria-label': 'Process details' });
    this.subpanes = el('div.subpanes');
    this.pane.append(this.head, this.sub, this.subpanes);
    this.panels = new Map();
    this.offProcs = on('procs', () => this.renderHead());
    this.renderHead();
    this.buildTabs();
    this.loadCmdline();
  }

  get title() { const p = procByPid(this.pid); return p ? `${p.name}` : `PID ${this.pid}`; }
  get subtitle() { return String(this.pid); }

  renderHead() {
    const p = procByPid(this.pid);
    clear(this.head);
    if (!p) { this.head.append(el('div.pv-name', {}, el('h2', { text: `PID ${this.pid}` }), el('span.muted', { text: 'not in the process list (exited or hidden?) — pivots still work' }))); return; }
    const par = p.parent;
    const facts = el('div.pv-facts');
    const f = (k, v) => { if (v !== null && v !== undefined && v !== '') facts.append(el('span', {}, k + ' ', v instanceof Node ? v : el('b', { text: String(cellText(v)) }))); };
    f('PPID', par ? el('button.linkbtn', { type: 'button', text: `${p.ppid} ${par.name}`, on: { click: () => emit('nav', { kind: 'proc', pid: par.pid }) } }) : el('b', { text: `${p.ppid} (not listed)` }));
    f('threads', p.threads);
    f('handles', p.handles);
    f('session', p.session);
    f('wow64', p.wow64);
    f('uid', p.uid);
    if (p.offset && typeof p.offset === 'string') f({ windows: 'EPROCESS', linux: 'task_struct', mac: 'proc' }[store.session.os] || 'object', el('button.linkbtn', { type: 'button', text: p.offset, title: 'View this structure in memory', on: { click: () => emit('nav', { kind: 'hex', layer: 'kernel', addr: p.offset }) } }));
    f('started', p.create ? fmtTime(p.create) : null);
    if (p.exit !== null) f('exited', fmtTime(p.exit));
    const kids = p.kids.length ? el('span', {}, 'children ', ...p.kids.slice(0, 8).flatMap((k, i) => [i ? ', ' : '', el('button.linkbtn', { type: 'button', text: `${k.name} ${k.pid}`, on: { click: () => emit('nav', { kind: 'proc', pid: k.pid }) } })]), p.kids.length > 8 ? ` +${p.kids.length - 8}` : '') : null;
    if (kids) facts.append(kids);
    const life = el('div.pv-life', { title: 'Lifetime on a log scale of time before capture' });
    const { t0, t1 } = treeTimes();
    if (t0 !== null && t1 !== null && p.create) {
      const a = lifePos(p.create), b = lifePos(p.exit ?? t1);
      const sp = el('div.span', { class: 'span' + (p.exit !== null ? ' dead' : '') });
      sp.style.left = (a * 100) + '%'; sp.style.width = Math.max(0.3, (b - a) * 100) + '%';
      life.append(el('div.track'), sp);
      const up = t1 - t0;
      const ticks = [[t0, 'boot ' + fmtTime(t0).slice(11)]];
      for (const [s, l] of [[86400, '-1d'], [3600, '-1h'], [600, '-10m'], [60, '-1m']]) if (s < up * 0.7) ticks.push([t1 - s, l]);
      ticks.push([t1, 'capture ' + fmtTime(t1).slice(11)]);
      for (const [t, l] of ticks) {
        const x = lifePos(t);
        const lab = el('span.lab', { text: l });
        if (x <= 0.02) lab.classList.add('first'); else if (x >= 0.98) lab.classList.add('last');
        lab.style.left = (x * 100) + '%';
        life.append(el('span.tick', { style: { left: (x * 100) + '%' } }), lab);
      }
      f('age', relToCapture(p.create, t1) + (p.exit !== null ? `, ran ${Math.max(0, Math.round(p.exit - p.create))} s` : ''));
    }
    this.cmdEl = el('div.pv-cmd', {}, el('span.lbl', { text: 'cmd' }), this.cmd || p.cmd || '…');
    const pathEl = p.path ? el('div.pv-cmd', {}, el('span.lbl', { text: 'path' }), p.path) : null;
    const flags = p.flags.length ? el('div.pv-flags', {}, ...p.flags.map(x => el('span.flagchip', { text: '⚑ ' + x }))) : null;
    const actions = el('div.rv-actions', {},
      el('button.btn', { type: 'button', title: 'Other plugins that accept --pid, prefilled', on: { click: () => emit('palette', { query: '', pidFor: this.pid }) } }, 'More plugins for this PID…'),
      el('button.btn.ghost', { type: 'button', on: { click: () => copy(String(this.pid)) } }, 'Copy PID'));
    this.head.append(...[
      el('div.pv-name', {}, el('h2', { text: p.name || '(no name)' }), el('span.pid', {}, 'PID ', el('b', { text: String(p.pid) })), p.exit !== null ? el('span.stamp.cancelled', { text: 'exited' }) : null),
      actions, this.cmdEl, pathEl, facts, life, flags].filter(Boolean));
  }

  async loadCmdline() {
    const os = store.session && store.session.os;
    const c = (CMDLINE[os] || []).find(([n]) => store.pluginMap.has(n));
    if (!c) { this.cmd = '(no command-line plugin for this OS)'; this.renderHead(); return; }
    const [name, colName] = c;
    try {
      const run = await runPlugin(name, pidArgs(name, this.pid), { reuse: true, origin: 'pivot' });
      const r = await whenDone(run.id);
      if (r.status !== 'done') { this.cmd = '(unavailable)'; this.renderHead(); return; }
      const rows = await allRows(r.id, 50);
      const ci = r.cols.findIndex(x => x.name === colName);
      const pi = r.cols.findIndex(x => /^(PID|Pid)$/.test(x.name));
      const row = rows.find(x => pi < 0 || Number(x[pi + 2]) === this.pid);
      this.cmd = row && ci >= 0 ? cellText(row[ci + 2]) : '(no command line)';
    } catch (e) { this.cmd = '(unavailable)'; }
    this.renderHead();
  }

  buildTabs() {
    const os = store.session && store.session.os;
    const defs = (PIVOTS[os] || []).map(([label, cands]) => ({ label, plugin: firstPlugin(cands) }));
    this.defs = defs;
    const last = prefs.get('pivot', 'Handles');
    let first = null;
    defs.forEach((d, k) => {
      const b = el('button.subtab', { role: 'tab', type: 'button', 'aria-selected': 'false', class: 'subtab' + (d.plugin ? '' : ' na'), title: d.plugin ? `${d.plugin}\n${blurb(d.plugin)}` : 'Not available in this build', disabled: !d.plugin, on: { click: () => this.show(k) } }, d.label, el('span.n'));
      d.btn = b;
      this.sub.append(b);
      if (d.plugin && (first === null || d.label === last)) first = k;
    });
    this.sub.addEventListener('keydown', e => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const avail = defs.map((d, k) => (d.plugin ? k : -1)).filter(k => k >= 0);
      const i = avail.indexOf(this.current);
      const n = avail[(i + (e.key === 'ArrowRight' ? 1 : -1) + avail.length) % avail.length];
      this.show(n);
      defs[n].btn.focus();
      e.preventDefault();
    });
    if (first !== null) this.show(first);
    else this.subpanes.append(el('div.empty-state', {}, el('h2', { text: 'No pivots' }), 'This build has none of the per-process plugins for this OS yet.'));
  }

  async show(k) {
    const d = this.defs[k];
    if (!d || !d.plugin) return;
    this.current = k;
    prefs.set('pivot', d.label);
    for (const x of this.defs) if (x.btn) x.btn.setAttribute('aria-selected', String(x === d));
    for (const [kk, p] of this.panels) p.node.hidden = kk !== k;
    if (this.panels.has(k)) { this.panels.get(k).table.root.focus({ preventScroll: true }); return; }
    const holder = { node: el('div.pane') };
    this.panels.set(k, holder);
    this.subpanes.append(holder.node);
    try {
      const args = pidArgs(d.plugin, this.pid);
      const byArg = Object.keys(args).length > 0;
      const run = await runPlugin(d.plugin, args, { reuse: true, origin: 'pivot' });
      const fixed = {};
      if (!byArg) {
        // no --pid option: run once for everything, filter on the PID column
        const cols = run.cols && run.cols.length ? run.cols : (await waitCols(run.id));
        const pc = cols.findIndex(c => /^(PID|Pid|Owner PID)$/i.test(c.name));
        if (pc >= 0) fixed[pc] = '=' + this.pid;
      }
      const panel = new ResultPanel({
        runId: run.id, fixed, label: `${d.label} of PID ${this.pid}`,
        onUpdate: r => { d.btn.querySelector('.n').textContent = r.status === 'done' ? (byArg ? fmtCount(r.rows) : '') : r.status === 'failed' ? '!' : '…'; },
        extraBar: [el('button.btn.ghost', { type: 'button', title: 'Open this result in its own tab', on: { click: () => emit('nav', { kind: 'run', id: run.id }) } }, 'Open ↗')],
      });
      holder.panel = panel;
      holder.table = panel.table;
      holder.node.append(panel.node);
      if (this.current === k) holder.node.hidden = false;
      const r = await whenDone(run.id);
      if (r.status === 'failed' && r.error) {
        holder.node.prepend(errCard(r.error));
      }
    } catch (e) {
      holder.node.append(el('div.errcard', {}, el('h4', { text: 'Could not run ' + d.plugin }), el('p', { text: e.message })));
    }
  }

  focus() {
    const h = this.panels.get(this.current);
    if (h && h.table) h.table.root.focus({ preventScroll: true });
  }

  focusFilter() { const h = this.panels.get(this.current); if (h && h.panel) h.panel.focusFilter(); }

  onShow() { selectPid(this.pid); }

  destroy() { this.offProcs(); for (const h of this.panels.values()) if (h.panel) h.panel.destroy(); }
}

async function waitCols(id) {
  const r = await whenDone(id);
  return r.cols || [];
}

/** Arguments that restrict a plugin to one PID (empty when it has no pid option). */
export function pidArgs(name, pid) {
  const p = store.pluginMap.get(name);
  if (!p) return {};
  const r = p.reqs.find(x => /^pids?$/i.test(x.name) && (x.kind === 'list_int' || x.kind === 'int'));
  if (!r) return {};
  return { [r.name]: r.kind === 'list_int' ? [pid] : pid };
}

export function errCard(e) {
  return el('div.errcard', { class: 'errcard' + (e.kind === 'cancelled' ? ' soft' : '') },
    el('h4', { text: e.title }),
    e.message ? el('p', { text: e.message }) : null,
    e.hints && e.hints.length ? el('ul', {}, ...e.hints.map(h => el('li', { text: h }))) : null,
    e.detail ? el('details', {}, el('summary', { text: 'Technical details' }), el('pre', { text: e.detail })) : null);
}

export { hexTarget };
