// Workspace: tabs, the overview (landing), plugin result tabs, compare view, run history and
// the dialogs (open image, shortcuts).

import { store, api, on, emit, el, clear, copy, menu, modal, runPlugin, whenDone, sessionRuns, shortName, pluginOs, fmtCount, fmtMs, fmtBytes, fmtAgo, parseTime, fmtTime, prefs, toast, rememberDuration, expectedDuration, finished, debounce, int0, download } from './core.js';
import { QUICK, blurb } from './catalog.js';
import { ResultPanel, captureTime } from './result.js';
import { ProcessTab, errCard, selectPid, procByPid, firstPlugin } from './procs.js';
import { HexTab } from './hex.js';
import { openPalette } from './palette.js';

// ------------------------------------------------------------------ tabs
const tabs = [];      // {key, view, btn}
let active = null;

export function activeView() { return active && active.view; }

function tabFor(key) { return tabs.find(t => t.key === key); }

export function openTab(key, make, { focus = true, background = false } = {}) {
  let t = tabFor(key);
  if (!t) {
    const view = make();
    const btn = el('button.tab', { role: 'tab', type: 'button', 'aria-selected': 'false', 'aria-controls': 'pane-' + key, id: 'tab-' + key });
    t = { key, view, btn };
    view.pane.id = 'pane-' + key;
    view.pane.setAttribute('role', 'tabpanel');
    view.pane.setAttribute('aria-labelledby', 'tab-' + key);
    view.pane.hidden = true;
    btn.addEventListener('click', e => { if (e.target.closest('.x')) closeTab(key); else activate(key); });
    btn.addEventListener('auxclick', e => { if (e.button === 1 && key !== 'overview') closeTab(key); });
    document.getElementById('panes').append(view.pane);
    document.getElementById('tabs').append(btn);
    tabs.push(t);
    renderTabBtn(t);
    saveTabs();
  }
  if (!background) activate(key, focus);
  return t.view;
}

function renderTabBtn(t) {
  const v = t.view;
  const b = t.btn;
  clear(b);
  const status = v.status ? v.status() : null;
  if (status === 'running' || status === 'queued') b.append(el('span.dot.running'));
  else if (status === 'failed') b.append(el('span.dot.failed'));
  b.append(el('span.tt', { text: v.title }));
  if (v.subtitle) b.append(el('span.tk', { text: v.subtitle }));
  if (t.key !== 'overview') b.append(el('span.x', { 'aria-label': 'Close tab', title: 'Close (Alt+W)', text: '×' }));
  b.title = v.title + (v.subtitle ? ' — ' + v.subtitle : '');
}

export function refreshTabs() { for (const t of tabs) renderTabBtn(t); }

export function activate(key, focus = true) {
  const t = tabFor(key);
  if (!t) return;
  for (const x of tabs) {
    const on = x === t;
    x.btn.setAttribute('aria-selected', String(on));
    x.btn.tabIndex = on ? 0 : -1;
    x.view.pane.hidden = !on;
  }
  active = t;
  t.btn.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  if (t.view.onShow) t.view.onShow();
  if (focus && t.view.focus) setTimeout(() => t.view.focus(), 0);
  highlightRunList();
  saveTabs();
}

export function closeTab(key) {
  const i = tabs.findIndex(t => t.key === key);
  if (i < 0 || key === 'overview') return;
  const t = tabs[i];
  if (t.view.destroy) t.view.destroy();
  t.view.pane.remove();
  t.btn.remove();
  tabs.splice(i, 1);
  if (active === t) activate(tabs[Math.min(i, tabs.length - 1)].key);
  saveTabs();
}

export function cycleTab(d) {
  if (!active) return;
  const i = tabs.indexOf(active);
  activate(tabs[(i + d + tabs.length) % tabs.length].key);
}
export function nthTab(n) { if (tabs[n]) activate(tabs[n].key); }

function saveTabs() {
  if (!store.session || !store.session.image) return;
  prefs.set('tabs:' + store.session.image, { keys: tabs.map(t => t.key).filter(k => /^(run|proc):/.test(k)), active: active && active.key });
}

export function restoreTabs() {
  if (!store.session || !store.session.image) return;
  const s = prefs.get('tabs:' + store.session.image, null);
  if (!s) return;
  for (const k of s.keys) {
    const [kind, id] = k.split(':');
    if (kind === 'run' && store.runs.has(+id) && store.runs.get(+id).session === store.session.id) openRun(+id, { background: true });
    if (kind === 'proc') openProcess(+id, { background: true });
  }
  if (s.active && tabFor(s.active)) activate(s.active, false);
}

export function closeSessionTabs() {
  for (const t of [...tabs]) if (t.key !== 'overview') closeTab(t.key);
}

// ------------------------------------------------------------------ navigation
export function openRun(id, opts = {}) {
  return openTab('run:' + id, () => new RunTab(id), opts);
}
export function openProcess(pid, opts = {}) {
  selectPid(pid, !opts.background);
  return openTab('proc:' + pid, () => new ProcessTab(pid), opts);
}
export function openHex(layer, addr) {
  const v = new HexTab({ layer, addr });
  return openTab(v.key, () => v);
}

on('nav', ev => {
  if (ev.kind === 'run') openRun(ev.id);
  else if (ev.kind === 'proc') openProcess(ev.pid);
  else if (ev.kind === 'hex') openHex(ev.layer, ev.addr);
  else if (ev.kind === 'overview') activate('overview');
  else if (ev.kind === 'compare') openCompare(ev.a, ev.b);
});
on('tabs-changed', () => refreshTabs());
on('palette', ev => {
  if (ev.pidFor) {
    // plugins with a pid option for this OS, prefilled
    openPalette({ query: '', pidFor: ev.pidFor });
  } else openPalette(ev);
});

// ------------------------------------------------------------------ run tab
class RunTab {
  constructor(id) {
    this.id = id;
    this.run = store.runs.get(id);
    this.pane = el('div.pane');
    this.head = el('div.rv-head');
    this.errBox = el('div');
    this.filesBox = el('div.files', { hidden: true });
    this.progress = el('div.progress', { hidden: true }, el('i'));
    this.panel = new ResultPanel({ runId: id, onUpdate: r => this.update(r) });
    this.pane.append(this.head, this.progress, this.errBox, this.filesBox, this.panel.node);
    this.update(this.run);
    this.tick = setInterval(() => { if (this.run && this.run.status === 'running') this.renderHead(); }, 250);
  }
  get title() { return this.run ? shortName(this.run.plugin) : 'run ' + this.id; }
  get subtitle() { return this.run && this.run.args.length ? this.run.args.join(' ') : '#' + this.id; }
  status() { return this.run && this.run.status; }

  update(r) {
    if (!r) return;
    const prev = this.run;
    this.run = r;
    if (r.status === 'done' && prev && prev.status !== 'done' && r.elapsed) rememberDuration(r.plugin, r.elapsed);
    this.renderHead();
    clear(this.errBox);
    if (r.error && (r.status === 'failed' || (r.status === 'cancelled' && r.error.kind !== 'cancelled'))) this.errBox.append(errCard(r.error));
    if (r.evicted) this.errBox.append(errCard({ kind: 'cancelled', title: 'This result was dropped from memory', message: 'Newer results needed the memory (--max-memory). Nothing was lost on disk: run it again to see it (it only takes as long as the plugin).', hints: [], detail: '' }));
    if (r.truncated) this.errBox.append(errCard({ kind: 'cancelled', title: `Showing the first ${fmtCount(r.stored)} of ${fmtCount(r.rows)} rows`, message: 'This result is larger than the memory vol serve sets aside for results (--max-memory). The remaining rows were counted but not kept.', hints: ['Narrow the run with the plugin\'s options (for example --pid), or', 'export the complete output straight to disk with Export → “vol -r csv” (it re-runs the plugin and streams everything).'], detail: '' }));
    const running = r.status === 'running' || r.status === 'queued';
    this.progress.hidden = !running;
    this.filesBox.hidden = !r.files || !r.files.length;
    if (r.files && r.files.length) {
      clear(this.filesBox);
      this.filesBox.append(el('span.label', { text: `${r.files.length} file${r.files.length > 1 ? 's' : ''} written` }));
      for (const f of r.files.slice(0, 12)) this.filesBox.append(el('button.linkbtn', { type: 'button', title: `${fmtBytes(f.size)} — download`, text: f.name, on: { click: () => download(`/api/runs/${r.id}/files/${encodeURIComponent(f.name)}`) } }));
      if (r.files.length > 12) this.filesBox.append(el('span.muted', { text: `+${r.files.length - 12} more` }));
      if (r.files.length > 1) this.filesBox.append(el('button.linkbtn', { type: 'button', text: 'download all (.zip)', on: { click: () => download(`/api/runs/${r.id}/files.zip`) } }));
    }
    refreshTabs();
  }

  renderHead() {
    const r = this.run;
    clear(this.head);
    const os = pluginOs(r.plugin);
    const title = el('div.rv-title', {},
      el('h2', {}, el('span.ns', { text: os === 'generic' ? '' : os + '.' }), shortName(r.plugin)),
      r.args.length ? el('span.args', { text: r.args.join(' ') }) : null,
      el('span', { class: 'stamp ' + r.status, text: r.status === 'done' ? 'done' : r.status }));
    const exp = expectedDuration(r.plugin);
    let meta = `${fmtCount(r.rows)} rows`;
    if (r.status === 'running') {
      meta += ` · ${fmtMs(r.elapsed)}`;
      if (r.elapsed > 800 && r.rows) meta += ` · ${fmtCount(Math.round(r.rows / (r.elapsed / 1000)))}/s`;
      if (exp && exp > 1500) meta += ` · usually ~${fmtMs(exp)}`;
      const bar = this.progress;
      if (exp && exp > 1500) { bar.classList.add('eta'); bar.firstChild.style.right = Math.max(2, 100 - Math.min(98, (r.elapsed / exp) * 100)) + '%'; }
    } else if (r.status === 'queued') meta = 'waiting for a free worker…';
    else meta += ` · ${fmtMs(r.elapsed)}`;
    if (r.truncated) meta += ' · table size cap reached: the rest was counted, not kept';
    const acts = el('div.rv-actions');
    if (r.status === 'running' || r.status === 'queued') {
      acts.append(el('button.btn.danger', { type: 'button', title: 'Cancel (the plugin stops at its next result)', on: { click: () => api(`runs/${r.id}/cancel`, { method: 'POST' }).catch(e => toast(e.message, 'bad')) } }, 'Cancel'));
    } else {
      acts.append(el('button.btn', { type: 'button', title: 'Run again with the same options', on: { click: () => this.rerun() } }, '↻ Re-run'));
    }
    acts.append(
      el('button.btn.ghost', { type: 'button', title: 'Edit options and run again', on: { click: () => openPalette({ plugin: r.plugin, query: shortName(r.plugin), args: argsToPrefill(r), focusForm: true }) } }, 'Options…'),
      el('button.btn.ghost', { type: 'button', title: 'Compare with another run', on: { click: () => openCompare(r.id, null) } }, 'Compare'));
    const b = blurb(r.plugin);
    this.head.append(title, el('span.rv-meta', { text: meta, title: b || '' }), acts);
  }

  async rerun() {
    try {
      const run = await runPlugin(this.run.plugin, argsToPrefill(this.run), { origin: 'user' });
      openRun(run.id);
    } catch (e) { toast(e.message, 'bad'); }
  }

  focus() { this.panel.table.root.focus({ preventScroll: true }); }
  focusFilter() { this.panel.focusFilter(); }
  destroy() { clearInterval(this.tick); this.panel.destroy(); }
}

/** Reconstruct the option values of a run from its argv. */
function argsToPrefill(r) {
  const p = store.pluginMap.get(r.plugin);
  if (!p) return {};
  const out = {};
  const argv = r.args;
  for (let i = 0; i < argv.length; i++) {
    const req = p.reqs.find(x => x.flag === argv[i]);
    if (!req) continue;
    if (req.kind === 'bool') { out[req.name] = true; continue; }
    const vals = [];
    while (i + 1 < argv.length && !p.reqs.some(x => x.flag === argv[i + 1])) vals.push(argv[++i]);
    out[req.name] = req.kind.startsWith('list') ? vals : vals[0];
  }
  return out;
}

// ------------------------------------------------------------------ overview
export class Overview {
  constructor() {
    this.pane = el('div.pane.scrollpane');
    this.root = el('div.ov');
    this.pane.append(this.root);
    on('session', () => this.render());
    on('runs', debounce(() => this.renderDynamic(), 120));
    on('procs', () => this.renderDynamic());
    this.render();
  }
  get title() { return 'Overview'; }
  get subtitle() { return ''; }

  render() {
    clear(this.root);
    const s = store.session;
    if (!s) return;
    if (!s.image) { this.root.append(openImageCard(true)); return; }
    this.evCard = el('section.card.evcard.full', { 'aria-label': 'Evidence' });
    this.root.append(this.evCard);
    this.renderEvidence();
    this.triage = el('section.card', { 'aria-label': 'Triage' });
    this.quick = el('section.card', { 'aria-label': 'Quick actions' });
    this.recent = el('section.card.full', { 'aria-label': 'Recent runs' });
    this.root.append(this.quick, this.triage, this.recent);
    this.renderDynamic();
  }

  renderEvidence() {
    const s = store.session;
    const c = this.evCard;
    clear(c);
    const b = el('div.card-b');
    const osName = { windows: 'Windows', linux: 'Linux', mac: 'macOS' }[s.os] || '';
    b.append(el('div.ev-title', {}, el('h1', { text: s.name }), osName ? el('span.oslogo', { text: `${osName}${s.arch ? ' · ' + (s.arch === 'intel64' ? 'x64' : 'x86') : ''}` }) : null),
      el('div.ev-path', { text: `${s.image} · ${fmtBytes(s.size)}` }));
    if (s.state === 'warming') {
      b.append(el('div.warming', {}, el('span.spinner'), `${s.phase || 'Preparing'}…`));
    } else if (s.state === 'failed') {
      const hints = [];
      if (s.banners && s.banners.length) {
        for (const x of s.banners) hints.push('Kernel banner in the image: ' + x);
        hints.push('Generate a symbol table for exactly this kernel with dwarf2json (from the vmlinux with debug info, or the macOS Kernel Debug Kit), put it in a directory, then use “Open another image…” with that symbols directory.');
      } else hints.push(...(s.notes || []));
      b.append(errCard({ title: s.banners && s.banners.length ? 'Symbols needed for this kernel' : 'This image could not be analysed', message: s.error, hints, detail: (s.notes || []).join('\n') }));
    }
    const facts = el('div.facts');
    const fact = (k, v, big = false, small = '') => { if (v === undefined || v === null || v === '') return; facts.append(el('div.fact', {}, el('div.k', { text: k }), el('div.v', { class: 'v' + (big ? ' big' : '') }, String(v), small ? el('small', { text: ' ' + small }) : null))); };
    const F = Object.fromEntries(s.facts || []);
    const cap = captureTime();
    if (cap) fact('Captured', fmtTime(cap), false, 'UTC');
    if (s.os === 'windows') {
      const mm = F['Major/Minor'];
      fact('Windows build', mm ? mm.split('.').pop() : F.NtMajorVersion, false, F.NtProductType ? F.NtProductType.replace('NtProduct', '') : '');
      fact('CPUs', F.KeNumberProcessors);
      fact('Kernel base', F['Kernel Base'] || F['Kernel base']);
      fact('DTB', F.DTB);
      fact('System root', F.NtSystemRoot);
      fact('Kernel PDB', F.Kernel);
    } else if (F.Banner) {
      const m = /version (\S+)/i.exec(F.Banner) || /Darwin Kernel Version (\S+?):/.exec(F.Banner);
      fact('Kernel', m ? m[1] : F.Banner);
      fact('KASLR shift', F['KASLR shift']);
      fact('DTB', F.DTB);
      fact('Layer', F.Layer);
    }
    const procs = store.procs;
    if (procs) {
      const running = procs.filter(p => p.exit === null).length;
      fact('Processes', fmtCount(procs.length), true, procs.length - running ? `${procs.length - running} exited` : '');
    }
    if (s.layers && s.layers.length) fact('Layers', s.layers.join(' → '));
    if (s.warm_ms) fact('Ready in', fmtMs(s.warm_ms));
    b.append(facts);
    if (F.Banner) b.append(el('div.fact.banner', {}, el('div.k', { text: 'Banner' }), el('div.v', { text: F.Banner })));
    const changeBtn = el('button.btn.ghost', { type: 'button', on: { click: () => openImageDialog() } }, 'Open another image…');
    const allFacts = el('button.btn.ghost', { type: 'button', on: { click: () => factsDialog() } }, 'All OS details');
    c.append(el('div.card-h', {}, el('h3', { text: 'Evidence' }), el('div.rv-actions', {}, allFacts, changeBtn)), b);
  }

  renderDynamic() {
    const s = store.session;
    if (!s || !s.image || !this.quick) return;
    this.renderEvidence();
    // quick actions
    clear(this.quick);
    const tiles = el('div.tiles');
    const runs = sessionRuns();
    const bannerOs = s.banners && s.banners.length ? (s.banners[0].startsWith('Darwin') ? 'mac' : 'linux') : null;
    (QUICK[s.os || bannerOs] || QUICK.windows).forEach(([label, cands], k) => {
      const name = firstPlugin(cands);
      if (!name) return;
      const last = runs.find(r => r.plugin === name && r.args.length === 0);
      const st = last ? (last.status === 'done' ? `✓ ${fmtCount(last.rows)}` : last.status) : '';
      tiles.append(el('button.tile', { type: 'button', title: blurb(name), on: { click: () => this.quickRun(name) } },
        el('span.tn', { text: label }), el('span.ts', { class: 'ts ' + (last ? last.status : ''), text: st }),
        el('span.tp', { text: shortName(name) }), el('span.td', { text: blurb(name).split('. ')[0] })));
    });
    if (!tiles.childNodes.length) tiles.append(el('p.muted', { text: 'No quick actions for this OS in this build yet — press Ctrl+K to browse all plugins.' }));
    this.quick.append(el('div.card-h', {}, el('h3', { text: 'Start here' }), el('button.btn.ghost', { type: 'button', on: { click: () => openPalette() } }, 'All plugins', el('kbd', { text: 'Ctrl K' }))), el('div.card-b', {}, tiles));
    // triage
    clear(this.triage);
    const tri = el('div.triage');
    const procs = store.procs || [];
    const flagged = procs.filter(p => p.flags.some(f => !f.startsWith('started')));
    const recent = procs.filter(p => p.flags.some(f => f.startsWith('started')));
    const exited = procs.filter(p => p.exit !== null);
    // smss.exe and userinit.exe exit by design, so their children are expected orphans
    const orphans = procs.filter(p => !p.parent && p.ppid !== 0 && s.os === 'windows' && !/^(System|smss\.exe|Registry|MemCompression|csrss\.exe|wininit\.exe|winlogon\.exe|explorer\.exe)$/i.test(p.name));
    const item = (n, title, sub, list, hot) => {
      const chips = el('div.chips', {}, ...list.slice(0, 14).map(p => el('button.chip', { type: 'button', title: p.flags.join('\n'), on: { click: () => emit('nav', { kind: 'proc', pid: p.pid }) } }, `${p.name} ${p.pid}`)));
      if (list.length > 14) chips.append(el('span.chip', { text: `+${list.length - 14}` }));
      tri.append(el('div.tri', { class: 'tri' + (hot && n ? ' hot' : '') }, el('div.n', { text: String(n) }), el('div.t', {}, title, el('small', { text: sub }), list.length ? chips : null)));
    };
    if (s.state === 'failed' || s.state === 'idle') tri.append(el('div.tri', {}, el('div.n', { text: '–' }), el('div.t', {}, 'No process list', el('small', { text: 'The kernel of this image was not identified, so there is nothing to triage yet.' }))));
    else if (!store.procs) tri.append(el('div.tri', {}, el('div.n', {}, el('span.spinner')), el('div.t', { text: s.state === 'warming' ? 'Preparing the image…' : 'Reading the process list…' })));
    else {
      item(flagged.length, 'Processes worth a look', s.os === 'windows' ? 'Unexpected parents, duplicated singletons, shells spawned by services.' : 'Heuristic flags.', flagged, true);
      item(recent.length, 'Started shortly before capture', 'New processes are where an intrusion is most likely to be visible.', recent, true);
      if (s.os === 'windows') item(orphans.length, 'Parent not in the process list', 'Normal for some (parent exited), odd for others.', orphans, false);
      item(exited.length, 'Exited but still listed', 'Terminated processes whose objects are still in memory.', exited, false);
    }
    this.triage.append(el('div.card-h', {}, el('h3', { text: 'Triage hints' }), el('span.muted', { text: 'heuristics, not verdicts', style: { fontSize: '10px' } })), tri);
    // recent runs
    clear(this.recent);
    const list = el('ol.runlist.recent');
    for (const r of runs.filter(r => r.origin === 'user').slice(0, 10)) list.append(runItem(r));
    if (!list.childNodes.length) list.append(el('li', { style: { cursor: 'default' } }, el('span'), el('span.muted', { text: 'Nothing run yet. Pick a tile, a process on the left, or press Ctrl+K.' })));
    this.recent.append(el('div.card-h', {}, el('h3', { text: 'Your recent runs' })), el('div', { style: { padding: '6px 0' } }, list));
  }

  async quickRun(name) {
    try {
      const run = await runPlugin(name, {}, { reuse: true, origin: 'user' });
      openRun(run.id);
    } catch (e) { toast(e.message, 'bad'); }
  }

  focus() { const t = this.root.querySelector('.tile, button'); if (t) t.focus({ preventScroll: true }); }
}

function factsDialog() {
  const s = store.session;
  const box = el('div.dialog', { 'aria-label': 'OS details' });
  const kv = el('div', { style: { padding: '8px 0 14px' } });
  for (const [k, v] of s.facts || []) kv.append(el('div.kv', {}, el('div.k', { text: k }), el('div.v', { text: v })));
  const m = modal(box);
  box.append(el('div.card-h', {}, el('h3', { text: 'Operating system details' }), el('button.iconbtn', { type: 'button', 'aria-label': 'Close', text: '×', on: { click: () => m.close() } })), kv);
  box.querySelector('button').focus();
}

// ------------------------------------------------------------------ open image
function openImageCard(first) {
  const s = store.session;
  const card = el('section.card.full', { 'aria-label': 'Open a memory image' });
  const path = el('input.input', { type: 'text', value: (s && s.image) || '', placeholder: '/cases/host1/memory.raw', spellcheck: false, autocomplete: 'off', 'aria-label': 'Path of the memory image' });
  const syms = el('input.input', { type: 'text', value: s ? s.symbol_dirs.join(';') : '', placeholder: 'optional: symbol directories, ; separated', spellcheck: false, autocomplete: 'off', 'aria-label': 'Symbol directories' });
  const list = el('div.fslist', { role: 'listbox', 'aria-label': 'Files' });
  const err = el('div.err', { style: { color: 'var(--bad)', fontSize: '12px' }, role: 'alert' });
  const go = el('button.btn.primary', { type: 'button', on: { click: () => submit() } }, 'Open image');
  async function browse() {
    try {
      const r = await api('fs?path=' + encodeURIComponent(path.value || '.'));
      clear(list);
      const up = r.dir.replace(/\/[^/]+\/?$/, '') || '/';
      list.append(el('button', { type: 'button', on: { click: () => { path.value = up + '/'; browse(); } } }, el('span', { text: '↰' }), el('span', { text: '..' }), el('span.sz')));
      for (const e of r.entries) {
        const full = (r.dir.endsWith('/') ? r.dir : r.dir + '/') + e.name;
        if (path.value && !full.startsWith(path.value) && !path.value.endsWith('/') && !r.dir.startsWith(path.value)) {
          const prefix = path.value.slice(path.value.lastIndexOf('/') + 1);
          if (!e.name.startsWith(prefix)) continue;
        }
        list.append(el('button', { type: 'button', on: { click: () => { path.value = full + (e.dir ? '/' : ''); if (e.dir) browse(); else path.focus(); } } },
          el('span', { text: e.dir ? '▸' : '·' }), el('span', { text: e.name + (e.dir ? '/' : '') }), el('span.sz', { text: e.dir ? '' : fmtBytes(e.size) })));
      }
    } catch (e) { clear(list); list.append(el('div.muted', { text: e.message, style: { padding: '6px 8px', fontSize: '12px' } })); }
  }
  async function submit() {
    err.textContent = '';
    go.disabled = true;
    try {
      const body = { file: path.value.trim() };
      if (syms.value.trim()) body.symbol_dirs = syms.value.split(';').map(x => x.trim()).filter(Boolean);
      await api('session', { method: 'POST', body });
      toast('Opening ' + body.file);
      document.dispatchEvent(new CustomEvent('rsvol-close-dialog'));
    } catch (e) { err.textContent = e.message; }
    go.disabled = false;
  }
  path.addEventListener('input', debounce(browse, 150));
  path.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  const body = el('div.card-b.openbox', {},
    first ? el('p.prose', { text: 'No memory image is loaded. Enter the path of one (raw, LiME, ELF core such as a QEMU or VirtualBox core dump, Windows crash dump, VMware .vmem, QEMU savevm, AVML…). It is only read, never modified.', style: { margin: 0 } }) : el('p.prose', { text: 'Switching images keeps earlier runs in the history, but they belong to the old image.', style: { margin: 0 } }),
    el('div.row', {}, path, go), syms, list, err);
  card.append(el('div.card-h', {}, el('h3', { text: 'Open a memory image' })), body);
  setTimeout(() => { browse(); path.focus(); }, 0);
  return card;
}

export function openImageDialog() {
  const box = el('div.dialog', { 'aria-label': 'Open a memory image' });
  box.append(openImageCard(false));
  const m = modal(box);
  const close = () => { m.close(); document.removeEventListener('rsvol-close-dialog', close); };
  document.addEventListener('rsvol-close-dialog', close);
}

// ------------------------------------------------------------------ run history (rail)
function runItem(r) {
  const li = el('li', { tabindex: 0, dataset: { id: r.id }, title: `${r.plugin} ${r.args.join(' ')}\n${r.status} · ${fmtCount(r.rows)} rows · ${fmtMs(r.elapsed)} · ${fmtAgo(r.created)}${r.origin !== 'user' ? '\n(opened by ' + r.origin + ')' : ''}` },
    el('span.rs', { class: 'rs ' + r.status }),
    el('span.rn', {}, shortName(r.plugin), ' ', el('span.ra', { text: r.args.join(' ') }), r.origin !== 'user' ? el('span.origin', { text: ' ' + r.origin }) : null),
    el('span.rm', { text: r.status === 'done' ? fmtCount(r.rows) : r.status === 'running' ? fmtMs(r.elapsed) : r.status }));
  li.addEventListener('click', () => openRun(r.id));
  li.addEventListener('keydown', e => { if (e.key === 'Enter') openRun(r.id); if (e.key === 'Delete') deleteRun(r.id); });
  li.addEventListener('contextmenu', e => {
    e.preventDefault();
    menu(li, [
      { label: 'Open', act: () => openRun(r.id) },
      { label: 'Compare with…', act: () => openCompare(r.id, null) },
      { label: finished(r) ? 'Remove from history' : 'Cancel', act: () => (finished(r) ? deleteRun(r.id) : api(`runs/${r.id}/cancel`, { method: 'POST' })) },
    ]);
  });
  return li;
}

async function deleteRun(id) {
  closeTab('run:' + id);
  await api(`runs/${id}`, { method: 'DELETE' }).catch(() => {});
}

export function renderRunList() {
  const list = document.getElementById('runlist');
  const runs = sessionRuns();
  const showAll = prefs.get('showPivotRuns', false);
  const shown = runs.filter(r => showAll || r.origin === 'user' || r.status === 'running');
  document.getElementById('run-count').textContent = runs.length ? `${shown.length}${shown.length !== runs.length ? '/' + runs.length : ''}` : '';
  list.replaceChildren(...shown.map(runItem));
  if (!shown.length) list.append(el('li', { style: { cursor: 'default' } }, el('span'), el('span.muted', { text: runs.length ? 'Only background runs so far.' : 'No runs yet.' })));
  if (runs.length !== shown.length || showAll) list.append(el('li', { style: { cursor: 'default' } }, el('span'), el('button.linkbtn', { type: 'button', text: showAll ? 'hide background runs' : `show ${runs.length - shown.length} background runs`, on: { click: () => { prefs.set('showPivotRuns', !showAll); renderRunList(); } } })));
  highlightRunList();
  // top-bar activity
  const act = document.getElementById('activity');
  const running = runs.filter(r => r.status === 'running' || r.status === 'queued');
  clear(act);
  if (running.length) act.append(el('span.pulse'), el('span.txt', { text: `${running.length} running` }));
}

function highlightRunList() {
  const id = active && active.key.startsWith('run:') ? active.key.slice(4) : null;
  for (const li of document.querySelectorAll('#runlist li')) li.classList.toggle('active', li.dataset.id === id);
}

// ------------------------------------------------------------------ compare
let cmpSeq = 0;
export function openCompare(a, b) {
  const v = new CompareTab(a, b);
  return openTab('cmp' + (++cmpSeq), () => v);
}

class CompareTab {
  constructor(a, b) {
    this.pane = el('div.pane');
    this.a = a; this.b = b;
    this.mode = 'all';
    this.bar = el('div.cmp-bar');
    this.grid = el('div.cmp-grid');
    this.pane.append(el('div.cmp', {}, this.bar, this.grid));
    this.renderBar();
    this.build();
  }
  get title() { return 'compare'; }
  get subtitle() { const ra = store.runs.get(this.a), rb = store.runs.get(this.b); return ra && rb ? `${shortName(ra.plugin)} ⇆ ${shortName(rb.plugin)}` : ''; }

  runOptions(sel, cur) {
    clear(sel);
    sel.append(el('option', { value: '', text: '— pick a run —' }));
    for (const r of sessionRuns().filter(r => r.status === 'done' && r.cols.length)) sel.append(el('option', { value: r.id, text: `#${r.id} ${shortName(r.plugin)} ${r.args.join(' ')} (${fmtCount(r.rows)})`, selected: r.id === cur }));
  }

  renderBar() {
    clear(this.bar);
    const sa = el('select.input', { 'aria-label': 'Left run' });
    const sb = el('select.input', { 'aria-label': 'Right run' });
    this.runOptions(sa, this.a);
    this.runOptions(sb, this.b);
    sa.addEventListener('change', () => { this.a = +sa.value || null; this.keys = null; this.build(); refreshTabs(); });
    sb.addEventListener('change', () => { this.b = +sb.value || null; this.keys = null; this.build(); refreshTabs(); });
    const mode = el('select.input', { 'aria-label': 'Rows to show' },
      el('option', { value: 'all', text: 'all rows, differences highlighted' }),
      el('option', { value: 'only', text: 'only rows missing on the other side' }),
      el('option', { value: 'common', text: 'only rows present on both sides' }));
    mode.value = this.mode;
    mode.addEventListener('change', () => { this.mode = mode.value; this.build(); });
    this.keysBtn = el('button.btn.ghost', { type: 'button', on: { click: () => this.keysMenu() } }, 'Match on…');
    this.bar.append(sa, el('span.muted', { text: '⇆' }), sb, mode, this.keysBtn);
  }

  common() {
    const ra = store.runs.get(this.a), rb = store.runs.get(this.b);
    if (!ra || !rb) return [];
    return ra.cols.map((c, i) => [c.name, i, rb.cols.findIndex(d => d.name === c.name)]).filter(x => x[2] >= 0);
  }

  defaultKeys() {
    const common = this.common();
    const pref = ['PID', 'ImageFileName', 'Name', 'COMM', 'Process', 'Path', 'Base', 'Offset', 'Offset(V)'];
    const keys = common.filter(([n]) => pref.includes(n) && !(n.startsWith('Offset') && common.some(([m]) => m === 'PID')));
    return (keys.length ? keys : common.filter(([n]) => !/time|count|threads|handles/i.test(n)).slice(0, 3)).map(([n]) => n);
  }

  keysMenu() {
    const common = this.common();
    const items = [{ header: 'Rows match when these columns are equal' }];
    for (const [n] of common) {
      const cb = el('input', { type: 'checkbox', checked: this.keys.includes(n) });
      cb.addEventListener('change', () => { this.keys = cb.checked ? [...this.keys, n] : this.keys.filter(k => k !== n); if (this.keys.length) this.build(); });
      items.push({ node: el('label.mi', {}, cb, n) });
    }
    if (!common.length) items.push({ header: 'The two runs have no column in common.' });
    menu(this.keysBtn, items);
  }

  build() {
    if (this.pa) { this.pa.destroy(); this.pb.destroy(); this.pa = this.pb = null; }
    clear(this.grid);
    const ra = store.runs.get(this.a), rb = store.runs.get(this.b);
    if (!ra || !rb) {
      this.grid.append(el('div.empty-state', { style: { gridColumn: '1 / -1' } }, el('h2', { text: 'Compare two results' }), 'Pick two finished runs above — e.g. pslist and psscan to find hidden processes, or the same plugin before and after changing options. Rows missing on the other side are highlighted.'));
      return;
    }
    this.keys ??= this.defaultKeys();
    const common = this.common().filter(([n]) => this.keys.includes(n));
    this.keysBtn.textContent = `Match on: ${this.keys.join(', ') || 'nothing'}`;
    if (!common.length) { this.grid.append(el('div.empty-state', { style: { gridColumn: '1 / -1' }, text: 'Choose at least one column that both runs have (Match on…).' })); return; }
    const side = (run, other, mine, theirs) => {
      const p = new ResultPanel({ runId: run.id, cmp: { run: other.id, keys: mine, other_keys: theirs, mode: this.mode }, label: shortName(run.plugin) });
      const h = el('div.cmp-h', {}, el('b', { text: '#' + run.id }), `${shortName(run.plugin)} ${run.args.join(' ')}`, el('span.muted', { text: `${fmtCount(run.rows)} rows` }));
      const s = el('div.cmp-side', {}, h, p.node);
      this.grid.append(s);
      return p;
    };
    this.pa = side(ra, rb, common.map(c => c[1]), common.map(c => c[2]));
    this.pb = side(rb, ra, common.map(c => c[2]), common.map(c => c[1]));
  }

  focus() { if (this.pa) this.pa.table.root.focus({ preventScroll: true }); }
  focusFilter() { if (this.pa) this.pa.focusFilter(); }
  destroy() { if (this.pa) { this.pa.destroy(); this.pb.destroy(); } }
}

// ------------------------------------------------------------------ shortcuts dialog
export function helpDialog() {
  const box = el('div.dialog', { 'aria-label': 'Keyboard shortcuts' });
  const keys = el('div.keys');
  const sec = t => keys.append(el('h5', { text: t }));
  const k = (ks, what) => keys.append(el('div.kk', {}, ...ks.map(x => el('kbd', { text: x }))), el('div', { text: what }));
  sec('Anywhere');
  k(['Ctrl', 'K'], 'Run a plugin (search all plugins)');
  k(['/'], 'Filter the current table');
  k(['T'], 'Filter the process tree');
  k(['O'], 'Overview');
  k(['M'], 'Memory viewer at an address');
  k(['Alt', '1…9'], 'Go to tab N');
  k(['[', ']'], 'Previous / next tab');
  k(['Alt', 'W'], 'Close the tab');
  k(['Shift', 'T'], 'Light / dark theme');
  k(['?'], 'This help');
  sec('Tables');
  k(['↑↓', 'PgUp', 'PgDn'], 'Move; Ctrl+Home/End: first/last row');
  k(['←→'], 'Move between columns');
  k(['Enter'], 'Row details');
  k(['C'], 'Copy cell (Shift+C: row as TSV)');
  k(['S'], 'Sort by the column (again: reverse; Shift: add)');
  k(['F'], 'Per-column filters: text, =exact, !not, >0x10, <=5, /regex/, - (empty)');
  k(['H'], 'Open the address under the cursor in the memory viewer');
  k(['P'], 'Open the row\'s process');
  sec('Process tree');
  k(['↑↓←→'], 'Move / collapse / expand');
  k(['Enter'], 'Open the process view');
  k(['*'], 'Expand everything');
  k(['a…z'], 'Jump to a process by name');
  sec('Memory viewer');
  k(['G'], 'Go to address');
  k(['Enter'], 'Follow the pointer under the cursor');
  k(['Backspace'], 'Back');
  k(['D'], 'Disassemble from the cursor');
  k(['Shift', '←→'], 'Select a range; C copies it as hex');
  const m = modal(box);
  box.append(el('div.card-h', {}, el('h3', { text: 'Keyboard shortcuts' }), el('button.iconbtn', { type: 'button', 'aria-label': 'Close', text: '×', on: { click: () => m.close() } })), keys);
  box.querySelector('button').focus();
}

export function memoryPrompt() {
  const box = el('div.dialog', { 'aria-label': 'Open memory' });
  const inp = el('input.input', { type: 'text', placeholder: '0xfffff80000000000', 'aria-label': 'Address', style: { width: '100%' } });
  const lay = el('select.input', { 'aria-label': 'Address space' }, el('option', { value: 'kernel', text: 'Kernel virtual' }), el('option', { value: 'phys', text: 'Physical' }),
    ...(store.procs || []).filter(p => p.exit === null).map(p => el('option', { value: 'pid:' + p.pid, text: `Process ${p.pid} ${p.name}` })));
  const m = modal(box);
  const go = () => {
    let v = inp.value.trim();
    if (/^[0-9a-f]+$/i.test(v) && !/^\d+$/.test(v)) v = '0x' + v;
    const n = int0(v);
    if (n === null || n < 0n) { inp.classList.add('invalid'); return; }
    m.close();
    openHex(lay.value, '0x' + n.toString(16));
  };
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  box.append(el('div.card-h', {}, el('h3', { text: 'Open memory at an address' })), el('div.card-b', { style: { display: 'grid', gap: '8px' } }, lay, inp, el('div', {}, el('button.btn.primary', { type: 'button', on: { click: go } }, 'Open'))));
  inp.focus();
}
