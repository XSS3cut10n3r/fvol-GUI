// Command palette (Ctrl+K): fuzzy search over every plugin, with the plugin's options as an
// auto-generated form (python int(x, 0) validation, PID pickers that know the process list).

import { store, el, clear, int0, modal, runPlugin, emit, shortName, pluginOs, sessionRuns, fmtCount, toast, fmtMs, expectedDuration } from './core.js';
import { category, blurb } from './catalog.js';

let open = null;

function score(p, tokens) {
  if (!tokens.length) return 1;
  const name = p.name.toLowerCase();
  const short = shortName(p.name).toLowerCase();
  const desc = (p.description + ' ' + blurb(p.name)).toLowerCase();
  let s = 0;
  for (const t of tokens) {
    const i = short.indexOf(t);
    if (i >= 0) { s += 120 - Math.min(i, 40) + (i === 0 || short[i - 1] === '.' ? 40 : 0); continue; }
    if (name.includes(t)) { s += 60; continue; }
    if (subseq(short, t)) { s += 35; continue; }
    if (desc.includes(t)) { s += 12; continue; }
    return 0;
  }
  return s;
}

function subseq(h, n) {
  let j = 0;
  for (let i = 0; i < h.length && j < n.length; i++) if (h[i] === n[j]) j++;
  return j === n.length && n.length > 2;
}

function highlight(text, tokens) {
  const frag = [];
  const low = text.toLowerCase();
  let i = 0;
  const marks = new Array(text.length).fill(false);
  for (const t of tokens) {
    const k = low.indexOf(t);
    if (k >= 0) for (let j = k; j < k + t.length; j++) marks[j] = true;
  }
  while (i < text.length) {
    let j = i;
    while (j < text.length && marks[j] === marks[i]) j++;
    frag.push(marks[i] ? el('mark', { text: text.slice(i, j) }) : text.slice(i, j));
    i = j;
  }
  return frag;
}

/** Open the palette. opts: {query, plugin, args} to preselect a plugin and prefill options. */
export function openPalette(opts = {}) {
  if (open) { open.input.focus(); return; }
  const os = store.session && store.session.os;
  let osFilter = os || 'all';
  let items = [];
  let sel = 0;
  let current = null;       // selected plugin
  let form = null;          // form controller

  const input = el('input', { type: 'text', placeholder: opts.pidFor ? `Plugins that take a PID — prefilled with ${opts.pidFor}` : 'Search ' + store.plugins.length + ' plugins — name, purpose or keyword', 'aria-label': 'Search plugins', autocomplete: 'off', spellcheck: false, role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'pal-list', 'aria-autocomplete': 'list' });
  const osBtns = el('div.os', { role: 'group', 'aria-label': 'Operating system' });
  for (const o of ['all', 'windows', 'linux', 'mac', 'generic']) {
    const b = el('button', { type: 'button', text: o === 'generic' ? 'other' : o, 'aria-pressed': String(o === osFilter), on: { click: () => { osFilter = o; for (const x of osBtns.children) x.setAttribute('aria-pressed', String(x === b)); refresh(); input.focus(); } } });
    osBtns.append(b);
  }
  const list = el('div.pal-list#pal-list', { role: 'listbox', 'aria-label': 'Plugins' });
  const detail = el('div.pal-detail', { 'aria-live': 'polite' });
  const foot = el('div.pal-foot', {},
    el('span', {}, el('kbd', { text: '↑↓' }), ' choose'),
    el('span', {}, el('kbd', { text: 'Enter' }), ' run / options'),
    el('span', {}, el('kbd', { text: 'Tab' }), ' edit options'),
    el('span', {}, el('kbd', { text: 'Ctrl Enter' }), ' run'),
    el('span.sp'),
    el('span', {}, el('kbd', { text: 'Esc' }), ' close'));
  const root = el('div.palette', { 'aria-label': 'Run a plugin' },
    el('div.pal-in', {}, el('svg', {}), input, osBtns), list, detail, foot);
  root.querySelector('svg').outerHTML = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 10.5 14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';

  function refresh() {
    const q = input.value.trim().toLowerCase();
    const tokens = q.split(/\s+/).filter(Boolean);
    let ps = store.plugins.filter(p => osFilter === 'all' || pluginOs(p.name) === osFilter);
    if (opts.pidFor) ps = ps.filter(p => p.reqs.some(r => /^pids?$/i.test(r.name) && (r.kind === 'list_int' || r.kind === 'int')));
    const scored = ps.map(p => {
      let s = score(p, tokens);
      if (!s) return null;
      if (os && pluginOs(p.name) !== os && pluginOs(p.name) !== 'generic') s -= 60;
      if (/deprecated/i.test(p.description)) s -= 25;
      return { p, s };
    }).filter(Boolean);
    clear(list);
    items = [];
    if (!tokens.length) {
      const groups = new Map();
      for (const { p } of scored) {
        const c = category(p.name);
        if (!groups.has(c)) groups.set(c, []);
        groups.get(c).push(p);
      }
      const order = ['Processes & threads', 'Malware & injection', 'Network', 'Memory', 'Files', 'Registry', 'Services', 'Credentials', 'Kernel & drivers', 'Timeline', 'System info', 'Other'];
      for (const g of order) {
        const ps2 = groups.get(g);
        if (!ps2) continue;
        ps2.sort((a, b) => (/deprecated/i.test(a.description) - /deprecated/i.test(b.description)) || a.name.localeCompare(b.name));
        list.append(el('div.pal-grp', { text: g, role: 'presentation' }));
        for (const p of ps2) list.append(item(p, []));
      }
    } else {
      scored.sort((a, b) => b.s - a.s || a.p.name.localeCompare(b.p.name));
      for (const { p } of scored.slice(0, 80)) list.append(item(p, tokens));
    }
    if (!items.length) list.append(el('div.pal-empty', { text: `No plugin matches “${input.value}”.` }));
    sel = Math.min(sel, Math.max(0, items.length - 1));
    if (opts.plugin && !current) {
      const k = items.findIndex(x => x.p.name === opts.plugin);
      if (k >= 0) sel = k;
    }
    select(sel, false);
  }

  function item(p, tokens) {
    const idx = items.length;
    const runs = sessionRuns().filter(r => r.plugin === p.name);
    const last = runs[0];
    const other = os && pluginOs(p.name) !== os && pluginOs(p.name) !== 'generic';
    const node = el('div.pal-item', { role: 'option', id: 'pal-o' + idx, 'aria-selected': 'false', class: 'pal-item' + (other ? ' other-os' : ''), on: { mousedown: e => { e.preventDefault(); select(idx); }, dblclick: () => submit() } },
      el('div.pn', {}, el('span.ns', { text: pluginOs(p.name) === 'generic' ? '' : pluginOs(p.name) + '.' }), ...highlight(shortName(p.name), tokens)),
      el('span.pb', { class: 'pb' + (last && last.status === 'done' ? ' ok' : ''), text: last ? (last.status === 'done' ? `✓ ${fmtCount(last.rows)}` : last.status) : '' }),
      el('div.pd', { text: blurb(p.name) || p.description.split('\n')[0] || '—' }));
    items.push({ p, node });
    return node;
  }

  function select(i, scroll = true) {
    if (!items.length) { current = null; clear(detail); return; }
    sel = (i + items.length) % items.length;
    for (const [k, it] of items.entries()) it.node.setAttribute('aria-selected', String(k === sel));
    const it = items[sel];
    input.setAttribute('aria-activedescendant', it.node.id);
    if (scroll) it.node.scrollIntoView({ block: 'nearest' });
    if (current !== it.p) {
      current = it.p;
      renderDetail(it.p);
    }
  }

  function renderDetail(p) {
    clear(detail);
    const b = blurb(p.name);
    detail.append(...[
      el('h3', { text: shortName(p.name) }),
      el('div.full', { text: p.name }),
      b ? el('p.blurb', { text: b }) : null,
      p.description ? el('p.desc', { text: p.description + (p.epilog ? '\n\n' + p.epilog : '') }) : null].filter(Boolean));
    const exp = expectedDuration(p.name);
    let pre = opts.plugin === p.name ? opts.args || {} : {};
    if (opts.pidFor) {
      const r = p.reqs.find(x => /^pids?$/i.test(x.name));
      if (r) pre = { [r.name]: r.kind === 'list_int' ? [String(opts.pidFor)] : String(opts.pidFor) };
    }
    form = buildForm(p, pre);
    detail.append(form.node);
    const runBtn = el('button.btn.primary', { type: 'button', on: { click: () => submit() } }, 'Run', el('kbd', { text: 'Ctrl ↵' }));
    detail.append(el('div', { style: { display: 'flex', gap: '8px', alignItems: 'center', marginTop: '14px' } }, runBtn,
      exp ? el('span.muted', { text: `took ${fmtMs(exp)} last time` }) : null));
    detail.append(form.cmd);
    const prev = sessionRuns().filter(r => r.plugin === p.name).slice(0, 5);
    if (prev.length) {
      detail.append(el('div.label', { text: 'Earlier runs', style: { marginTop: '16px', marginBottom: '4px' } }));
      for (const r of prev) {
        detail.append(el('button.chip', { type: 'button', style: { marginRight: '4px' }, on: { click: () => { close(); emit('nav', { kind: 'run', id: r.id }); } } },
          `#${r.id} ${r.args.join(' ') || 'defaults'} · ${r.status === 'done' ? fmtCount(r.rows) + ' rows' : r.status}`));
      }
    }
  }

  async function submit() {
    if (!current) return;
    const vals = form.values();
    if (!vals) { form.focusFirstError(); return; }
    try {
      const run = await runPlugin(current.name, vals, { origin: 'user' });
      close();
      emit('nav', { kind: 'run', id: run.id });
    } catch (e) {
      form.showError(e.message);
    }
  }

  input.addEventListener('input', () => { sel = 0; current = null; refresh(); });
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); select(sel + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); select(sel - 1); }
    else if (e.key === 'PageDown') { e.preventDefault(); select(Math.min(items.length - 1, sel + 10)); }
    else if (e.key === 'PageUp') { e.preventDefault(); select(Math.max(0, sel - 10)); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      if (!current) return;
      if (e.ctrlKey || e.metaKey || !form.needsInput()) submit();
      else { root.classList.add('form-mode'); form.focus(); }
    } else if (e.key === 'Tab' && !e.shiftKey && current && form.hasFields()) {
      e.preventDefault();
      root.classList.add('form-mode');
      form.focus();
    }
  });
  root.addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); submit(); }
  });

  const m = modal(root, { onClose: () => { open = null; } });
  const close = m.close;
  open = { input, close };
  input.value = opts.query || '';
  refresh();
  input.focus();
  if (opts.plugin && opts.focusForm) setTimeout(() => form && form.focus(), 0);
}

/** Build the options form for a plugin. */
export function buildForm(p, prefill = {}) {
  const node = el('div.form');
  const fields = [];
  const err = el('div.fld', {}, el('div.err', { role: 'alert' }));
  const cmd = el('div.cmdline', { title: 'The equivalent command line' });
  const img = store.session && store.session.image ? store.session.image : 'IMAGE';

  function update() {
    const parts = ['fvol', '-f', quote(img)];
    if (store.session && store.session.symbol_dirs.length) parts.push('-s', quote(store.session.symbol_dirs.join(';')));
    parts.push(p.name);
    for (const f of fields) parts.push(...f.argv());
    clear(cmd);
    cmd.append(el('b', { text: '$ ' }), parts.join(' '));
  }

  for (const r of p.reqs) {
    const f = field(r, prefill[r.name], update);
    fields.push(f);
    node.append(f.node);
  }
  if (!p.reqs.length) node.append(el('p.muted', { text: 'This plugin has no options.', style: { margin: 0, fontSize: '12px' } }));
  node.append(err);
  update();
  return {
    node, cmd,
    hasFields: () => fields.some(f => !f.disabled),
    needsInput: () => fields.some(f => f.required && f.empty()),
    focus: () => { const f = fields.find(x => x.required && x.empty()) || fields.find(x => !x.disabled); if (f) f.focus(); },
    focusFirstError: () => { const f = fields.find(x => x.error()); if (f) f.focus(); },
    showError: m => { err.firstChild.textContent = m; },
    values: () => {
      const out = {};
      let ok = true;
      for (const f of fields) {
        const e = f.validate();
        if (e) ok = false;
        const v = f.value();
        if (v !== undefined) out[f.name] = v;
      }
      if (!ok) { err.firstChild.textContent = 'Fix the highlighted options.'; return null; }
      err.firstChild.textContent = '';
      return out;
    },
  };
}

function quote(s) { return /^[\w./:=,@%+-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`; }

function field(r, pre, onChange) {
  const id = 'f-' + r.name + '-' + Math.random().toString(36).slice(2, 7);
  const required = !r.optional && r.default === null;
  const label = el('label', { for: id }, el('code', { text: r.flag }), required ? el('span.req', { text: 'REQUIRED' }) : null);
  const help = el('div.help', { text: r.description + (r.default !== null && r.default !== false && !(Array.isArray(r.default) && !r.default.length) ? `  (default: ${JSON.stringify(r.default)})` : '') });
  const errEl = el('div.err', { role: 'alert' });
  const f = { name: r.name, required, disabled: false, node: null, _err: '' };
  let get, empty, focus, argv;
  const setErr = m => { f._err = m || ''; errEl.textContent = f._err; };

  if (r.kind === 'bool') {
    const cb = el('input', { type: 'checkbox', id, checked: pre === true || r.default === true });
    cb.addEventListener('change', onChange);
    f.node = el('div.fld', {}, el('label.check', { for: id }, cb, el('code', { text: r.flag, style: { color: 'var(--addr)' } })), help);
    get = () => (cb.checked ? true : undefined);
    empty = () => !cb.checked;
    focus = () => cb.focus();
    argv = () => (cb.checked ? [r.flag] : []);
  } else if (r.kind === 'choice') {
    const s = el('select.input', { id });
    if (r.optional) s.append(el('option', { value: '', text: r.default ? `(default: ${r.default})` : '—' }));
    for (const c of r.choices) s.append(el('option', { value: c, text: c, selected: pre === c }));
    s.addEventListener('change', onChange);
    f.node = el('div.fld', {}, label, s, help, errEl);
    get = () => s.value || undefined;
    empty = () => !s.value;
    focus = () => s.focus();
    argv = () => (s.value ? [r.flag, s.value] : []);
  } else if (r.kind === 'list_int' || r.kind === 'list_str') {
    const isPid = /^pids?$/i.test(r.name) || /process id/i.test(r.description);
    const tok = tokensInput(id, r.kind === 'list_int', isPid, pre, () => { validate(); onChange(); });
    f.node = el('div.fld', {}, label, tok.node, help, errEl);
    get = () => (tok.values().length ? tok.values() : undefined);
    empty = () => !tok.values().length;
    focus = () => tok.focus();
    argv = () => (tok.values().length ? [r.flag, ...tok.values().map(v => String(r.kind === 'list_int' ? (int0(v) ?? v) : quote(v)))] : []);
    f.validate0 = () => {
      if (r.kind !== 'list_int') return '';
      const bad = tok.values().filter(v => int0(v) === null);
      return bad.length ? `invalid int value: '${bad[0]}' (python int(x, 0): 42, 0x2a, 0o52, 0b101010)` : '';
    };
  } else {
    const inp = el('input.input', { id, type: 'text', value: pre ?? '', spellcheck: false, autocomplete: 'off', placeholder: r.kind === 'int' ? 'e.g. 1234 or 0x4d2' : r.kind === 'uri' ? 'path or file:// URL' : '' });
    if (r.kind === 'bytes') { inp.disabled = true; inp.placeholder = 'not settable (volatility3 rejects bytes options on the command line too)'; f.disabled = true; }
    inp.addEventListener('input', () => { validate(); onChange(); });
    f.node = el('div.fld', {}, label, inp, help, errEl);
    get = () => (inp.value.trim() ? inp.value.trim() : undefined);
    empty = () => !inp.value.trim();
    focus = () => inp.focus();
    argv = () => (inp.value.trim() ? [r.flag, r.kind === 'int' ? String(int0(inp.value) ?? inp.value) : quote(inp.value.trim())] : []);
    f.validate0 = () => (r.kind === 'int' && inp.value.trim() && int0(inp.value) === null ? `invalid int value: '${inp.value.trim()}' (python int(x, 0): 42, 0x2a, 0o52, 0b101010)` : '');
    f.input = inp;
  }
  function validate() {
    let m = f.validate0 ? f.validate0() : '';
    setErr(m);
    if (f.input) f.input.classList.toggle('invalid', !!m);
    return m;
  }
  Object.assign(f, {
    value: get, empty, focus, argv,
    error: () => f._err,
    validate: () => {
      const m = validate();
      if (m) return m;
      if (required && empty()) { setErr('required'); return 'required'; }
      return '';
    },
  });
  return f;
}

/** Chips input; for PIDs suggests processes from the process list. */
function tokensInput(id, ints, pidPicker, pre, onChange) {
  const vals = Array.isArray(pre) ? pre.map(String) : pre !== undefined && pre !== null ? [String(pre)] : [];
  const wrap = el('div.tokens');
  const inp = el('input', { id, type: 'text', autocomplete: 'off', spellcheck: false, placeholder: pidPicker ? 'PID or process name…' : ints ? 'numbers, space separated' : 'values, space separated' });
  const box = el('div.suggest', {}, wrap);
  let sugg = null, sidx = 0, matches = [];
  function render() {
    for (const c of [...wrap.querySelectorAll('.chip')]) c.remove();
    for (const [i, v] of vals.entries()) {
      const p = pidPicker && store.procs ? store.procs.find(x => String(x.pid) === String(int0(v) ?? v)) : null;
      wrap.insertBefore(el('span.chip', { style: ints && int0(v) === null ? { borderColor: 'var(--bad)', color: 'var(--bad)' } : {} },
        v, p ? el('span.muted', { text: p.name }) : null,
        el('button', { type: 'button', 'aria-label': 'Remove ' + v, text: '×', on: { click: () => { vals.splice(i, 1); render(); onChange(); } } })), inp);
    }
  }
  function add(text) {
    for (const t of text.split(/[\s,]+/).filter(Boolean)) vals.push(t);
    inp.value = '';
    render(); hide(); onChange();
  }
  function hide() { if (sugg) { sugg.remove(); sugg = null; } }
  function suggest() {
    hide();
    if (!pidPicker || !store.procs || !store.procs.length) return;
    const q = inp.value.trim().toLowerCase();
    matches = store.procs.filter(p => !q || String(p.pid).startsWith(q) || p.name.toLowerCase().includes(q)).slice(0, 50);
    if (!matches.length) return;
    sidx = 0;
    sugg = el('div.suggest-list', { role: 'listbox' });
    matches.forEach((p, i) => sugg.append(el('div', { role: 'option', 'aria-selected': String(i === 0), on: { mousedown: e => { e.preventDefault(); add(String(p.pid)); inp.focus(); } } },
      el('span', { text: String(p.pid) }), el('span', { text: p.name }), el('span.sp', { text: p.ppid !== undefined ? 'ppid ' + p.ppid : '' }))));
    box.append(sugg);
  }
  inp.addEventListener('input', () => { if (/[\s,]$/.test(inp.value)) add(inp.value); else suggest(); });
  inp.addEventListener('focus', suggest);
  inp.addEventListener('blur', () => { setTimeout(hide, 100); if (inp.value.trim()) add(inp.value); });
  inp.addEventListener('keydown', e => {
    if (sugg && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      sidx = (sidx + (e.key === 'ArrowDown' ? 1 : -1) + matches.length) % matches.length;
      [...sugg.children].forEach((c, i) => c.setAttribute('aria-selected', String(i === sidx)));
      sugg.children[sidx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey) {
      if (sugg && matches[sidx] && !/^\d+$/.test(inp.value.trim()) && inp.value.trim()) { e.preventDefault(); add(String(matches[sidx].pid)); }
      else if (inp.value.trim()) { e.preventDefault(); add(inp.value); }
    } else if (e.key === 'Backspace' && !inp.value && vals.length) { vals.pop(); render(); onChange(); }
    else if (e.key === 'Escape' && sugg) { e.stopPropagation(); hide(); }
  });
  wrap.append(inp);
  wrap.addEventListener('mousedown', e => { if (e.target === wrap) { e.preventDefault(); inp.focus(); } });
  render();
  return { node: box, values: () => vals.slice(), focus: () => inp.focus() };
}

export function paletteOpen() { return !!open; }
export { toast };
