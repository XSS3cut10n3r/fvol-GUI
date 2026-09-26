// A result panel: toolbar + virtual table + row detail drawer + (optional) timeline strip.
// Used for plugin tabs, process pivots and the compare view.

import { store, api, on, emit, el, clear, copy, menu, cellText, fmtCount, fmtMs, fmtTime, parseTime, toast, shortName, prefs, expectedDuration, download } from './core.js';
import { VirtualTable } from './table.js';

/** Where to look at a Hex value: physical, kernel or a process address space. */
export function hexTarget(text, colName, row, cols, run) {
  const addr = text;
  if (/\(P\)|phys/i.test(colName)) return { layer: 'phys', addr };
  const n = BigInt(text);
  const pidCol = cols.findIndex(c => /^(PID|Pid)$/.test(c.name));
  let pid = pidCol >= 0 && typeof row[pidCol + 2] === 'string' ? row[pidCol + 2] : null;
  if (!pid && run && run.args) {
    const k = run.args.indexOf('--pid');
    if (k >= 0 && /^\d+$/.test(run.args[k + 1] || '')) pid = run.args[k + 1];
  }
  const os = store.session && store.session.os;
  const userSpace = os === 'windows' ? n < 0x800000000000n : n < 0xffff800000000000n && n < 0x800000000000n;
  if (pid && userSpace && pid !== '4' && pid !== '0') return { layer: 'pid:' + pid, addr };
  return { layer: 'kernel', addr };
}

export class ResultPanel {
  /** opts: runId, fixed, compact, cmp, label, onState */
  constructor(opts) {
    this.o = opts;
    this.runId = opts.runId;
    this.run = store.runs.get(opts.runId) || { cols: [], status: 'queued', plugin: opts.plugin || '' };
    this.node = el('div.rv-main');
    this.bar = el('div.rv-bar');
    this.q = el('input', { type: 'search', class: 'q', placeholder: 'Filter rows…  ( / )', 'aria-label': 'Filter rows (all columns)', spellcheck: false, autocomplete: 'off' });
    this.count = el('span.count');
    this.histBox = el('div.hist', { hidden: true });
    this.body = el('div.rv-body');
    this.table = new VirtualTable({
      runId: opts.runId,
      plugin: this.run.plugin,
      fixed: opts.fixed,
      cmp: opts.cmp,
      label: opts.label || shortName(this.run.plugin || ''),
      onHex: (text, colName, row) => this.openHex(text, colName, row),
      onPid: pid => emit('nav', { kind: 'proc', pid }),
      onOpen: row => this.openDrawer(row),
      onCursor: row => { if (this.drawer) this.openDrawer(row, true); },
      onState: () => this.updateCount(),
    });
    this.q.addEventListener('input', () => this.table.setQuery(this.q.value.trim()));
    this.q.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); this.table.root.focus(); }
      if (e.key === 'Escape') { if (this.q.value) { this.q.value = ''; this.table.setQuery(''); } else this.table.root.focus(); e.stopPropagation(); }
    });
    const filtersBtn = el('button.btn.ghost', { type: 'button', title: 'Per-column filters (F)', on: { click: () => this.table.toggleFilters() } }, 'Filters');
    const colsBtn = el('button.btn.ghost', { type: 'button', title: 'Show / hide columns', on: { click: () => this.columnsMenu(colsBtn) } }, 'Columns');
    this.timeBtn = el('button.btn.ghost', { type: 'button', title: 'Time histogram of a DateTime column; drag to filter a time range', hidden: true, on: { click: () => this.toggleHist() } }, 'Timeline');
    const exportBtn = el('button.btn.ghost', { type: 'button', title: 'Export', on: { click: () => this.exportMenu(exportBtn) } }, 'Export ▾');
    this.bar.append(this.q, filtersBtn, colsBtn, this.timeBtn, el('span.spacer'), this.count, exportBtn);
    if (opts.extraBar) this.bar.append(...opts.extraBar);
    this.body.append(this.table.root);
    this.node.append(this.bar, this.histBox, this.body);
    this.off = on('run:' + this.runId, r => this.update(r));
    this.update(this.run);
  }

  update(r) {
    this.run = r;
    this.table.update(r);
    const hasTime = (r.cols || []).some(c => c.type === 'DateTime');
    this.timeBtn.hidden = !hasTime;
    if (this.hist && (r.status === 'done' || this.table.total % 50 === 0)) this.loadHist();
    this.updateCount();
    if (this.o.onUpdate) this.o.onUpdate(r);
  }

  updateCount() {
    const t = this.table;
    clear(this.count);
    if (!t.built) return;
    if (t.hasSpec() && t.view) this.count.append(el('b', { text: fmtCount(t.total) }), ` of ${fmtCount(t.stored)}`);
    else this.count.append(el('b', { text: fmtCount(t.total) }), ' rows');
  }

  focusFilter() { this.q.focus(); this.q.select(); }

  columnsMenu(anchor) {
    const t = this.table;
    const items = [{ header: 'Columns' }];
    t.cols.forEach((c, i) => {
      const cb = el('input', { type: 'checkbox', checked: !t.hidden.has(i) });
      cb.addEventListener('change', () => t.setHidden(i, !cb.checked));
      items.push({ node: el('label.mi', {}, cb, c.name, el('small', { text: c.type })) });
    });
    items.push('sep', { label: 'Show all', act: () => { t.hidden.clear(); t.saveCols(); t.buildHead(); } });
    menu(anchor, items);
  }

  exportMenu(anchor) {
    const t = this.table;
    const dl = url => download(url);
    const r = this.run;
    const cli = () => {
      const s = store.session;
      const parts = ['vol', '-f', s.image];
      if (s.symbol_dirs.length) parts.push('-s', s.symbol_dirs.join(';'));
      parts.push(r.plugin, ...r.args);
      return parts.map(p => (/^[\w./:=,@%+-]+$/.test(p) ? p : `'${p.replace(/'/g, `'\\''`)}'`)).join(' ');
    };
    menu(anchor, [
      { header: 'Current view (filters, sort, visible columns)' },
      { label: 'CSV', hint: '.csv', act: () => dl(t.exportUrl('csv')) },
      { label: 'TSV', hint: '.tsv', act: () => dl(t.exportUrl('tsv')) },
      { label: 'JSON', hint: '.json', act: () => dl(t.exportUrl('json')) },
      { label: 'JSON Lines', hint: '.jsonl', act: () => dl(t.exportUrl('jsonl')) },
      { label: 'Markdown table', hint: '.md', act: () => dl(t.exportUrl('md')) },
      'sep',
      { header: 'Exactly as vol prints it (re-runs the plugin)' },
      { label: 'vol -r jsonl', act: () => dl(`/api/runs/${this.runId}/vol?renderer=jsonl`) },
      { label: 'vol -r json', act: () => dl(`/api/runs/${this.runId}/vol?renderer=json`) },
      { label: 'vol -r csv', act: () => dl(`/api/runs/${this.runId}/vol?renderer=csv`) },
      { label: 'vol (quick text)', act: () => dl(`/api/runs/${this.runId}/vol?renderer=quick`) },
      'sep',
      { label: 'Copy visible rows as TSV', hint: '≤ 20k', act: () => this.copyRows() },
      { label: 'Copy the vol command', act: () => copy(cli(), 'Command copied') },
    ]);
  }

  async copyRows() {
    const t = this.table;
    const out = [t.headerTsv()];
    const n = Math.min(t.total, 20000);
    for (let from = 0; from < n; from += 5000) {
      const r = await api(`runs/${this.runId}/rows?view=${t.view}&from=${from}&count=${Math.min(5000, n - from)}`);
      for (const row of r.rows) out.push(t.rowTsv(row));
    }
    copy(out.join('\n'), `Copied ${out.length - 1} rows`);
  }

  openHex(text, colName, row) {
    const tgt = hexTarget(text, colName, row, this.table.cols, this.run);
    emit('nav', { kind: 'hex', ...tgt });
  }

  // ---------------------------------------------------------------- drawer
  openDrawer(row, follow = false) {
    if (follow && !this.drawer) return;
    if (!this.drawer) {
      this.drawer = el('aside.drawer', { 'aria-label': 'Row details' });
      this.body.append(this.drawer);
    }
    const d = this.drawer;
    clear(d);
    const cols = this.table.cols;
    const closeBtn = el('button.iconbtn', { type: 'button', 'aria-label': 'Close details (Esc)', text: '×', on: { click: () => this.closeDrawer() } });
    d.append(el('div.drawer-h', {}, el('h3', { text: `Row ${row[0] + 1}` }),
      el('button.btn.ghost', { type: 'button', on: { click: () => copy(cols.map((c, i) => `${c.name}: ${cellText(row[i + 2])}`).join('\n'), 'Row copied') } }, 'Copy all'),
      closeBtn));
    const b = el('div.drawer-b');
    cols.forEach((c, i) => {
      const v = row[i + 2];
      const text = cellText(v);
      const multi = typeof v === 'string' && v.includes('\n');
      const kv = el('div.kv', {}, el('div.k', { text: c.name }));
      if (multi) {
        kv.append(el('div.v.block', {}, c.type === 'Disassembly' ? disasmBlock(v) : el('pre.code', { text: v.replace(/^\n/, '') })));
      } else {
        const vEl = el('div.v', { class: 'v' + (v === null || v === 0 ? ' faint' : c.type === 'Hex' ? ' addr' : '') , text });
        kv.append(vEl);
      }
      const acts = el('div.acts');
      if (c.type === 'Hex' && typeof v === 'string') acts.append(el('button.linkbtn', { type: 'button', text: 'view memory', on: { click: () => this.openHex(v, c.name, row) } }));
      if (/^(PID|PPID|Pid)$/.test(c.name) && typeof v === 'string') acts.append(el('button.linkbtn', { type: 'button', text: 'open process', on: { click: () => emit('nav', { kind: 'proc', pid: Number(v) }) } }));
      if (c.type === 'DateTime' && typeof v === 'string') {
        const t = parseTime(v);
        const cap = captureTime();
        if (t && cap) acts.append(el('span.muted', { text: relToCapture(t, cap), style: { fontSize: '11px' } }));
      }
      if (typeof v === 'string') acts.append(el('button.linkbtn', { type: 'button', text: 'copy', on: { click: () => copy(v.replace(/^\n/, '')) } }));
      if (acts.childNodes.length) kv.append(acts);
      b.append(kv);
    });
    d.append(b);
    d.addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); this.closeDrawer(); } });
    if (!follow) closeBtn.focus();
  }

  closeDrawer() {
    if (this.drawer) { this.drawer.remove(); this.drawer = null; this.table.root.focus(); }
  }

  // ---------------------------------------------------------------- time histogram
  toggleHist() {
    this.hist = !this.hist;
    this.histBox.hidden = !this.hist;
    if (this.hist) this.loadHist();
    else if (this.table.range) this.table.setRange(null);
  }

  async loadHist() {
    const cols = this.table.cols;
    const timeCols = cols.map((c, i) => [c, i]).filter(([c]) => c.type === 'DateTime');
    if (!timeCols.length) return;
    if (this.histCol === undefined || !timeCols.some(([, i]) => i === this.histCol)) this.histCol = timeCols[0][1];
    const w = Math.max(40, Math.floor((this.histBox.clientWidth || 800) / 5));
    let h;
    try { h = await api(`runs/${this.runId}/hist?col=${this.histCol}&view=0&buckets=${Math.min(300, w)}`); } catch (e) { return; }
    clear(this.histBox);
    const sel = el('select.input', { 'aria-label': 'Time column', style: { height: '20px', fontSize: '10px' } });
    for (const [c, i] of timeCols) sel.append(el('option', { value: i, text: c.name, selected: i === this.histCol }));
    sel.addEventListener('change', () => { this.histCol = +sel.value; this.table.setRange(null); this.loadHist(); });
    const label = el('span', { text: this.table.range ? `${this.table.range.from.slice(0, 19)} → ${this.table.range.to.slice(0, 19)}` : 'drag to select a time range' });
    const clearBtn = el('button.linkbtn', { type: 'button', text: 'clear', hidden: !this.table.range, on: { click: () => { this.table.setRange(null); this.loadHist(); } } });
    this.histBox.append(el('div.hl', {}, label, clearBtn, sel));
    if (h.empty) { this.histBox.append(el('div.muted', { text: 'No timestamps in this column.', style: { paddingTop: '14px', fontSize: '11px' } })); return; }
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    const n = h.counts.length;
    const max = Math.max(...h.counts, 1);
    svg.setAttribute('viewBox', `0 0 ${n} 42`);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', `Histogram of ${cols[this.histCol].name}`);
    const span = h.max - h.min || 1;
    const r = this.table.range;
    const rf = r ? parseTime(r.from) : null, rt = r ? parseTime(r.to) : null;
    h.counts.forEach((c, i) => {
      if (!c) return;
      const bh = Math.max(1.5, Math.sqrt(c / max) * 40);
      const rect = document.createElementNS(NS, 'rect');
      rect.setAttribute('x', i + 0.1); rect.setAttribute('width', 0.8);
      rect.setAttribute('y', 42 - bh); rect.setAttribute('height', bh);
      const t0 = h.min + (i / n) * span;
      rect.setAttribute('class', 'b' + (r && t0 >= rf - span / n && t0 <= rt ? ' in' : ''));
      const tt = document.createElementNS(NS, 'title');
      tt.textContent = `${fmtTime(t0)} — ${c} row${c > 1 ? 's' : ''}`;
      rect.append(tt);
      svg.append(rect);
    });
    const brush = document.createElementNS(NS, 'rect');
    brush.setAttribute('class', 'brush'); brush.setAttribute('y', 0); brush.setAttribute('height', 42); brush.setAttribute('width', 0);
    svg.append(brush);
    let x0 = null;
    const toX = e => { const b = svg.getBoundingClientRect(); return Math.max(0, Math.min(n, ((e.clientX - b.left) / b.width) * n)); };
    svg.addEventListener('mousedown', e => { x0 = toX(e); brush.setAttribute('x', x0); brush.setAttribute('width', 0); });
    svg.addEventListener('mousemove', e => { if (x0 === null) return; const x = toX(e); brush.setAttribute('x', Math.min(x, x0)); brush.setAttribute('width', Math.abs(x - x0)); });
    const up = e => {
      if (x0 === null) return;
      const x = toX(e);
      const a = Math.min(x, x0), b = Math.max(x, x0);
      x0 = null;
      if (b - a < 0.3) { this.table.setRange(null); this.loadHist(); return; }
      const from = fmtTime(h.min + (a / n) * span), to = fmtTime(h.min + (b / n) * span + 1);
      this.table.setRange({ col: this.histCol, from, to });
      label.textContent = `${from} → ${to}`;
      clearBtn.hidden = false;
    };
    svg.addEventListener('mouseup', up);
    svg.addEventListener('mouseleave', e => { if (x0 !== null) up(e); });
    this.histBox.append(svg, el('div.axis', {}, el('span', { text: fmtTime(h.min) }), el('span', { text: fmtTime(h.min + span / 2) }), el('span', { text: fmtTime(h.max) })));
  }

  destroy() { this.off(); this.table.destroy(); }
}

/** Disassembly text with light syntax colouring (address / mnemonic / operands). */
export function disasmBlock(text) {
  const pre = el('pre.code');
  for (const line of text.replace(/^\n/, '').split('\n')) {
    const m = /^(0x[0-9a-f]+:?)(\s+)(\S+)(\s*)(.*)$/i.exec(line);
    if (!m) { pre.append(line + '\n'); continue; }
    const ops = el('span.o');
    for (const part of m[5].split(/(0x[0-9a-f]+)/i)) ops.append(/^0x/i.test(part) ? el('span.x', { text: part }) : part);
    pre.append(el('span.a', { text: m[1] }), m[2], el('span.m', { text: m[3] }), m[4], ops, '\n');
  }
  return pre;
}

export function captureTime() {
  const s = store.session;
  if (!s) return null;
  const f = (s.facts || []).find(([k]) => k === 'SystemTime');
  if (f) return parseTime(f[1]);
  return store.captureGuess || null;
}

export function relToCapture(t, cap) {
  const d = cap - t;
  if (Math.abs(d) < 1) return 'at capture time';
  const span = Math.abs(d);
  const txt = span < 60 ? `${Math.round(span)} s` : span < 3600 ? `${Math.round(span / 60)} min` : span < 172800 ? `${(span / 3600).toFixed(1)} h` : `${Math.round(span / 86400)} days`;
  return d > 0 ? `${txt} before capture` : `${txt} after capture`;
}

export { expectedDuration, fmtMs, prefs, toast };
