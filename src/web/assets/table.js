// Virtualised result table. The server owns the rows (compact tables + filtered/sorted
// views); the browser only ever holds a few pages around the viewport, so millions of rows
// scroll as smoothly as ten.

import { api, fetchRows, el, clear, copy, debounce, prefs, cellText, menu } from './core.js';

const PAGE = 256;
const MAX_PX = 15_000_000;          // stay well below browser element-height limits
const NUMERIC = new Set(['Int', 'Float', 'Bin']);
let uid = 0;

export class VirtualTable {
  /**
   * opts: runId, plugin, fixed ({col: expr} always-on filters), cmp (compare spec),
   * onHex(addrText, colName, row), onPid(pid), onOpen(row), onState(), rowH
   */
  constructor(opts) {
    this.o = opts;
    this.id = 'vt' + (++uid);
    this.runId = opts.runId;
    this.rowH = opts.rowH || 24;
    this.cols = [];
    this.widths = [];
    this.hidden = new Set();
    this.sort = [];
    this.filters = {};
    this.q = '';
    this.range = null;              // {col, from, to}
    this.view = 0;
    this.total = 0;
    this.stored = 0;
    this.matched = 0;
    this.viewMs = 0;
    this.pages = new Map();
    this.inflight = new Map();
    this.gen = 0;
    this.cur = { row: 0, col: 0 };
    this.showFilters = false;
    this.pool = [];
    this.error = '';
    this.status = '';
    this.built = false;
    this.lastViewAt = 0;

    this.root = el('div.vt', { tabindex: 0, role: 'grid', 'aria-label': opts.label || 'Results', 'aria-multiselectable': 'false' });
    this.root._vt = this; // handle for tests / debugging
    this.scroll = el('div.vt-scroll');
    this.head = el('div.vt-head', { role: 'rowgroup' });
    this.spacer = el('div.vt-spacer', { role: 'rowgroup' });
    this.rowsEl = el('div.vt-rows');
    this.spacer.append(this.rowsEl);
    this.emptyEl = el('div.vt-empty', { hidden: true });
    this.scroll.append(this.head, this.spacer);
    this.foot = el('div.vt-foot', { 'aria-live': 'polite' });
    this.root.append(this.scroll, this.emptyEl, this.foot);

    this.scroll.addEventListener('scroll', () => this.schedule(), { passive: true });
    this.ro = new ResizeObserver(() => this.schedule());
    this.ro.observe(this.scroll);
    this.root.addEventListener('keydown', e => this.onKey(e));
    this.rowsEl.addEventListener('click', e => this.onClick(e));
    this.rowsEl.addEventListener('dblclick', e => { const r = this.rowFromEvent(e); if (r) this.o.onOpen && this.o.onOpen(r); });
    this.refreshView = debounce(() => this.buildView(), 180);
  }

  // ------------------------------------------------------------------ data
  /** Feed a run summary (from the event stream). */
  update(run) {
    this.status = run.status;
    if (!this.built && run.cols && run.cols.length) this.setColumns(run.cols);
    if (!this.built) { this.renderFoot(); this.renderEmpty(); return; }
    const grew = run.stored !== this.stored;
    this.stored = run.stored;
    if (!grew && this.statusSeen === run.status) return;
    const finishedNow = this.statusSeen !== run.status && run.status !== 'running' && run.status !== 'queued';
    this.statusSeen = run.status;
    if (this.view === 0 && !this.hasSpec()) {
      const old = this.total;
      this.total = run.stored;
      this.matched = run.stored;
      // the page holding the old tail was partial
      this.pages.delete(Math.floor(old / PAGE));
      this.layout();
      this.schedule();
    } else if (grew || finishedNow) {
      // filtered/sorted views are snapshots: refresh at most once a second while rows arrive
      const wait = finishedNow ? 0 : Math.max(0, 1000 - (Date.now() - this.lastViewAt));
      clearTimeout(this.viewTimer);
      this.viewTimer = setTimeout(() => this.buildView(false), wait);
    }
    this.renderFoot();
  }

  setColumns(cols) {
    this.cols = cols;
    this.built = true;
    const saved = prefs.get('cols:' + this.o.plugin, null);
    const hid = saved && saved.hidden ? saved.hidden : [];
    this.hidden = new Set(cols.map((c, i) => (hid.includes(c.name) ? i : -1)).filter(i => i >= 0));
    if (this.hidden.size === cols.length) this.hidden.clear();
    this.savedWidths = (saved && saved.widths) || {};
    this.widths = cols.map(c => this.savedWidths[c.name] || this.guessWidth(c, []));
    this.autosized = false;
    this.cur.col = this.visible()[0] || 0;
    this.buildHead();
    this.buildView();
  }

  hasSpec() {
    return !!(this.q || this.sort.length || Object.values(this.filters).some(Boolean) || this.range || this.o.cmp || (this.o.fixed && Object.keys(this.o.fixed).length));
  }

  spec() {
    const cols = { ...(this.o.fixed || {}) };
    for (const [k, v] of Object.entries(this.filters)) if (v) cols[k] = cols[k] ? cols[k] : v;
    return {
      q: this.q,
      cols,
      visible: this.visible(),
      sort: this.sort.map(([c, d]) => [c, d]),
      range: this.range,
      cmp: this.o.cmp || null,
      tree: true,
    };
  }

  /** Rebuild the server-side view. `reset`: the spec changed, so go back to the top (a
   * refresh because more rows arrived keeps the position). */
  async buildView(reset = true) {
    if (!this.built) return;
    const gen = ++this.gen;
    this.lastViewAt = Date.now();
    // big views take a moment: show it after 120 ms
    const busyT = setTimeout(() => { if (gen === this.gen) this.root.classList.add('busy'); }, 120);
    try {
      const r = await api(`runs/${this.runId}/view`, { method: 'POST', body: this.spec() });
      clearTimeout(busyT);
      this.root.classList.remove('busy');
      if (gen !== this.gen) return;
      this.error = '';
      this.view = r.view;
      this.total = r.total;
      this.matched = r.matched;
      this.viewMs = r.ms;
      this.pages.clear();
      this.inflight.clear();
      if (reset) { this.scroll.scrollTop = 0; this.cur.row = 0; }
      if (this.cur.row >= this.total) this.cur.row = Math.max(0, this.total - 1);
      this.markFilterErrors(null);
      this.layout();
      this.schedule();
    } catch (e) {
      clearTimeout(busyT);
      this.root.classList.remove('busy');
      if (gen !== this.gen) return;
      this.error = e.message;
      this.markFilterErrors(e.message);
    }
    this.renderFoot();
    this.renderEmpty();
    this.o.onState && this.o.onState();
  }

  page(p) {
    const got = this.pages.get(p);
    if (got) return got;
    if (this.inflight.has(p)) return null;
    const gen = this.gen, view = this.view;
    const ctl = new AbortController();
    this.inflight.set(p, ctl);
    fetchRows(this.runId, view, p * PAGE, PAGE, ctl.signal).then(r => {
      this.inflight.delete(p);
      if (gen !== this.gen) return;
      this.pages.set(p, r.rows);
      if (!this.autosized && p === 0) this.autosize(r.rows);
      // keep memory bounded: drop far-away pages
      if (this.pages.size > 48) {
        const center = Math.floor(this.firstRow / PAGE);
        const far = [...this.pages.keys()].sort((a, b) => Math.abs(b - center) - Math.abs(a - center));
        for (const k of far.slice(0, this.pages.size - 40)) this.pages.delete(k);
      }
      this.schedule();
    }).catch(e => {
      this.inflight.delete(p);
      if (e.name === 'AbortError') return;
      if (e.status === 410 && /dropped from memory/.test(e.message)) { this.error = e.message; this.renderFoot(); return; }
      if (e.status === 410) { this.buildView(); return; }
      this.error = e.message;
      this.renderFoot();
    });
    return null;
  }

  /** Row data at view index `i` (array [idx, flags, ...cells]) or undefined if not loaded. */
  rowAt(i) {
    const p = this.pages.get(Math.floor(i / PAGE));
    return p ? p[i % PAGE] : undefined;
  }

  visible() { return this.cols.map((_, i) => i).filter(i => !this.hidden.has(i)); }

  // ------------------------------------------------------------------ layout
  charW() {
    if (!VirtualTable._cw) {
      const probe = el('span', { style: { position: 'absolute', visibility: 'hidden', font: getComputedStyle(this.root).font, whiteSpace: 'pre' } }, 'x'.repeat(100));
      document.body.append(probe);
      VirtualTable._cw = probe.getBoundingClientRect().width / 100 || 7.5;
      probe.remove();
    }
    return VirtualTable._cw;
  }

  guessWidth(c, rows, i) {
    const cw = this.charW();
    let chars = Math.max(c.name.length + 3, { Hex: 16, DateTime: 30, Int: 6, Bool: 5 }[c.type] || 8);
    if (rows.length && i !== undefined) {
      let m = 0;
      for (const r of rows) {
        const v = r[i + 2];
        if (typeof v !== 'string') continue;
        const nl = v.indexOf('\n');
        const len = nl >= 0 ? Math.max(nl, 12) : v.length;
        if (len > m) m = len;
      }
      chars = Math.max(c.name.length + 3, Math.min(m + 1, c.type === 'Str' ? 64 : 40), 4);
    }
    return Math.round(chars * cw + 18);
  }

  autosize(rows) {
    this.autosized = true;
    this.widths = this.cols.map((c, i) => this.savedWidths[c.name] || this.guessWidth(c, rows, i));
    this.applyWidths();
  }

  applyWidths() {
    const t = this.visible().map(i => this.widths[i] + 'px').join(' ');
    this.root.style.setProperty('--vt-cols', t);
  }

  saveCols() {
    const widths = {};
    this.cols.forEach((c, i) => { if (this.userSized && this.userSized.has(i)) widths[c.name] = this.widths[i]; });
    const prev = prefs.get('cols:' + this.o.plugin, {}) || {};
    prefs.set('cols:' + this.o.plugin, { widths: { ...(prev.widths || {}), ...widths }, hidden: [...this.hidden].map(i => this.cols[i].name) });
  }

  buildHead() {
    clear(this.head);
    const vis = this.visible();
    const hrow = el('div.vt-hrow', { role: 'row', 'aria-rowindex': 1 });
    for (const i of vis) {
      const c = this.cols[i];
      const s = this.sort.findIndex(([k]) => k === i);
      const dir = s >= 0 ? this.sort[s][1] : null;
      const cell = el('div.vt-hcell', {
        role: 'columnheader',
        'aria-sort': dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none',
        title: `${c.name} (${c.type}) — click to sort, Shift+click for a secondary sort, right-click for more`,
        class: 'vt-hcell' + (this.filters[i] ? ' filtered' : ''),
        dataset: { col: i },
      },
      el('span.hn', { text: c.name }),
      dir ? el('span.so', { text: (dir === 'asc' ? '▲' : '▼') + (this.sort.length > 1 ? s + 1 : '') }) : null,
      el('span.ht', { text: typeLabel(c.type) }));
      const grip = el('span.grip', { 'aria-hidden': 'true' });
      grip.addEventListener('mousedown', e => this.startResize(e, i, grip));
      grip.addEventListener('dblclick', e => { e.stopPropagation(); this.fitColumn(i); });
      grip.addEventListener('click', e => e.stopPropagation());
      cell.append(grip);
      cell.addEventListener('click', e => this.toggleSort(i, e.shiftKey));
      cell.addEventListener('contextmenu', e => { e.preventDefault(); this.columnMenu(cell, i); });
      hrow.append(cell);
    }
    this.head.append(hrow);
    if (this.showFilters) {
      const frow = el('div.vt-frow', { role: 'row' });
      for (const i of vis) {
        const c = this.cols[i];
        const inp = el('input', {
          type: 'text', value: this.filters[i] || '', spellcheck: false, autocomplete: 'off',
          placeholder: NUMERIC.has(c.type) || c.type === 'Hex' ? '>0x10, =4, !-' : c.type === 'DateTime' ? '>2024-01-31' : 'contains, =, !, /re/',
          'aria-label': `Filter ${c.name}`,
          dataset: { col: i },
        });
        inp.addEventListener('input', () => { this.filters[i] = inp.value; this.refreshView(); this.markHeader(); });
        inp.addEventListener('keydown', e => {
          if (e.key === 'Enter') { this.buildView(); }
          if (e.key === 'Escape') { if (inp.value) { inp.value = ''; this.filters[i] = ''; this.buildView(); } else { this.root.focus(); } e.stopPropagation(); }
          if (e.key === 'ArrowDown') { e.preventDefault(); this.root.focus(); }
          e.stopPropagation();
        });
        frow.append(inp);
      }
      this.head.append(frow);
    }
    this.root.setAttribute('aria-colcount', vis.length);
    this.applyWidths();
    this.rebuildPool();
  }

  markHeader() {
    for (const h of this.head.querySelectorAll('.vt-hcell')) h.classList.toggle('filtered', !!this.filters[+h.dataset.col]);
  }

  markFilterErrors(msg) {
    for (const inp of this.head.querySelectorAll('.vt-frow input')) {
      const col = this.cols[+inp.dataset.col];
      inp.classList.toggle('invalid', !!msg && !!inp.value && msg.includes(col.name));
    }
  }

  toggleFilters(force) {
    this.showFilters = force ?? !this.showFilters;
    this.buildHead();
    if (this.showFilters) {
      const vis = this.visible();
      const k = Math.max(0, vis.indexOf(this.cur.col));
      const inp = this.head.querySelectorAll('.vt-frow input')[k];
      if (inp) inp.focus();
    }
    this.o.onState && this.o.onState();
  }

  toggleSort(i, add) {
    const s = this.sort.findIndex(([k]) => k === i);
    if (!add) {
      const next = s < 0 ? 'asc' : this.sort[s][1] === 'asc' ? 'desc' : null;
      this.sort = next ? [[i, next]] : [];
    } else if (s < 0) this.sort.push([i, 'asc']);
    else if (this.sort[s][1] === 'asc') this.sort[s][1] = 'desc';
    else this.sort.splice(s, 1);
    this.buildHead();
    this.buildView();
  }

  columnMenu(anchor, i) {
    const c = this.cols[i];
    menu(anchor, [
      { header: c.name },
      { label: 'Sort ascending', act: () => { this.sort = [[i, 'asc']]; this.buildHead(); this.buildView(); } },
      { label: 'Sort descending', act: () => { this.sort = [[i, 'desc']]; this.buildHead(); this.buildView(); } },
      { label: 'Filter this column…', hint: 'F', act: () => { this.cur.col = i; this.toggleFilters(true); } },
      { label: 'Only rows with a value', act: () => { this.filters[i] = '!-'; this.buildHead(); this.buildView(); } },
      'sep',
      { label: 'Fit width to content', act: () => this.fitColumn(i) },
      { label: 'Hide column', act: () => this.setHidden(i, true) },
      { label: 'Copy visible values', act: () => this.copyColumn(i) },
    ]);
  }

  setHidden(i, hide) {
    if (hide) this.hidden.add(i); else this.hidden.delete(i);
    if (this.hidden.size >= this.cols.length) this.hidden.delete(i);
    if (this.hidden.has(this.cur.col)) this.cur.col = this.visible()[0];
    this.saveCols();
    this.buildHead();
    if (this.q) this.buildView(); else this.schedule();
    this.o.onState && this.o.onState();
  }

  startResize(e, i, grip) {
    e.preventDefault();
    e.stopPropagation();
    const x0 = e.clientX, w0 = this.widths[i];
    grip.classList.add('drag');
    const move = ev => { this.widths[i] = Math.max(36, w0 + ev.clientX - x0); this.applyWidths(); };
    const up = () => {
      grip.classList.remove('drag');
      removeEventListener('mousemove', move);
      removeEventListener('mouseup', up);
      (this.userSized ||= new Set()).add(i);
      this.saveCols();
    };
    addEventListener('mousemove', move);
    addEventListener('mouseup', up);
  }

  fitColumn(i) {
    const rows = [];
    for (let k = this.firstRow || 0; k < (this.firstRow || 0) + 200; k++) { const r = this.rowAt(k); if (r) rows.push(r); }
    this.widths[i] = this.guessWidth(this.cols[i], rows, i);
    (this.userSized ||= new Set()).add(i);
    this.applyWidths();
    this.saveCols();
  }

  async copyColumn(i) {
    const out = [];
    const n = Math.min(this.total, 20000);
    for (let from = 0; from < n; from += 5000) {
      const r = await fetchRows(this.runId, this.view, from, Math.min(5000, n - from));
      for (const row of r.rows) out.push(cellText(row[i + 2]));
    }
    copy(out.join('\n'), `Copied ${out.length} values`);
  }

  rebuildPool() {
    clear(this.rowsEl);
    this.pool = [];
    this.schedule();
  }

  layout() {
    const full = this.total * this.rowH;
    this.scaled = full > MAX_PX;
    this.spacer.style.height = (this.scaled ? MAX_PX : full) + 'px';
    this.root.setAttribute('aria-rowcount', this.total + 1);
  }

  schedule() {
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => { this.raf = 0; this.render(); });
  }

  render() {
    if (!this.built) return;
    const vis = this.visible();
    const headH = this.head.offsetHeight;
    const viewH = Math.max(0, this.scroll.clientHeight - headH);
    const st = this.scroll.scrollTop;
    const n = this.total;
    const count = Math.ceil(viewH / this.rowH) + 1;
    let first, offset;
    if (this.scaled) {
      const range = Math.max(1, MAX_PX - viewH);
      const topF = Math.min(1, st / range) * Math.max(0, n - count + 1);
      first = Math.floor(topF);
      offset = st - (topF - first) * this.rowH;
    } else {
      first = Math.floor(st / this.rowH);
      offset = first * this.rowH;
    }
    const overscan = this.scaled ? 0 : 4;
    const start = Math.max(0, first - overscan);
    if (!this.scaled) offset = start * this.rowH;
    const end = Math.min(n, first + count + overscan);
    this.firstRow = first;
    this.rowsEl.style.transform = `translateY(${offset}px)`;
    const need = end - start;
    while (this.pool.length < need) {
      const slot = this.pool.length;
      const r = el('div.vt-row', { role: 'row' });
      r._cells = vis.map((c, k) => { const d = el('div.vt-cell', { role: 'gridcell', id: `${this.id}-s${slot}-c${k}` }); r.append(d); return d; });
      this.rowsEl.append(r);
      this.pool.push(r);
    }
    for (let k = 0; k < this.pool.length; k++) this.pool[k].hidden = k >= need;
    // request pages covering the range (+1 page of look-ahead)
    for (let p = Math.floor(start / PAGE); p <= Math.floor(Math.max(start, end - 1) / PAGE) && n; p++) this.page(p);
    const nextP = Math.floor(end / PAGE);
    if (end < n && !this.pages.has(nextP) && end % PAGE > PAGE * 0.6) this.page(nextP);
    let active = null;
    for (let k = 0; k < need; k++) {
      const vi = start + k;
      const rowEl = this.pool[k];
      const row = this.rowAt(vi);
      rowEl.setAttribute('aria-rowindex', vi + 2);
      rowEl._vi = vi;
      const isCur = vi === this.cur.row;
      if (!row) {
        rowEl.className = 'vt-row loading' + (isCur ? ' cur' : '');
        for (const c of rowEl._cells) { c._v = undefined; c.textContent = ''; c.className = 'vt-cell'; }
        continue;
      }
      const flags = row[1];
      const depth = flags >> 2;
      rowEl.className = 'vt-row' + (flags & 1 ? ' ctx' : '') + (flags & 2 ? ' uniq' : '') + (isCur ? ' cur' : '');
      rowEl.setAttribute('aria-selected', isCur ? 'true' : 'false');
      rowEl._row = row;
      for (let j = 0; j < vis.length; j++) {
        const ci = vis[j];
        const cell = rowEl._cells[j];
        this.fillCell(cell, ci, row[ci + 2], j === 0 ? depth : -1);
        if (isCur && ci === this.cur.col) { cell.classList.add('cc'); active = cell; }
      }
    }
    if (active) this.root.setAttribute('aria-activedescendant', active.id);
    else this.root.removeAttribute('aria-activedescendant');
    this.renderEmpty();
  }

  fillCell(cell, ci, v, depth) {
    const c = this.cols[ci];
    const key = v === null ? '\u0000n' : v === 0 ? '\u0000a' : v;
    if (cell._v === key && cell._ci === ci && cell._d === depth) {
      return;
    }
    cell._v = key; cell._ci = ci; cell._d = depth;
    let cls = 'vt-cell';
    if (depth >= 0) { cls += ' t0'; cell.style.setProperty('--d', depth); if (depth > 0) cls += ' tree'; }
    if (v === null || v === 0) {
      cell.className = cls + ' ab';
      cell.textContent = v === null ? '-' : 'N/A';
      return;
    }
    const t = c.type;
    if (NUMERIC.has(t)) cls += ' num';
    if (t === 'Hex') cls += ' hex link';
    if (t === 'Int' && /^(PID|PPID|Pid|PPid|Process ID)$/.test(c.name) && this.o.onPid) cls += ' pidlink';
    cell.className = cls;
    const nl = v.indexOf('\n');
    if (nl >= 0) {
      const lines = v.split('\n');
      const firstLine = lines.find(l => l.trim()) || '';
      clear(cell);
      cell.append(firstLine, el('span.ml', { text: `${lines.length} lines` }));
      return;
    }
    if (t === 'DateTime' && v.length > 19) {
      clear(cell);
      cell.append(v.slice(0, 19), el('span.dim', { text: v.slice(19) }));
      return;
    }
    cell.textContent = v;
  }

  renderEmpty() {
    let msg = '';
    if (!this.built) {
      msg = this.status === 'queued' ? 'Waiting for a free worker…' : this.status === 'running' ? 'Running… results appear here as soon as the plugin produces them.' : this.status === 'done' ? 'The plugin produced no table.' : '';
    } else if (this.total === 0) {
      if (this.status === 'running' || this.status === 'queued') msg = 'No rows yet…';
      else if (this.hasSpec() && this.stored > 0 && this.o.fixed && Object.keys(this.o.fixed).length && !this.q && !Object.values(this.filters).some(Boolean) && !this.range)
        msg = `Nothing for this process — the plugin found ${this.stored.toLocaleString()} rows in total (Open ↗ shows them all).`;
      else if (this.hasSpec() && this.stored > 0) msg = 'No rows match the current filters.';
      else if (this.status === 'done') msg = 'The plugin finished without results.';
    }
    this.emptyEl.hidden = !msg;
    this.emptyEl.textContent = msg;
  }

  renderFoot() {
    const parts = [];
    if (this.built) {
      if (this.hasSpec() && this.view) parts.push(`${this.total.toLocaleString()} of ${this.stored.toLocaleString()} rows`);
      else parts.push(`${this.total.toLocaleString()} rows`);
      if (this.sort.length) parts.push('sorted by ' + this.sort.map(([c, d]) => `${this.cols[c].name} ${d === 'asc' ? '▲' : '▼'}`).join(', '));
      if (this.view && this.viewMs > 20) parts.push(`view ${this.viewMs} ms`);
    }
    clear(this.foot);
    this.foot.append(...parts.map(p => el('span', { text: p })), el('span.sp'));
    if (this.error) this.foot.append(el('span', { text: this.error, style: { color: 'var(--bad)' } }));
    if (this.built && this.total) this.foot.append(el('span', { text: `row ${(this.cur.row + 1).toLocaleString()}` }));
    this.o.onState && this.o.onState();
  }

  // ------------------------------------------------------------------ interaction
  rowFromEvent(e) {
    const r = e.target.closest('.vt-row');
    return r && r._row ? r._row : null;
  }

  onClick(e) {
    const rowEl = e.target.closest('.vt-row');
    if (!rowEl || rowEl._vi === undefined) return;
    const cellEl = e.target.closest('.vt-cell');
    const k = rowEl._cells.indexOf(cellEl);
    const vis = this.visible();
    this.cur.row = rowEl._vi;
    if (k >= 0) this.cur.col = vis[k];
    this.root.focus({ preventScroll: true });
    this.render();
    this.renderFoot();
    const row = rowEl._row;
    if (!row || k < 0) return;
    const ci = vis[k];
    const c = this.cols[ci];
    const v = row[ci + 2];
    if (c.type === 'Hex' && typeof v === 'string' && this.o.onHex && !e.shiftKey && !window.getSelection().toString()) this.o.onHex(v, c.name, row, this);
    else if (cellEl.classList.contains('pidlink') && typeof v === 'string') this.o.onPid(Number(v));
    this.o.onCursor && this.o.onCursor(row);
  }

  moveTo(row, col) {
    if (!this.total) return;
    this.cur.row = Math.max(0, Math.min(this.total - 1, row));
    if (col !== undefined) this.cur.col = col;
    // scroll into view
    const headH = this.head.offsetHeight;
    const viewH = this.scroll.clientHeight - headH;
    if (this.scaled) {
      const range = MAX_PX - viewH;
      const count = Math.ceil(viewH / this.rowH);
      const first = this.firstRow || 0;
      if (this.cur.row < first || this.cur.row >= first + count - 1) {
        const target = Math.max(0, this.cur.row - Math.floor(count / 2));
        this.scroll.scrollTop = (target / Math.max(1, this.total - count)) * range;
      }
    } else {
      const y = this.cur.row * this.rowH;
      if (y < this.scroll.scrollTop) this.scroll.scrollTop = y;
      else if (y + this.rowH > this.scroll.scrollTop + viewH) this.scroll.scrollTop = y + this.rowH - viewH;
    }
    // horizontal
    const vis = this.visible();
    const k = vis.indexOf(this.cur.col);
    let x = 0;
    for (let j = 0; j < k; j++) x += this.widths[vis[j]];
    const w = this.widths[this.cur.col] || 0;
    if (x < this.scroll.scrollLeft) this.scroll.scrollLeft = x;
    else if (x + w > this.scroll.scrollLeft + this.scroll.clientWidth) this.scroll.scrollLeft = x + w - this.scroll.clientWidth;
    this.render();
    this.renderFoot();
    const r = this.rowAt(this.cur.row);
    if (r && this.o.onCursor) this.o.onCursor(r);
  }

  onKey(e) {
    if (e.target !== this.root) return;
    const vis = this.visible();
    const k = vis.indexOf(this.cur.col);
    const pageRows = Math.max(1, Math.floor((this.scroll.clientHeight - this.head.offsetHeight) / this.rowH) - 1);
    const row = this.rowAt(this.cur.row);
    const cell = row ? row[this.cur.col + 2] : undefined;
    const ctrl = e.ctrlKey || e.metaKey;
    switch (e.key) {
      case 'ArrowDown': this.moveTo(this.cur.row + 1); break;
      case 'ArrowUp': this.moveTo(this.cur.row - 1); break;
      case 'PageDown': this.moveTo(this.cur.row + pageRows); break;
      case 'PageUp': this.moveTo(this.cur.row - pageRows); break;
      case 'Home': ctrl ? this.moveTo(0) : this.moveTo(this.cur.row, vis[0]); break;
      case 'End': ctrl ? this.moveTo(this.total - 1) : this.moveTo(this.cur.row, vis[vis.length - 1]); break;
      case 'ArrowRight': this.moveTo(this.cur.row, vis[Math.min(vis.length - 1, k + 1)]); break;
      case 'ArrowLeft': this.moveTo(this.cur.row, vis[Math.max(0, k - 1)]); break;
      case 'Enter': if (row && this.o.onOpen) this.o.onOpen(row); break;
      case 'c': case 'C':
        if (ctrl && window.getSelection().toString()) return;
        if (!row) return;
        if (e.shiftKey) copy(this.rowTsv(row), 'Row copied');
        else copy(cellText(cell), 'Copied');
        break;
      case 'x': case 'h': {
        if (!row || !this.o.onHex) return;
        let ci = this.cols[this.cur.col].type === 'Hex' ? this.cur.col : this.cols.findIndex(c => c.type === 'Hex');
        if (ci < 0 || typeof row[ci + 2] !== 'string') return;
        this.o.onHex(row[ci + 2], this.cols[ci].name, row, this);
        break;
      }
      case 'p': {
        const pc = this.cols.findIndex(c => /^(PID|Pid)$/.test(c.name));
        if (row && pc >= 0 && typeof row[pc + 2] === 'string' && this.o.onPid) this.o.onPid(Number(row[pc + 2]));
        break;
      }
      case 'f': case 'F': if (ctrl) return; this.toggleFilters(); break;
      case 's': this.toggleSort(this.cur.col, e.shiftKey); break;
      default: return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  rowTsv(row) {
    return this.visible().map(i => cellText(row[i + 2])).join('\t');
  }

  headerTsv() { return this.visible().map(i => this.cols[i].name).join('\t'); }

  /** Export URL of the current view with the visible columns. */
  exportUrl(fmt) {
    return `/api/runs/${this.runId}/export?view=${this.view}&format=${fmt}&cols=${this.visible().join(',')}`;
  }

  setQuery(q) { this.q = q; this.refreshView(); }

  setRange(r) { this.range = r; this.buildView(); }

  destroy() { this.ro.disconnect(); this.gen++; for (const c of this.inflight.values()) c.abort(); }
}

function typeLabel(t) {
  return { Hex: 'hex', Int: '#', DateTime: 'time', Str: '', Bool: 'bool', Bytes: 'bytes', HexBytes: 'dump', Disassembly: 'asm', MultiTypeData: 'data', LayerData: 'dump', Float: '#.#', Bin: 'bin' }[t] ?? '';
}
