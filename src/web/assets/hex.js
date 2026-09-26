// Hex viewer over any layer (physical, kernel, a process's address space), with a data
// inspector, pointer following, history and disassembly.

import { api, store, el, clear, copy, int0, toast, emit, fmtTime } from './core.js';
import { disasmBlock, captureTime } from './result.js';

const ROWS = 65536;           // rows in the scrollable window (1 MiB)
const RH = 20;
const CHUNK = 16384n;

function hex(n, w = 16) { return n.toString(16).padStart(w, '0'); }
function hx(n) { return '0x' + n.toString(16); }

let hexSeq = 0;

export class HexTab {
  constructor({ layer = 'kernel', addr = '0x0' }) {
    this.key = 'hex' + (++hexSeq);
    this.layer = layer;
    this.chunks = new Map();     // chunk base (BigInt) -> {data: Uint8Array, bad: Uint8Array} | 'loading' | {error}
    this.history = [];
    this.sel = null;
    this.anchor = null;
    this.pane = el('div.pane');
    this.build();
    this.goto(BigInt(addr), true);
  }

  get title() { return 'mem ' + hx(this.sel ?? 0n); }
  get subtitle() { return this.layerLabel(this.layer); }

  layerLabel(id) {
    if (id === 'phys') return 'physical';
    if (id === 'kernel') return 'kernel';
    const pid = id.slice(4);
    const p = (store.procs || []).find(x => String(x.pid) === pid);
    return `pid ${pid}${p ? ' ' + p.name : ''}`;
  }

  build() {
    this.addrIn = el('input.input.addrin', { type: 'text', spellcheck: false, autocomplete: 'off', 'aria-label': 'Address (python int syntax: 0x..., decimal)', placeholder: '0x… address  (G)' });
    this.addrIn.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        const v = int0(this.addrIn.value.trim().match(/^[0-9a-f]+$/i) && !/^\d+$/.test(this.addrIn.value.trim()) ? '0x' + this.addrIn.value.trim() : this.addrIn.value);
        if (v === null || v < 0n) { this.addrIn.classList.add('invalid'); return; }
        this.addrIn.classList.remove('invalid');
        this.goto(v);
        this.grid.focus();
      }
      if (e.key === 'Escape') { this.grid.focus(); e.stopPropagation(); }
    });
    this.laySel = el('select.input.lay', { 'aria-label': 'Address space' });
    this.fillLayers();
    this.laySel.addEventListener('change', () => { this.layer = this.laySel.value; this.chunks.clear(); this.render(); this.inspect(); emit('tabs-changed'); });
    const back = el('button.btn.ghost', { type: 'button', title: 'Back (Backspace)', on: { click: () => this.back() } }, '← Back');
    const follow = el('button.btn.ghost', { type: 'button', title: 'Follow the pointer at the cursor (Enter)', on: { click: () => this.follow() } }, 'Follow ptr');
    const dis = el('button.btn', { type: 'button', title: 'Disassemble from the cursor (D)', on: { click: () => this.disasm() } }, 'Disassemble');
    const cp = el('button.btn.ghost', { type: 'button', title: 'Copy the selection as hex (C)', on: { click: () => this.copySel() } }, 'Copy hex');
    this.statusEl = el('span.muted', { style: { fontSize: '11px', marginLeft: 'auto' } });
    const bar = el('div.hx-bar', {}, this.laySel, this.addrIn, back, follow, dis, cp, this.statusEl);
    this.grid = el('div.hx-grid', { tabindex: 0, role: 'grid', 'aria-label': 'Memory bytes' });
    this.spacer = el('div', { style: { position: 'relative', height: ROWS * RH + 'px' } });
    this.rowsEl = el('div', { style: { position: 'absolute', left: 0, right: 0, top: 0 } });
    this.spacer.append(this.rowsEl);
    this.grid.append(this.spacer);
    this.side = el('div.hx-side');
    this.insp = el('div.insp');
    this.dis = el('div.hx-dis');
    this.side.append(el('h4', { text: 'Inspector' }), this.insp, el('h4', { text: 'Disassembly' }), this.dis);
    this.dis.append(el('div.hx-note', { text: 'Press D (or Disassemble) to disassemble from the cursor.' }));
    this.pane.append(el('div.hx', {}, bar, el('div.hx-body', {}, this.grid, this.side)));
    this.pool = [];
    this.grid.addEventListener('scroll', () => this.schedule(), { passive: true });
    new ResizeObserver(() => this.schedule()).observe(this.grid);
    this.grid.addEventListener('mousedown', e => {
      const t = e.target.closest('[data-o]');
      if (!t) return;
      const a = this.base + BigInt(t.dataset.o);
      if (e.shiftKey && this.sel !== null) { this.anchor ??= this.sel; this.sel = a; }
      else { this.anchor = null; this.sel = a; }
      this.grid.focus({ preventScroll: true });
      this.render();
      this.inspect();
      e.preventDefault();
    });
    this.grid.addEventListener('keydown', e => this.onKey(e));
  }

  fillLayers() {
    clear(this.laySel);
    const opts = [['kernel', 'Kernel virtual'], ['phys', 'Physical']];
    for (const p of (store.procs || []).filter(p => p.exit === null)) opts.push([`pid:${p.pid}`, `Process ${p.pid} ${p.name}`]);
    if (!opts.some(([v]) => v === this.layer)) opts.push([this.layer, this.layerLabel(this.layer)]);
    for (const [v, t] of opts) this.laySel.append(el('option', { value: v, text: t, selected: v === this.layer }));
  }

  goto(addr, initial = false) {
    if (!initial && this.sel !== null) this.history.push(this.sel);
    this.sel = addr;
    this.anchor = null;
    // window of ROWS*16 bytes around the address
    const half = BigInt(ROWS / 2) * 16n;
    let base = addr > half ? ((addr - half) & ~0xfffn) : 0n;
    this.base = base;
    this.addrIn.value = hx(addr);
    const row = Number((addr - base) / 16n);
    requestAnimationFrame(() => {
      this.grid.scrollTop = Math.max(0, row * RH - this.grid.clientHeight / 3);
      this.render();
    });
    this.inspect();
    emit('tabs-changed');
  }

  back() { if (this.history.length) { const a = this.history.pop(); this.sel = null; this.goto(a, true); } }

  chunk(base) {
    const c = this.chunks.get(base);
    if (c) return c === 'loading' ? null : c;
    this.chunks.set(base, 'loading');
    const layer = this.layer;
    api(`mem?layer=${encodeURIComponent(layer)}&addr=${hx(base)}&len=${CHUNK}`).then(r => {
      if (layer !== this.layer) return;
      const data = new Uint8Array(r.len);
      for (let i = 0; i < r.len; i++) data[i] = parseInt(r.hex.substr(i * 2, 2), 16);
      const bad = new Uint8Array(r.len);
      for (const [o, l] of r.bad) bad.fill(1, o, o + l);
      this.chunks.set(base, { data, bad, name: r.name });
      this.statusEl.textContent = '';
      if (this.chunks.size > 96) for (const k of [...this.chunks.keys()].slice(0, 32)) this.chunks.delete(k);
      this.schedule();
      this.inspect();
    }).catch(e => {
      this.chunks.set(base, { error: e.message });
      this.statusEl.textContent = e.message;
      this.schedule();
    });
    return null;
  }

  byte(a) {
    const base = a & ~(CHUNK - 1n);
    const c = this.chunk(base);
    if (!c) return undefined;
    if (c.error) return null;
    const i = Number(a - base);
    return c.bad[i] ? null : c.data[i];
  }

  schedule() { if (!this.raf) this.raf = requestAnimationFrame(() => { this.raf = 0; this.render(); }); }

  render() {
    if (!this.grid.isConnected) return;
    const first = Math.floor(this.grid.scrollTop / RH);
    const n = Math.ceil(this.grid.clientHeight / RH) + 2;
    this.rowsEl.style.transform = `translateY(${first * RH}px)`;
    while (this.pool.length < n) {
      const r = el('div.hx-row', { role: 'row' });
      r._o = el('span.o');
      r.append(r._o);
      r._b = [];
      for (let i = 0; i < 16; i++) { if (i === 8) r.append(el('span')); const b = el('b', { role: 'gridcell' }); r._b.push(b); r.append(b); }
      r.append(el('span'));
      r._a = el('span.asc');
      r._u = [];
      for (let i = 0; i < 16; i++) { const u = el('u'); r._u.push(u); r._a.append(u); }
      r.append(r._a);
      this.rowsEl.append(r);
      this.pool.push(r);
    }
    const lo = this.anchor !== null && this.sel !== null ? (this.anchor < this.sel ? this.anchor : this.sel) : null;
    const hi = this.anchor !== null && this.sel !== null ? (this.anchor < this.sel ? this.sel : this.anchor) : null;
    for (let k = 0; k < this.pool.length; k++) {
      const r = this.pool[k];
      const row = first + k;
      if (row >= ROWS || k >= n) { r.hidden = true; continue; }
      r.hidden = false;
      const a0 = this.base + BigInt(row) * 16n;
      r._o.textContent = hex(a0);
      r._o.className = 'o' + (this.sel !== null && a0 <= this.sel && this.sel < a0 + 16n ? ' here' : '');
      for (let i = 0; i < 16; i++) {
        const a = a0 + BigInt(i);
        const v = this.byte(a);
        const b = r._b[i], u = r._u[i];
        const off = String(row * 16 + i);
        b.dataset.o = off; u.dataset.o = off;
        let cls = '';
        if (v === undefined) { b.textContent = '··'; u.textContent = ' '; cls = 'bad'; }
        else if (v === null) { b.textContent = '??'; u.textContent = '·'; cls = 'bad'; }
        else {
          b.textContent = v.toString(16).padStart(2, '0');
          const printable = v >= 0x20 && v < 0x7f;
          u.textContent = printable ? String.fromCharCode(v) : '.';
          cls = v === 0 ? 'z' : '';
          u.className = printable ? '' : 'np';
        }
        const isSel = this.sel === a;
        const inRange = lo !== null && a >= lo && a <= hi;
        b.className = cls + (isSel ? ' sel' : inRange ? ' rng' : '');
        if (isSel) u.className = 'sel'; else if (inRange) u.className = 'rng'; else if (v === null || v === undefined) u.className = 'np';
      }
    }
  }

  readLE(a, n) {
    let v = 0n;
    for (let i = n - 1; i >= 0; i--) {
      const b = this.byte(a + BigInt(i));
      if (b === undefined || b === null) return null;
      v = (v << 8n) | BigInt(b);
    }
    return v;
  }

  inspect() {
    clear(this.insp);
    if (this.sel === null) return;
    const a = this.sel;
    const row = (k, v, extra) => { this.insp.append(el('span.k', { text: k }), el('span.v', {}, v ?? '—', extra || '')); };
    row('address', hx(a));
    if (this.anchor !== null) { const n = (this.sel > this.anchor ? this.sel - this.anchor : this.anchor - this.sel) + 1n; row('selection', `${n} bytes`); }
    const u8 = this.readLE(a, 1), u16 = this.readLE(a, 2), u32 = this.readLE(a, 4), u64 = this.readLE(a, 8);
    const s = (v, bits) => (v === null ? null : v >= 1n << BigInt(bits - 1) ? v - (1n << BigInt(bits)) : v);
    row('u8 / i8', u8 === null ? null : `${u8} / ${s(u8, 8)}`);
    row('u16 le', u16 === null ? null : `${u16}  ${hx(u16)}`);
    row('u32 le', u32 === null ? null : `${u32}  ${hx(u32)}`);
    row('i32 le', u32 === null ? null : String(s(u32, 32)));
    const ptr = u64 === null ? null : el('button.linkbtn', { type: 'button', text: hx(u64), title: 'Follow (Enter)', on: { click: () => this.follow() } });
    row('u64 / ptr', ptr);
    if (u64 !== null) {
      const ft = Number(u64) / 1e7 - 11644473600;
      if (ft > 0 && ft < 4102444800) row('FILETIME', fmtTime(ft) + ' UTC');
    }
    if (u32 !== null) {
      // only plausible timestamps: within ten years of the capture
      const ut = Number(u32);
      const cap = captureTime() || Date.now() / 1000;
      if (Math.abs(ut - cap) < 10 * 365 * 86400) row('unix time', fmtTime(ut) + ' UTC');
    }
    let str = '';
    for (let i = 0n; i < 96n; i++) { const b = this.byte(a + i); if (b === null || b === undefined || b === 0) break; str += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'; }
    row('ascii', str ? JSON.stringify(str) : null);
    let w = '';
    for (let i = 0n; i < 192n; i += 2n) { const v = this.readLE(a + i, 2); if (v === null || v === 0n) break; w += String.fromCharCode(Number(v)); }
    row('utf-16le', w ? JSON.stringify(w) : null);
  }

  follow() {
    if (this.sel === null) return;
    const bits = store.session && store.session.arch === 'intel' ? 4 : 8;
    const v = this.readLE(this.sel, bits);
    if (v === null) { toast('No readable pointer at the cursor', 'bad'); return; }
    this.goto(v);
  }

  async disasm() {
    if (this.sel === null) return;
    clear(this.dis);
    this.dis.append(el('div.hx-note', { text: 'Disassembling…' }));
    try {
      const r = await api(`disasm?layer=${encodeURIComponent(this.layer)}&addr=${hx(this.sel)}&len=256`);
      clear(this.dis);
      this.dis.append(el('div.hx-note', { text: `${r.arch} from ${r.addr}${r.partial ? ' (partly unreadable)' : ''}` }), disasmBlock(r.text || '(nothing decodable)'));
    } catch (e) {
      clear(this.dis);
      this.dis.append(el('div.hx-note', { text: e.message }));
    }
  }

  copySel() {
    if (this.sel === null) return;
    let lo = this.sel, hi = this.sel;
    if (this.anchor !== null) { lo = this.anchor < this.sel ? this.anchor : this.sel; hi = this.anchor < this.sel ? this.sel : this.anchor; }
    if (hi - lo > 65536n) { toast('Selection too large to copy (max 64 KiB)', 'bad'); return; }
    const out = [];
    for (let a = lo; a <= hi; a++) { const b = this.byte(a); out.push(b === null || b === undefined ? '??' : b.toString(16).padStart(2, '0')); }
    copy(out.join(' '), `Copied ${out.length} bytes`);
  }

  onKey(e) {
    if (this.sel === null) this.sel = this.base;
    const page = BigInt(Math.max(1, Math.floor(this.grid.clientHeight / RH) - 1) * 16);
    const move = d => {
      if (e.shiftKey) this.anchor ??= this.sel; else this.anchor = null;
      let n = this.sel + d;
      if (n < 0n) n = 0n;
      this.sel = n;
      const row = Number((n - this.base) / 16n);
      if (row < 0 || row >= ROWS) { const s = this.sel; this.sel = null; this.goto(s, true); return; }
      const y = row * RH;
      if (y < this.grid.scrollTop) this.grid.scrollTop = y;
      else if (y + RH > this.grid.scrollTop + this.grid.clientHeight) this.grid.scrollTop = y + RH - this.grid.clientHeight;
      this.render(); this.inspect();
      this.addrIn.value = hx(this.sel);
      emit('tabs-changed');
    };
    switch (e.key) {
      case 'ArrowRight': move(1n); break;
      case 'ArrowLeft': move(-1n); break;
      case 'ArrowDown': move(16n); break;
      case 'ArrowUp': move(-16n); break;
      case 'PageDown': move(page); break;
      case 'PageUp': move(-page); break;
      case 'Home': move(-(this.sel % 16n)); break;
      case 'End': move(15n - (this.sel % 16n)); break;
      case 'Enter': this.follow(); break;
      case 'Backspace': this.back(); break;
      case 'g': case 'G': this.addrIn.focus(); this.addrIn.select(); break;
      case 'd': case 'D': this.disasm(); break;
      case 'c': case 'C': if ((e.ctrlKey || e.metaKey) && window.getSelection().toString()) return; this.copySel(); break;
      default: return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  onShow() { this.fillLayers(); this.schedule(); }
  focus() { this.grid.focus({ preventScroll: true }); }
  focusFilter() { this.addrIn.focus(); this.addrIn.select(); }
  destroy() {}
}
