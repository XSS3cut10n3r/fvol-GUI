// Bootstrap: load plugins and session, start the event stream, wire global shortcuts.

import { store, api, on, emit, el, startEvents, prefs, fmtBytes, fmtTime, toast, closeMenu, TOKEN, setToken, modal } from './core.js';
import { openTab, activate, cycleTab, nthTab, closeTab, activeView, Overview, renderRunList, restoreTabs, closeSessionTabs, helpDialog, memoryPrompt, openImageDialog, openCompare, refreshTabs } from './views.js';
import { initTree, loadProcs, resetTree, renderTree } from './procs.js';
import { openPalette, paletteOpen } from './palette.js';
import { captureTime } from './result.js';

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('rsvol.theme', t); } catch (e) { /* ignore */ }
}

function renderTopbar() {
  const s = store.session;
  const name = document.getElementById('ev-name');
  const meta = document.getElementById('ev-meta');
  if (!s || !s.image) { name.textContent = 'no image — click to open one'; meta.textContent = ''; return; }
  name.textContent = s.name;
  const F = Object.fromEntries(s.facts || []);
  const parts = [fmtBytes(s.size)];
  if (s.os === 'windows') parts.push(`Windows ${(F['Major/Minor'] || '').split('.').pop() || ''} ${s.arch === 'intel64' ? 'x64' : 'x86'}`.replace(/\s+/g, ' ').trim());
  else if (s.os === 'linux') parts.push('Linux ' + ((F.Banner || '').match(/Linux version (\S+)/) || [, ''])[1]);
  else if (s.os === 'mac') parts.push('macOS ' + ((F.Banner || '').match(/Darwin Kernel Version (\S+?):/) || [, ''])[1]);
  const cap = captureTime();
  if (cap) parts.push('captured ' + fmtTime(cap) + ' UTC');
  if (s.state === 'warming') parts.push((s.phase || 'preparing') + '…');
  if (s.state === 'failed') parts.push('⚠ not recognised');
  meta.textContent = parts.join('  ·  ');
  document.title = `${s.name} — rsvol`;
}

function railResize() {
  const handle = document.getElementById('rail-resize');
  const rail = document.getElementById('rail');
  const w = prefs.get('railW', null);
  if (w) document.documentElement.style.setProperty('--rail', w + 'px');
  const set = px => { const v = Math.max(200, Math.min(innerWidth * 0.6, px)); document.documentElement.style.setProperty('--rail', v + 'px'); prefs.set('railW', v); };
  handle.addEventListener('mousedown', e => {
    e.preventDefault();
    handle.classList.add('drag');
    const move = ev => set(ev.clientX);
    const up = () => { handle.classList.remove('drag'); removeEventListener('mousemove', move); removeEventListener('mouseup', up); };
    addEventListener('mousemove', move);
    addEventListener('mouseup', up);
  });
  handle.addEventListener('keydown', e => {
    if (e.key === 'ArrowLeft') set(rail.offsetWidth - 20);
    if (e.key === 'ArrowRight') set(rail.offsetWidth + 20);
  });
  const split = document.getElementById('rail-split');
  const procs = rail.querySelector('.procs'), hist = rail.querySelector('.history');
  const hf = prefs.get('histFrac', null);
  const setFrac = f => { f = Math.max(0.12, Math.min(0.8, f)); procs.style.flex = `1 1 ${(1 - f) * 100}%`; hist.style.flex = `1 1 ${f * 100}%`; prefs.set('histFrac', f); };
  if (hf) setFrac(hf);
  split.addEventListener('mousedown', e => {
    e.preventDefault();
    split.classList.add('drag');
    const r = rail.getBoundingClientRect();
    const move = ev => setFrac(1 - (ev.clientY - r.top) / r.height);
    const up = () => { split.classList.remove('drag'); removeEventListener('mousemove', move); removeEventListener('mouseup', up); };
    addEventListener('mousemove', move);
    addEventListener('mouseup', up);
  });
}

function typing(e) {
  const t = e.target;
  return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
}

function shortcuts() {
  document.addEventListener('keydown', e => {
    const ctrl = e.ctrlKey || e.metaKey;
    if (ctrl && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); closeMenu(); openPalette(); return; }
    if (e.altKey && /^[1-9]$/.test(e.key)) { e.preventDefault(); nthTab(+e.key - 1); return; }
    if (e.altKey && (e.key === 'w' || e.key === 'W' || e.code === 'KeyW')) { e.preventDefault(); const v = document.querySelector('.tab[aria-selected="true"]'); if (v) closeTab(v.id.slice(4)); return; }
    if (paletteOpen() || typing(e) || ctrl || e.altKey || document.querySelector('.dialog, .palette')) return;
    const v = activeView();
    switch (e.key) {
      case '/': e.preventDefault(); if (v && v.focusFilter) v.focusFilter(); break;
      case '?': e.preventDefault(); helpDialog(); break;
      case 't': e.preventDefault(); document.getElementById('proc-filter').focus(); break;
      case 'T': e.preventDefault(); applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light'); break;
      case 'o': case 'O': e.preventDefault(); activate('overview'); break;
      case 'm': case 'M': e.preventDefault(); memoryPrompt(); break;
      case '[': e.preventDefault(); cycleTab(-1); break;
      case ']': e.preventDefault(); cycleTab(1); break;
      case 'Escape': if (v && v.panel && v.panel.drawer) { v.panel.closeDrawer(); } break;
      default: return;
    }
  });
}

/** No (valid) token: ask for it. The token is printed by `vol serve` (in the URL it prints). */
function lockScreen(wrong) {
  const inp = el('input.input', { type: 'password', autocomplete: 'off', spellcheck: false, placeholder: 'access token', 'aria-label': 'Access token' });
  const go = () => { if (inp.value.trim()) { setToken(inp.value.trim()); location.reload(); } };
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  const box = el('div.dialog.login-box', { 'aria-label': 'Access token needed' },
    el('div.card-h', {}, el('h3', { text: 'rsvol · locked' })),
    el('div.card-b.openbox', {},
      el('p.prose.flush', { text: 'This server gives access to a memory image. Open the URL printed by vol serve (it carries the token), or paste the token here.' }),
      wrong ? el('p.bad', { role: 'alert', text: 'The saved token is not valid for this server (it changes every time vol serve starts).' }) : null,
      el('div.row', {}, inp, el('button.btn.primary', { type: 'button', text: 'Unlock', on: { click: go } }))));
  document.body.append(el('div.scrim'), box);
  inp.focus();
}

/** Deep links: #proc/4, #run/12, #plugin/windows.pslist.PsList, #hex/kernel/0xfffff800..., #palette/malfind, #compare/3/5, #help. */
async function route() {
  const h = decodeURIComponent(location.hash.slice(1));
  if (!h || h.startsWith('token=')) return;
  const [kind, ...rest] = h.split('/');
  try {
    if (kind === 'proc' && rest[0]) emit('nav', { kind: 'proc', pid: +rest[0] });
    else if (kind === 'run' && rest[0]) emit('nav', { kind: 'run', id: +rest[0] });
    else if (kind === 'plugin' && rest[0]) {
      const [name, qs] = rest.join('/').split('?');
      const args = Object.fromEntries(new URLSearchParams(qs || ''));
      const { runPlugin } = await import('./core.js');
      const run = await runPlugin(name, args, { reuse: true });
      emit('nav', { kind: 'run', id: run.id });
    } else if (kind === 'hex' && rest.length >= 2) emit('nav', { kind: 'hex', layer: rest[0], addr: rest[1] });
    else if (kind === 'palette') openPalette({ query: rest.join('/') });
    else if (kind === 'compare') emit('nav', { kind: 'compare', a: +rest[0] || null, b: +rest[1] || null });
    else if (kind === 'help') helpDialog();
    else if (kind === 'overview') activate('overview');
  } catch (e) { toast(e.message, 'bad'); }
}

async function main() {
  document.getElementById('theme').addEventListener('click', () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light'));
  document.getElementById('help').addEventListener('click', helpDialog);
  document.getElementById('cmdk').addEventListener('click', () => openPalette());
  document.getElementById('evidence').addEventListener('click', () => openImageDialog());
  document.getElementById('compare-btn').addEventListener('click', () => openCompare(null, null));
  railResize();
  shortcuts();
  initTree();
  if (!TOKEN) { lockScreen(false); return; }
  try {
    const [plugins, session, runs] = await Promise.all([api('plugins'), api('session'), api('runs')]);
    store.plugins = plugins;
    store.pluginMap = new Map(plugins.map(p => [p.name, p]));
    store.session = session;
    for (const r of runs) store.runs.set(r.id, r);
  } catch (e) {
    if (e.status === 401) { lockScreen(true); return; }
    document.getElementById('panes').append(el('div.empty-state', {}, el('h2', { text: 'Can\'t reach the rsvol server' }), e.message));
    return;
  }
  renderTopbar();
  openTab('overview', () => new Overview(), { focus: false });
  renderRunList();
  let sessionId = store.session.id;
  let restored = false;
  const onReady = () => {
    const s = store.session;
    if (s.state === 'ready') {
      loadProcs().then(() => { if (!restored) { restored = true; restoreTabs(); } });
    } else if (s.state === 'failed' || s.state === 'idle') {
      document.getElementById('tree').replaceChildren(el('div.tree-empty', { text: s.state === 'idle' ? 'Open a memory image to see its processes.' : 'The kernel could not be identified, so there is no process list.' }));
    }
  };
  on('session', ({ prev, cur }) => {
    if (cur.id !== sessionId) {
      sessionId = cur.id;
      closeSessionTabs();
      resetTree();
      restored = false;
      activate('overview');
    }
    renderTopbar();
    onReady();
    renderRunList();
  });
  on('runs', () => { renderRunList(); refreshTabs(); });
  on('procs', () => renderTopbar());
  onReady();
  startEvents();
  addEventListener('hashchange', route);
  if (location.hash) {
    // wait for the process list so process views have their data
    if (store.session.state === 'ready') await loadProcs().catch(() => {});
    route();
  }
  document.getElementById('main').focus();
}

main();
