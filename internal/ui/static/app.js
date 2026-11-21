'use strict';
// afw interface. No framework, no build step, nothing loaded from elsewhere.
// Much of what is shown here was written by attackers (addresses, probe
// contents, an adviser's words), so the page only ever sets text. There is
// no innerHTML anywhere in this file, and it must stay that way.

const $ = id => document.getElementById(id);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(3)) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

// ---- pictures --------------------------------------------------------------
// Fixed shapes drawn as SVG nodes. Each attack type keeps one picture
// everywhere, so it is recognised before it is read.
const SVG = 'http://www.w3.org/2000/svg';
const ICONS = {
  shield: ['M12 3l8 3v6c0 4.6-3.3 8.4-8 9-4.7-.6-8-4.4-8-9V6z'], check: ['M5 13l4 4L19 7'],
  alert: ['M12 4l9 16H3z', 'M12 10v4', 'M12 17v.5'], ban: ['c12,12,9', 'M5.7 5.7l12.6 12.6'],
  slow: ['M4 17a8 8 0 1 1 16 0', 'M12 17l-3.5-5'], eye: ['M2 12s4-6.5 10-6.5S22 12 22 12s-4 6.5-10 6.5S2 12 2 12z', 'c12,12,2.5'],
  scan: ['c12,12,9', 'c12,12,4', 'M12 12l6.4-6.4'], key: ['c8,15,4', 'M11 12l8-8', 'M16 7l3 3', 'M14 9l2 2'],
  flood: ['M3 8c3-3 6 3 9 0s6 3 9 0', 'M3 13c3-3 6 3 9 0s6 3 9 0', 'M3 18c3-3 6 3 9 0s6 3 9 0'],
  decoy: ['c12,12,9', 'c12,12,5', 'c12,12,1'],
  chain: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2'],
  home: ['M4 11l8-7 8 7v9h-5v-6H9v6H4z'], flag: ['M5 21V4h12l-2.5 4L17 12H5'], bolt: ['M13 3L5 14h6l-1 7 8-11h-6z'],
  pulse: ['M3 12h4l2-6 4 12 2-6h6'], grid: ['M4 4h7v7H4z', 'M13 4h7v7h-7z', 'M4 13h7v7H4z', 'M13 13h7v7h-7z'],
  gear: ['c12,12,3', 'M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1'],
  x: ['M6 6l12 12', 'M18 6L6 18'], right: ['M5 12h14', 'M13 6l6 6-6 6'], clock: ['c12,12,9', 'M12 7v5l3 2'],
  bot: ['M6 9h12v9H6z', 'M12 9V5', 'c12,4,1', 'M9.5 13v1.5', 'M14.5 13v1.5'], data: ['M12 3v12', 'M7 10l5 5 5-5', 'M4 20h16'],
  user: ['c12,8,4', 'M4 21c0-4 4-6 8-6s8 2 8 6'], q: ['c12,12,9', 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7', 'M12 17v.5'],
};
function icon(name) {
  const s = document.createElementNS(SVG, 'svg');
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', 'ic'); s.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name] || ICONS.q) {
    const c = d[0] === 'c' ? d.slice(1).split(',') : null;
    const n = document.createElementNS(SVG, c ? 'circle' : 'path');
    if (c) { n.setAttribute('cx', c[0]); n.setAttribute('cy', c[1]); n.setAttribute('r', c[2]); } else n.setAttribute('d', d);
    s.append(n);
  }
  return s;
}
const dot = (name, tone, extra) => h('span', { class: 'dot t-' + tone + (extra ? ' ' + extra : '') }, icon(name));

// ---- words -----------------------------------------------------------------
const CLASS = {
  'access.bruteforce': 'Password guessing', 'access.exploit': 'Attack hidden in one request', 'access.phishing': 'Phishing or a bad download',
  'recon.scan.vertical': 'Port scan', 'recon.scan.horizontal': 'Scan across devices', 'recon.scan.slow': 'Slow port scan',
  'recon.decoy': 'Touched a decoy', 'recon.fingerprint': 'Probing what software runs',
  'dos.syn-flood': 'Flood of unfinished connections', 'dos.connection-flood': 'Flood of connections', 'dos.flood': 'Flood hurting the service',
  'dos.table-exhaustion': 'Connection table filled up', 'dos.volumetric': 'Very large flood', 'dos.slow-application': 'Slow drip attack on a service',
  'infra.known-bad': 'Known-bad address', 'c2.known-bad': 'Device contacting a known-bad address', 'c2.beacon': 'Malware checking in',
  'c2.dns-tunnel': 'Data hidden in DNS lookups', 'lateral.scan': 'Inside device scanning', 'lateral.bruteforce': 'Inside device guessing passwords',
  'lateral.decoy': 'Inside device touched a decoy', 'lateral.link-spoof': 'Impersonating a device on the local network', 'lateral.chain': 'Inside device: break-in chain',
  'exfil.volume': 'Large upload to a new place', 'exfil.covert': 'Slow hidden data theft', 'impact.ransomware-spread': 'Ransomware spreading',
  'defence.manipulation': 'Attempt to misuse the firewall', 'peer.reported': 'Reported by another afw', 'chain': 'Break-in chain', 'unknown': 'Unusual behaviour',
};
const SHORT = { 'access.bruteforce': 'Password guessing', 'recon.scan.vertical': 'Port scan', 'recon.scan.horizontal': 'Device scan', 'recon.scan.slow': 'Slow scan',
  'recon.decoy': 'Decoy touched', 'dos.syn-flood': 'Flood', 'dos.connection-flood': 'Flood', 'dos.flood': 'Flood', 'infra.known-bad': 'Known-bad address', 'peer.reported': 'Reported by a peer' };
const STAGE = { recon: ['scan', 'Scanned'], access: ['key', 'Guessed passwords'], decoy: ['decoy', 'Hit a decoy'], c2: ['flag', 'Called a bad address'] };
function className(c) {
  if (!c) return '';
  let many = '';
  if (c.endsWith('.distributed')) { c = c.slice(0, -12); many = ', from many addresses'; }
  const m = c.match(/^(lateral\.)?chain\.(.+)$/);
  if (m) return (m[1] ? 'Inside device: break-in chain: ' : 'Break-in chain: ') + m[2].split('-').map(s => (STAGE[s] || [0, s])[1].toLowerCase()).join(', then ') + many;
  if (CLASS[c]) return CLASS[c] + many;
  let inside = '';
  if (c.startsWith('lateral.')) { inside = 'Inside device: '; c = c.slice(8); }
  for (let k = c; k; k = k.includes('.') ? k.slice(0, k.lastIndexOf('.')) : '') {
    const hit = CLASS[k] || CLASS['recon.' + k] || CLASS['access.' + k];
    if (hit) return inside + (inside ? hit.charAt(0).toLowerCase() + hit.slice(1) : hit) + many;
  }
  return inside + c + many;
}
function shortName(c) {
  if (!c) return 'Suspicious';
  const base = c.replace(/\.distributed$/, '');
  if (/^(lateral\.)?chain/.test(base)) return base.startsWith('lateral') ? 'Inside device: break-in' : 'Break-in attempt';
  if (base.startsWith('lateral.')) return 'Inside device';
  if (base.startsWith('c2.')) return 'Bad address contacted';
  return SHORT[base] || className(base);
}
function classIcon(c) {
  c = c || '';
  if (c.startsWith('lateral.')) return 'home';
  if (c.startsWith('c2.')) return 'flag';
  if (c.includes('chain')) return 'chain';
  if (c.includes('bruteforce')) return 'key';
  if (c.includes('decoy')) return 'decoy';
  if (c.startsWith('dos.')) return 'flood';
  if (c.startsWith('recon.')) return 'scan';
  if (c.includes('known-bad')) return 'flag';
  if (c.startsWith('exfil.')) return 'data';
  if (c.startsWith('defence.')) return 'shield';
  if (c.startsWith('peer.')) return 'user';
  return 'alert';
}
const ACT = { drop: ['ban', 'Blocked', 'Would block'], throttle: ['slow', 'Slowed', 'Would slow'], observe: ['eye', 'Watching', 'Watching'], allow: ['check', 'Unblocked', 'Unblocked'] };
const isWould = (action, mode) => mode === 'shadow' && (action === 'drop' || action === 'throttle');
const actWord = (action, mode) => (ACT[action] || [0, action, action])[isWould(action, mode) ? 2 : 1];
const actionTag = (action, mode) => h('span', { class: 'tag t-' + action + (isWould(action, mode) ? ' would' : '') }, icon((ACT[action] || ['q'])[0]), actWord(action, mode));
const PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'Mail', 53: 'DNS', 80: 'Web', 443: 'Web', 445: 'File sharing', 2323: 'Telnet', 3306: 'MySQL', 3389: 'Remote desktop', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'Web', 8443: 'Web', 9200: 'Elasticsearch' };
function assetLabel(a) {
  let m = a.match(/^(.*) \(outbound\)$/);
  if (m) return ['Outgoing', m[1]];
  m = a.match(/^(.*)\/(\d+)\/(tcp|udp)$/);
  if (m) return [(PORTS[m[2]] ? PORTS[m[2]] + ' ' : '') + 'port ' + m[2], m[1]];
  return [a, ''];
}
const cap = t => t ? t.charAt(0).toUpperCase() + t.slice(1) : '';
const num = n => Number(n || 0).toLocaleString('en-GB');
const plural = (n, one, many) => num(n) + ' ' + (n === 1 ? one : many);
const clock = d => d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
const dayStart = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
function dayName(ts) {
  const d = new Date(ts), diff = Math.round((dayStart(new Date()) - dayStart(d)) / 864e5);
  return diff === 0 ? 'Today' : diff === 1 ? 'Yesterday' : d.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'short' });
}
function when(ts) { const d = new Date(ts); if (isNaN(d) || d.getFullYear() < 2000) return ''; const n = dayName(ts); return n === 'Today' ? clock(d) : n + ' ' + clock(d); }
function span(ms) {
  const m = Math.max(0, Math.round(ms / 60000));
  if (m < 1) return 'under 1 min';
  if (m < 60) return m + ' min';
  const hrs = Math.floor(m / 60), rest = m % 60;
  if (hrs < 24) return hrs + ' h' + (rest ? ' ' + rest + ' min' : '');
  return Math.floor(hrs / 24) + ' d ' + (hrs % 24) + ' h';
}
function ttlWords(ttl) { const m = /^([0-9.]+)(ms|s|m|h|d)$/.exec(ttl || ''); return m ? span(parseFloat(m[1]) * { ms: 1, s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2]]) : ttl; }
const tidy = t => (t || '').replace(/^\[[^\]]*\]\s*/, '');

// ---- state -----------------------------------------------------------------
const VIEWS = [['now', 'Now', 'shield'], ['activity', 'Activity', 'pulse'], ['coverage', 'Coverage', 'grid'], ['system', 'System', 'gear']];
const S = { st: null, okAt: 0, failing: false, stopped: false, view: '', act: { items: [], more: false, show: '', q: '', pages: 1 }, cov: null, sys: null, armed: null, flash: null, painted: {}, cell: null };
let token = sessionStorage.getItem('afw-t');
let opener = null;

(function takeLink() {
  const m = location.hash.match(/[#&]t=([0-9a-f]{32,})/);
  if (!m) return;
  token = m[1];
  sessionStorage.setItem('afw-t', token);
  const go = (location.hash.match(/[#&]go=([^&]+)/) || [])[1];
  history.replaceState(null, '', '#/' + (go ? decodeURIComponent(go) : 'now')); // the token never stays in the address bar
})();
function route() {
  const [path, qs] = location.hash.replace(/^#\/?/, '').split('?');
  return { view: VIEWS.some(v => v[0] === path) ? path : 'now', params: new URLSearchParams(qs || '') };
}
async function api(path, body) {
  const r = await fetch(path, { method: body ? 'POST' : 'GET', headers: Object.assign({ Authorization: 'Bearer ' + token }, body ? { 'Content-Type': 'application/json' } : {}), body: body ? JSON.stringify(body) : undefined, cache: 'no-store' });
  if (r.status === 401) { token = null; sessionStorage.removeItem('afw-t'); gate(); throw new Error('token'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'afw refused that (' + r.status + ')');
  return data;
}
// paint replaces a container only when what it shows has changed, and puts
// keyboard focus back where it was, so a refresh never interrupts anyone.
function paint(el, key, build) {
  if (!el || S.painted[el.id] === key) return;
  S.painted[el.id] = key;
  const open = [...el.querySelectorAll('details[open][data-k]')].map(d => d.getAttribute('data-k'));
  const k = document.activeElement && el.contains(document.activeElement) ? document.activeElement.getAttribute('data-k') : null;
  el.replaceChildren(...[build()].flat(3).filter(x => x != null && x !== false));
  for (const id of open) { const d = el.querySelector('details[data-k="' + CSS.escape(id) + '"]'); if (d) d.open = true; }
  if (k) { const again = el.querySelector('[data-k="' + CSS.escape(k) + '"]'); if (again) again.focus(); }
}
const repaint = () => { S.painted = {}; render(); const s = route().params.get('s'); if (s) showSource(s); };
// A risky action takes two presses, in place. No pop-up dialogs.
function twoStep(key, label, confirmLabel, run, cls) {
  if (S.armed !== key) return h('button', { 'data-k': key, class: cls || '', onclick: () => { S.armed = key; repaint(); } }, label);
  return [h('button', { 'data-k': key, class: (cls || '').replace('quiet', '') + ' primary', onclick: run }, confirmLabel),
    h('button', { 'data-k': key + ':no', class: (cls || '').includes('small') ? 'small' : '', onclick: () => { S.armed = null; repaint(); } }, 'Cancel')];
}
async function act(body, done) {
  try { await api('/api/do', body); S.flash = done || null; if (body.action === 'panic') S.stopped = true; }
  catch (e) { if (e.message !== 'token') S.flash = 'That did not work: ' + e.message; }
  S.armed = null;
  await tick(true);
}
const empty = (ic, tone, text, ...way) => h('div', { class: 'empty' }, dot(ic, tone), h('p', {}, text), way);
const addrChip = addr => h('button', { class: 'addr', 'data-k': 'src:' + addr, onclick: e => openSource(addr, e.currentTarget) }, addr);
const details = (key, label, ...body) => h('details', { 'data-k': key }, h('summary', {}, label), body);

// ---- frame -----------------------------------------------------------------
function chrome() {
  const st = S.st, r = route();
  $('node').textContent = st ? ' ' + st.node : '';
  const pill = $('status');
  if (st) {
    const emergency = st.posture === 'breakglass';
    pill.textContent = emergency ? 'Emergency' : st.mode === 'enforce' ? 'Blocking' : 'Watch-only';
    pill.className = 'pill t-' + (emergency ? 'bad' : st.mode === 'enforce' ? 'ok' : 'idle');
  }
  const fresh = $('fresh'), age = Math.round((Date.now() - S.okAt) / 1000);
  fresh.className = 'dim fresh' + (S.failing || S.stopped ? ' stale' : '');
  fresh.textContent = S.stopped ? 'afw has stopped' : S.failing ? "Can't reach afw" : !S.okAt ? '' : age < 8 ? 'Live' : age + ' s ago';
  const urgent = st ? st.attention.length : 0;
  paint($('nav'), r.view + urgent, () => VIEWS.map(([id, name, ic]) =>
    h('a', { href: '#/' + id, 'aria-current': id === r.view ? 'page' : null }, icon(ic), name,
      id === 'now' && urgent ? h('span', { class: 'count', 'aria-label': urgent + ' need you' }, urgent) : null)));
}
function gate() {
  $('nav').hidden = true;
  $('main').replaceChildren(empty('key', 'idle', 'This page needs its access link.',
    h('p', { class: 'dim' }, 'On the machine running afw, run ', h('code', { class: 'mono' }, 'sudo afw ui'), ' and open the address it prints.')));
}

// ---- Now -------------------------------------------------------------------
function chainSteps(cls, tone) {
  const m = (cls || '').match(/chain\.(.+?)(\.distributed)?$/);
  if (!m) return null;
  const parts = m[1].split('-');
  return h('div', { class: 'steps', role: 'img', 'aria-label': className(cls) },
    parts.map((p, i) => [i ? h('span', { class: 'arrow' }, icon('right')) : null,
      h('span', { class: 'step' }, h('span', { class: 'dot sm t-' + tone }, icon((STAGE[p] || ['q'])[0])), (STAGE[p] || [0, p])[1])]));
}
function needCard(a, i, ro) {
  let ic = 'alert', title = a.title, gist = '', acts = [], extra = [];
  const key = 'need:' + (a.do || a.title) + ':' + (a.subject || i);
  if (a.do === 'confirm') {
    ic = 'key'; title = 'Can you still get in?'; gist = tidy(a.detail).replace(/^Blocking was switched on recently\. /, '').replace(/, in case.*$/, '.');
    gist = cap(gist.replace(/^It switches itself off/, 'Blocking turns itself off'));
    if (!ro) acts.push(h('button', { class: 'primary', 'data-k': 'confirm', onclick: () => act({ action: 'confirm' }, 'Confirmed. Blocking stays on.') }, 'Yes, keep blocking'));
  } else if (a.do === 'breakglass-off') {
    ic = 'bolt'; title = 'Emergency mode is on'; gist = 'Known users first. Everyone else is limited.';
    if (!ro) acts.push(twoStep('bg:off', 'Turn off', 'Yes, turn off', () => act({ action: 'breakglass', value: 'off' }, 'Emergency mode is off. It returns by itself if the flood is still hurting.')));
    extra.push(details(key, 'Why it came on', h('p', {}, a.detail)));
  } else if (a.do === 'adviser-resume') {
    ic = 'bot'; title = 'AI adviser suspended'; gist = 'It gave answers an honest one would not.';
    if (!ro) acts.push(twoStep('adv', 'Resume', 'Yes, resume', () => act({ action: 'adviser-resume' }, 'The adviser was resumed.')));
    extra.push(details(key, 'What happened', h('p', {}, a.detail)));
  } else if (a.do === 'open-system') {
    ic = 'gear'; gist = ''; acts.push(h('a', { href: '#/system' }, 'Open System'));
    extra.push(details(key, 'Details', h('p', {}, a.detail)));
  } else {
    const cls = a.title;
    ic = classIcon(cls); title = shortName(cls);
    if (cls.startsWith('lateral.') || cls.startsWith('c2.')) { title = 'A device inside is misbehaving'; gist = 'It acts like an attacker. afw is watching it, not blocking it.'; }
    else if (!cls.includes('chain')) gist = className(cls) + '.';
    const srcs = (a.sources || []).filter(s => s !== '0.0.0.0/0');
    extra.push(chainSteps(cls, a.level));
    if (srcs.length) extra.push(h('div', { class: 'row' }, srcs.slice(0, 5).map(addrChip), srcs.length > 5 ? h('span', { class: 'dim' }, '+' + (srcs.length - 5)) : null, a.since ? h('span', { class: 'dim' }, 'since ' + when(a.since)) : null));
    extra.push(details(key, 'What afw is asking', h('p', {}, tidy(a.detail))));
  }
  return h('div', { class: 'need t-' + a.level }, dot(ic, a.level), h('h3', {}, title), acts.length ? h('div', { class: 'acts' }, acts) : null,
    gist ? h('p', { class: 'gist' }, gist) : null, h('div', { class: 'extra' }, extra));
}
function countdown(since, until, tone) {
  const end = new Date(until) - 0, start = new Date(since) - 0, now = Date.now();
  const total = start > 0 && end > start ? end - start : 0, left = Math.max(0, end - now);
  const pct = total ? Math.max(3, Math.min(100, 100 * left / total)) : 100;
  const fill = h('i'); fill.style.width = pct + '%';
  return [h('div', { class: 'track t-' + tone, role: 'img', 'aria-label': span(left) + ' left' }, fill), left];
}
function viewNow() {
  const st = S.st;
  if (!st) return h('p', { class: 'loading' }, 'afw is loading.');
  const out = [], ro = st.read_only, would = st.mode !== 'enforce';
  if (S.flash) out.push(h('div', { class: 'banner', role: 'status' }, S.flash));
  const urgent = st.attention.filter(a => a.level === 'act').length;
  const blocked = st.restricted.filter(r => r.action === 'drop').length, slowed = st.restricted.length - blocked;

  let tone = 'ok', ic = 'check', word = 'All clear', sub = 'Blocking is on', btn = null, live = false;
  if (st.posture === 'breakglass') { tone = 'bad'; ic = 'bolt'; word = 'Under attack'; sub = 'Emergency mode: known users first'; live = true; }
  else if (st.attention.length) { const n = st.attention.length; tone = urgent ? 'bad' : 'warn'; ic = 'alert'; word = n + (n === 1 ? ' thing needs you' : ' things need you'); sub = would ? 'Watch-only: nothing is being blocked' : 'Blocking is on'; live = urgent > 0; }
  else if (would) { tone = 'idle'; ic = 'eye'; word = 'Watching only'; sub = 'Nothing is being blocked'; }
  if (would && !ro) btn = twoStep('mode:enforce', 'Start blocking', 'Yes, start', () => act({ action: 'mode', value: 'enforce' }, 'Blocking is on.'), 'primary');
  out.push(h('section', { class: 'hero t-' + tone + (live ? ' live' : '') }, h('div', { class: 'ring' }, icon(ic)),
    h('div', {}, h('div', { class: 'word' }, word), h('div', { class: 'sub' }, sub)), btn ? h('div', { class: 'do' }, btn) : null));

  const tile = (n, label, tone2, ic2, href) => h('a', { class: 'tile t-' + tone2 + (n ? '' : ' zero'), href }, dot(ic2, n ? tone2 : 'idle'),
    h('div', {}, h('div', { class: 'num' }, num(n)), h('div', { class: 'lab' }, label)));
  out.push(h('section', { class: 'tiles', 'aria-label': 'Right now' },
    tile(blocked, would ? 'would block' : 'blocked now', 'drop', 'ban', '#/activity?show=drop'),
    tile(slowed, would ? 'would slow' : 'slowed now', 'throttle', 'slow', '#/activity?show=throttle'),
    tile(st.watching, 'being watched', 'observe', 'eye', '#/activity?show=observe')));

  const p = st.pulse, tot = p.blocked.map((b, i) => b + p.slowed[i] + p.watched[i]), peak = Math.max(1, ...tot), sum = tot.reduce((a, b) => a + b, 0);
  out.push(h('section', { class: 'pulse' },
    h('div', { class: 'head' }, h('span', {}, 'Last hour'), h('span', {}, sum ? plural(sum, 'decision', 'decisions') : 'quiet')),
    h('div', { class: 'bars', role: 'img', 'aria-label': 'Decisions per minute over the last hour: ' + sum + ' in total' }, tot.map((t, i) => {
      const bar = h('i', { class: p.blocked[i] ? 'b' : p.slowed[i] ? 's' : t ? 'w' : '', title: t ? (59 - i) + ' min ago: ' + [p.blocked[i] && p.blocked[i] + ' blocked', p.slowed[i] && p.slowed[i] + ' slowed', p.watched[i] && p.watched[i] + ' watched'].filter(Boolean).join(', ') : null });
      bar.style.height = (t ? 18 + 82 * Math.sqrt(t / peak) : 5) + '%';
      return bar;
    })),
    h('div', { class: 'axis' }, h('span', {}, '60 min ago'), h('span', {}, 'now'))));

  if (st.attention.length) {
    out.push(h('h2', {}, 'Needs you', h('span', { class: 'n' }, st.attention.length)));
    st.attention.forEach((a, i) => out.push(needCard(a, i, ro)));
  }
  if (st.handled) out.push(h('p', { class: 'dim' }, plural(st.handled, 'more incident', 'more incidents') + ' handled by afw. ', h('a', { href: '#/activity?show=review' }, 'Review')));

  out.push(h('h2', {}, would ? 'Would be restricted' : 'Restricted now', st.restricted.length ? h('span', { class: 'n' }, st.restricted.length) : null));
  if (!st.restricted.length) out.push(empty('check', 'ok', 'Nothing is restricted.'));
  else out.push(h('div', { class: 'rgrid' }, st.restricted.map(r => {
    const [bar, left] = countdown(r.since, r.until, r.action);
    return h('div', { class: 'rc t-' + r.action },
      h('button', { class: 'rc-main', 'data-k': 'src:' + r.subject, 'aria-label': r.subject + ', ' + actWord(r.action, st.mode) + ', ' + shortName(r.class), onclick: e => openSource(r.subject, e.currentTarget) },
        dot(classIcon(r.class), r.action, would ? 'would' : ''), h('span', {}, h('span', { class: 'who' }, r.subject), h('span', { class: 'what' }, shortName(r.class)))),
      bar,
      h('div', { class: 'rc-foot' }, h('span', {}, h('b', {}, actWord(r.action, st.mode)), ' · ' + span(left) + ' left'),
        ro || would ? null : h('span', { class: 'row' }, twoStep('unblock:' + r.subject, 'Unblock', 'Unblock 1 h', () => act({ action: 'unblock', subject: r.subject }, r.subject + ' unblocked for an hour.'), 'small'))));
  })));
  return out;
}

// ---- Activity --------------------------------------------------------------
const SHOW = [['', 'All', ''], ['drop', 'Blocked', 'drop'], ['throttle', 'Slowed', 'throttle'], ['observe', 'Watching', 'observe'], ['review', 'To review', 'check']];
function shellActivity() {
  let timer;
  const a = S.act, want = route().params.get('show');
  if (want != null && SHOW.some(x => x[0] === want)) { a.show = want; a.pages = 1; }
  return [h('div', { class: 'chips' }, h('span', { class: 'group', id: 'filters', role: 'group', 'aria-label': 'Show' }),
    h('input', { type: 'search', id: 'find', 'aria-label': 'Find an address', placeholder: 'Find an address', value: a.q,
      oninput: e => { clearTimeout(timer); const v = e.target.value.trim(); timer = setTimeout(() => { a.q = v; a.pages = 1; loadActivity(); }, 300); } })),
  h('div', { id: 'act' })];
}
async function loadActivity(older) {
  const a = S.act, p = new URLSearchParams({ show: a.show, q: a.q });
  if (older && a.items.length) p.set('before', a.items[a.items.length - 1].ts);
  try { const r = await api('/api/activity?' + p); a.items = older ? a.items.concat(r.items) : r.items; a.more = r.more; if (older) a.pages++; } catch (e) { /* the header says afw is unreachable */ }
  render();
}
// One attacker usually climbs a ladder: watched, then slowed, then blocked.
// The list shows where each one ended up; the steps are in its history.
function steps(items) {
  const out = [];
  for (const d of items) {
    const last = out[out.length - 1];
    if (last && last.d.subject === d.subject && new Date(last.d.ts) - new Date(d.ts) < 15 * 60000) last.review = last.review || d.escalated;
    else out.push({ d, review: d.escalated });
  }
  return out;
}
function ladder(action) {
  const lvl = { observe: 1, throttle: 2, drop: 3 }[action] || 0;
  return h('span', { class: 'ladder', role: 'img', 'aria-label': 'level ' + lvl + ' of 3' }, ['w', 's', 'b'].map((c, i) => h('i', { class: i < lvl ? 'on ' + (lvl === 3 ? 'b' : lvl === 2 ? 's' : 'w') : '' })));
}
function viewActivity() {
  const a = S.act, mode = S.st ? S.st.mode : 'enforce';
  paint($('filters'), a.show, () => SHOW.map(([id, name, tone]) => h('button', { class: 'fchip' + (id ? ' t-' + tone : ' all'), 'aria-pressed': String(a.show === id), 'data-k': 'show:' + id, onclick: () => { a.show = id; a.pages = 1; loadActivity(); } }, name)));
  paint($('act'), JSON.stringify([a.items.length, a.items[0], a.items[a.items.length - 1], a.more, a.pages, mode]), () => {
    if (!a.items.length) return a.q || a.show
      ? empty('q', 'idle', 'Nothing matches.', h('button', { onclick: () => { a.q = ''; a.show = ''; $('find').value = ''; loadActivity(); } }, 'Clear filters'))
      : empty('check', 'ok', 'No decisions yet.', h('p', { class: 'dim' }, 'They appear the moment something suspicious happens.'));
    const out = [a.pages > 1 ? h('p', { class: 'dim' }, 'Showing older decisions. ', h('button', { class: 'quiet', onclick: () => { a.pages = 1; loadActivity(); } }, 'Back to latest')) : null];
    let day = null, list = null;
    for (const { d, review } of steps(a.items)) {
      const name = dayName(d.ts);
      if (name !== day) { day = name; out.push(h('div', { class: 'day' }, name)); list = h('ul', { class: 'tl' }); out.push(list); }
      const w = isWould(d.action, d.mode);
      list.append(h('li', {}, h('button', { class: 'ev', 'data-k': 'dec:' + d.id, 'aria-label': clock(new Date(d.ts)) + ', ' + d.subject + ', ' + actWord(d.action, d.mode) + ', ' + shortName(d.class), onclick: e => openSource(d.subject, e.currentTarget) },
        h('span', { class: 'time' }, clock(new Date(d.ts))),
        dot(classIcon(d.class), d.action, w ? 'would' : ''),
        h('span', {}, h('span', { class: 'who' }, d.subject), h('span', { class: 'what' }, h('b', { class: 't-' + d.action + ' txt' }, actWord(d.action, d.mode)), ' · ' + shortName(d.class))),
        h('span', { class: 'side' }, review ? h('span', { class: 'flagme', title: 'afw was not fully sure: worth a second look' }, icon('q')) : null,
          d.action !== 'allow' && d.action !== 'observe' && d.ttl ? h('span', { class: 'ttl' }, ttlWords(d.ttl)) : null, ladder(d.action)))));
    }
    if (a.more) out.push(h('div', { class: 'row' }, h('button', { 'data-k': 'older', onclick: () => loadActivity(true) }, 'Show older')));
    return out;
  });
}

// ---- Coverage --------------------------------------------------------------
function viewCoverage() {
  const c = S.cov;
  if (!c) return h('p', { class: 'loading' }, 'Loading coverage.');
  const fams = [];
  for (const row of c.attack_universe) { let f = fams.find(x => x.name === row.family); if (!f) fams.push(f = { name: row.family, rows: [] }); f.rows.push(row); }
  const tone = r => r.see === 'no' || r.act === 'no' ? 'no' : r.see === 'yes' && r.act === 'yes' ? 'yes' : 'partial';
  const all = c.attack_universe, gaps = all.filter(r => tone(r) === 'no').length, part = all.filter(r => tone(r) === 'partial').length;
  const pick = all.find(r => r.class === S.cell);
  const WORD = { yes: 'afw sees and stops this.', partial: 'afw handles this only partly.', no: 'afw cannot stop this on its own.' };
  const max = Math.max(1, ...c.assets.map(a => a.flows_last_hour));
  const hit = a => Object.keys(a.classes || {}).length ? 1 : 0;
  const ranked = c.assets.filter(a => a.flows_last_hour || hit(a)).sort((x, y) => hit(y) - hit(x) || y.flows_last_hour - x.flows_last_hour);
  const assets = ranked.slice(0, S.allAssets ? 500 : 6);
  return [
    h('h2', {}, 'Attack map'),
    h('div', { class: 'card' },
      fams.map(f => h('div', { class: 'fam' }, h('div', { class: 'name' }, cap(f.name)), h('div', { class: 'cells' }, f.rows.map(r =>
        h('button', { class: 'cell t-' + tone(r) + (r.seen ? ' seen' : ''), 'aria-pressed': String(S.cell === r.class), 'data-k': 'cell:' + r.class, title: className(r.class),
          'aria-label': className(r.class) + '. ' + WORD[tone(r)] + (r.seen ? ' Seen here ' + r.seen + ' times.' : ''), onclick: () => { S.cell = S.cell === r.class ? null : r.class; repaint(); } },
        icon(classIcon(r.class)), r.seen ? h('span', { class: 'badge' }, r.seen > 99 ? '99+' : r.seen) : null))))),
      h('div', { class: 'legend' }, h('span', { class: 't-yes' }, h('i'), 'handled'), h('span', { class: 't-partial' }, h('i'), plural(part, 'partly', 'partly')), h('span', { class: 't-no' }, h('i'), plural(gaps, 'gap', 'gaps')), h('span', {}, 'number = times seen here')),
      pick ? h('div', { class: 'picked t-' + tone(pick) }, dot(classIcon(pick.class), tone(pick)), h('div', {}, h('h3', {}, className(pick.class)),
        h('p', { class: 'sec' }, WORD[tone(pick)] + ' ' + (pick.seen ? 'Seen here ' + plural(pick.seen, 'time', 'times') + '.' : pick.see === 'no' ? 'afw could not tell if it happened here.' : 'Not seen here yet.'))))
        : h('p', { class: 'dim picked' }, 'Tap a square to see what it is.')),

    h('h2', {}, 'Most targeted'),
    !assets.length ? empty('check', 'ok', 'Nothing has been targeted yet.') : h('div', { class: 'card' }, assets.map(a => {
      const [name, where] = assetLabel(a.asset), kinds = Object.keys(a.classes || {});
      const fill = h('i'); fill.style.width = Math.max(2, 100 * a.flows_last_hour / max) + '%';
      return h('div', { class: 'hbar t-' + (kinds.length ? 'drop' : 'observe') },
        h('div', { class: 'lab' }, name, h('small', {}, [where, kinds.length ? kinds.map(shortName).filter((v, i, x) => x.indexOf(v) === i).join(', ') : 'no attacks'].filter(Boolean).join(' · '))),
        h('div', { class: 'track', role: 'img', 'aria-label': a.flows_last_hour + ' connections in the last hour' }, fill), h('div', { class: 'n' }, num(a.flows_last_hour)));
    }), h('p', { class: 'dim' }, 'Connections in the last hour. Red means attacks were seen there.'),
    ranked.length > assets.length && !S.allAssets ? h('button', { class: 'quiet', onclick: () => { S.allAssets = true; repaint(); } }, 'Show all') : null),
  ];
}

// ---- System ----------------------------------------------------------------
const FEED = { drop: 'blocks', throttle: 'slows', observe: 'adds suspicion', benign: 'marks research scanners' };
function viewSystem() {
  const y = S.sys, st = S.st;
  if (!y || !st) return h('p', { class: 'loading' }, 'Loading system details.');
  const s = y.status, ro = st.read_only, out = [];
  if (S.flash) out.push(h('div', { class: 'banner', role: 'status' }, S.flash));
  const sens = s.sensors, enf = s.enforcer || {}, press = (s.engine || {}).pressure || {}, dec = s.decoys, adv = s.adviser || {}, x = s.crosstalk || {}, feeds = s.feeds || [];
  const badFeeds = feeds.filter(f => f.error && f.error !== 'not loaded yet').length;
  const light = (name, tone, state, ...more) => h('div', { class: 'light t-' + tone }, h('div', { class: 'head' }, h('span', { class: 'lamp' }), h('span', { class: 'name' }, name)),
    h('div', { class: 'state' }, state), more.filter(Boolean).length ? details('light:' + name, 'Details', more) : null);
  const line = t => h('p', {}, t);
  out.push(h('h2', {}, 'Health'), h('div', { class: 'lights' },
    light('Sensors', !sens ? 'off' : sens.overflow ? 'warn' : 'ok', !sens ? 'Simulated traffic' : sens.overflow ? 'Overloaded at some point' : 'Seeing traffic',
      sens ? line(num(sens.nflog_packets) + ' connections sampled, ' + num(sens.conntrack_events) + ' events' + (sens.overflow ? ', ' + num(sens.overflow) + ' missed' : '') + '.') : null,
      line(num(Math.round(press.NewPerSec || 0)) + ' new connections a second right now' + (s.posture && s.posture.baseline_per_sec >= 1 ? ' (usual: ' + num(Math.round(s.posture.baseline_per_sec)) + ')' : '') + '.')),
    light('Firewall rules', s.enforcer_error ? 'bad' : st.mode === 'enforce' ? 'ok' : 'off', s.enforcer_error ? 'Cannot read its rules' : st.mode === 'enforce' ? 'Installed' : 'Watch-only: none installed',
      s.enforcer_error ? line(s.enforcer_error) : line('Stopped so far: ' + num(enf.drop_verdict_packets) + ' packets from blocked sources, ' + num(enf.drop_reputation_packets) + ' from threat lists, ' + num(enf.drop_egress_packets) + ' outgoing to known-bad addresses, ' + num(enf.throttled_packets) + ' slowed.')),
    light('Threat lists', !feeds.length ? 'off' : badFeeds ? 'warn' : 'ok', !feeds.length ? 'None set up' : badFeeds ? badFeeds + ' failed to update' : feeds.length + ' up to date',
      feeds.map(f => line(f.name + ' (' + (FEED[f.action] || f.action) + '): ' + num(f.entries) + ' entries' + (f.error ? '. ' + f.error : f.updated ? ', updated ' + when(f.updated) : '') + '.'))),
    light('Decoys', !dec ? 'off' : (dec.ports || []).length ? 'ok' : 'warn', !dec ? 'Off' : (dec.ports || []).length ? plural(dec.touches, 'touch', 'touches') : 'No port could be opened',
      dec ? line('Listening on ' + ((dec.ports || []).join(', ') || 'nothing') + '. ' + num(dec.held_now) + ' held right now.' + (dec.skipped ? ' ' + dec.skipped + ' skipped: something real uses them.' : '')) : line('List unused ports under canary in the config.')),
    light('AI adviser', !adv.door ? 'off' : adv.suspended ? 'bad' : 'ok', !adv.door ? 'Not connected' : adv.suspended ? 'Suspended' : 'Connected',
      adv.door ? line(num(adv.accepted) + ' suggestions heard, ' + num(adv.refused) + ' refused, ' + plural(adv.strikes, 'strike', 'strikes') + '.') : line('afw works without one.')),
    light('Other afw nodes', y.peers ? 'ok' : 'off', y.peers ? plural(y.peers, 'node', 'nodes') + ' linked' : 'None linked',
      y.peers ? line(num(x.accepted) + ' warnings received, ' + num(x.rejected) + ' rejected, ' + num(x.sent) + ' sent.') : null),
    light('Safety limit', s.budget_denied ? 'warn' : 'ok', s.budget_denied ? plural(s.budget_denied, 'action', 'actions') + ' held back' : 'Never reached'),
    light('Record', s.journal_dropped ? 'warn' : 'ok', s.journal_dropped ? num(s.journal_dropped) + ' lines dropped' : 'Complete', h('p', { class: 'mono' }, y.log_path))));

  out.push(h('h2', {}, 'Never blocked'), (s.protected || []).length ? h('div', { class: 'row' }, s.protected.map(p => h('span', { class: 'addr' }, p.replace(/\/(32|128)$/, ''))))
    : h('p', { class: 'amber' }, 'Nothing is protected. Add your router and admin machine to the config.'));

  out.push(h('h2', {}, 'Controls'));
  if (ro) out.push(h('p', { class: 'dim' }, 'Read-only here. Controls are only on the machine itself.'));
  else {
    const sw = (key, on, name, hint, toneOn, turnOn, turnOff) => h('div', { class: 'ctl' }, h('div', { class: 'txt' }, h('b', {}, name), h('span', {}, hint)),
      S.armed === key ? [h('button', { class: 'primary', 'data-k': key, onclick: on ? turnOff : turnOn }, on ? 'Yes, turn off' : 'Yes, turn on'), h('button', { 'data-k': key + ':no', onclick: () => { S.armed = null; repaint(); } }, 'Cancel')]
        : h('button', { class: 'switch t-' + toneOn, role: 'switch', 'aria-checked': String(on), 'aria-label': name, 'data-k': key, onclick: () => { S.armed = key; repaint(); } }));
    out.push(
      sw('sw:block', st.mode === 'enforce', 'Blocking', st.mode === 'enforce' ? 'afw acts on what it sees.' : 'afw only records what it would do.', 'ok',
        () => act({ action: 'mode', value: 'enforce' }, 'Blocking is on.'), () => act({ action: 'mode', value: 'shadow' }, 'Watch-only. Nothing is blocked.')),
      sw('sw:bg', st.posture === 'breakglass', 'Emergency mode', 'For a flood: known users first, everyone else limited. afw turns it on by itself.', 'bad',
        () => act({ action: 'breakglass', value: 'on' }, 'Emergency mode is on for an hour.'), () => act({ action: 'breakglass', value: 'off' }, 'Emergency mode is off.')),
      h('div', { class: 'ctl' }, h('div', { class: 'txt' }, h('b', {}, 'Off switch'), h('span', {}, S.armed === 'panic' ? 'Deletes every afw rule and stops afw. Type remove to confirm.' : 'Removes everything afw put in the firewall and stops it.')),
        S.armed === 'panic' ? [h('input', { type: 'text', id: 'sure', 'aria-label': 'Type remove to confirm', autocomplete: 'off', 'data-k': 'sure', placeholder: 'remove' }),
          h('button', { class: 'danger', 'data-k': 'panic', onclick: () => { if ($('sure').value.trim().toLowerCase() === 'remove') act({ action: 'panic' }, 'afw removed its rules and stopped.'); else $('sure').focus(); } }, 'Remove'),
          h('button', { onclick: () => { S.armed = null; repaint(); } }, 'Cancel')]
          : h('button', { class: 'danger', 'data-k': 'panic', onclick: () => { S.armed = 'panic'; repaint(); } }, 'Remove all rules')));
  }
  out.push(h('p', { class: 'dim' }, s.node + ' · ' + (s.role === 'gateway' ? 'protects the whole network' : 'protects this machine') + ' · up ' + span(Date.now() - new Date(st.started)) + ' · ' + st.version));
  return out;
}

// ---- one source ------------------------------------------------------------
function openSource(addr, from) {
  opener = from ? from.getAttribute('data-k') : null;
  const r = route(); r.params.set('s', addr);
  location.hash = '#/' + r.view + '?' + r.params;
}
function closeSource() {
  const r = route(); r.params.delete('s');
  const qs = r.params.toString();
  location.hash = '#/' + r.view + (qs ? '?' + qs : '');
}
async function showSource(addr) {
  const p = $('panel');
  let v, err;
  try { v = await api('/api/source?q=' + encodeURIComponent(addr)); } catch (e) { if (e.message === 'token') return; err = e.message; }
  if (route().params.get('s') !== addr) return;
  const st = S.st || {};
  paint(p, JSON.stringify([addr, v, err, st.mode, st.read_only, S.armed, Math.floor(Date.now() / 30000)]), () => {
    const close = h('button', { id: 'close', 'data-k': 'close', 'aria-label': 'Close', onclick: closeSource }, icon('x'));
    if (err) return [h('div', { class: 'phead' }, h('h1', { id: 'panel-title' }, addr), close), empty('q', 'idle', err)];
    const r = v.restricted, l = v.latest, would = st.mode !== 'enforce', key = 'punblock:' + v.subject;
    const tone = r ? r.action : v.protected || v.known_user ? 'ok' : 'idle';
    const body = [h('div', { class: 'phead t-' + tone }, dot(l ? classIcon(l.class) : r ? 'ban' : 'check', tone),
      h('h1', { id: 'panel-title' }, v.subject, h('small', {}, r ? actWord(r.action, st.mode) + ' · ' + span(new Date(r.until) - Date.now()) + ' left' : 'Not restricted')), close)];
    if (r) body.push(countdown(l && l.ts, r.until, r.action)[0]);
    const badges = [v.protected && ['shield', 'ok', 'Never blocked'], v.known_user && ['user', 'ok', 'Regular user'], v.inside && ['home', 'idle', 'Inside your network']].filter(Boolean);
    if (badges.length) body.push(h('div', { class: 'badges' }, badges.map(([ic, t, text]) => h('span', { class: 'tag t-' + t }, icon(ic), text))));
    if (r && st.mode && !st.read_only && !would) body.push(h('div', { class: 'row badges' }, S.armed !== key
      ? h('button', { 'data-k': key, onclick: () => { S.armed = key; showSource(addr); } }, 'Unblock')
      : [h('button', { class: 'primary', 'data-k': key, onclick: async () => { await act({ action: 'unblock', subject: v.subject }, v.subject + ' unblocked for an hour.'); showSource(addr); } }, 'Unblock for 1 hour'),
        h('button', { 'data-k': key + ':no', onclick: () => { S.armed = null; showSource(addr); } }, 'Cancel')]));
    if (!v.known && !r) body.push(empty('check', 'ok', 'afw has no record of this address.'));

    // The story: what it did, in order, and how it ended.
    let story = [];
    const chain = l && (l.class || '').match(/chain\.(.+?)(\.distributed)?$/);
    if (chain) story = chain[1].split('-').map(p => ({ name: (STAGE[p] || [0, p])[1], ic: (STAGE[p] || ['q'])[0] }));
    else for (const t of v.timeline.filter(t => t.kind === 'decision').reverse()) {
      const name = shortName(t.class);
      if (!story.length || story[story.length - 1].name !== name) story.push({ name, ic: classIcon(t.class) });
    }
    if (story.length) body.push(h('h2', {}, 'What happened'), h('div', { class: 'steps' },
      story.slice(-4).map((s, i) => [i ? h('span', { class: 'arrow' }, icon('right')) : null, h('span', { class: 'step' }, h('span', { class: 'dot sm t-idle' }, icon(s.ic)), s.name)]),
      l ? [h('span', { class: 'arrow' }, icon('right')), h('span', { class: 'step' }, h('span', { class: 'dot sm t-' + l.action }, icon((ACT[l.action] || ['q'])[0])), actWord(l.action, st.mode))] : null));

    if (l && (l.signals || []).length) {
      const at = (l.summary || '').indexOf(l.reason), extra = at >= 0 ? l.summary.slice(at + l.reason.length).replace(/^\./, '').trim() : '';
      body.push(h('h2', {}, 'Evidence'), h('div', { class: 'card' }, l.signals.map(g => {
        const fill = h('i'); fill.style.width = Math.round(100 * Math.min(1, g.weight)) + '%';
        return h('div', { class: 'meter t-' + (g.spoofable ? 'throttle' : 'drop') + (g.spoofable ? ' faked' : '') },
          h('div', { class: 'txt' }, cap(g.detail || g.name), g.spoofable ? h('span', { class: 'faked-tag' }, 'could be faked') : null), h('div', { class: 'track', role: 'img', 'aria-label': 'strength ' + Math.round(g.weight * 100) + ' percent' }, fill));
      }), extra ? h('p', { class: 'dim' }, extra) : null));
    }
    if (v.timeline.length) body.push(h('h2', {}, 'History'), h('ul', { class: 'hist' }, v.timeline.map(t => h('li', {},
      h('span', { class: 'time' }, clock(new Date(t.ts))),
      t.kind === 'decision' ? h('span', { class: 'dot sm t-' + t.action }, icon((ACT[t.action] || ['q'])[0])) : h('span', { class: 'dot sm t-check' }, icon('q')),
      h('span', { class: 'body' }, t.kind === 'decision'
        ? [h('b', {}, actWord(t.action, st.mode) + (t.action !== 'allow' && t.action !== 'observe' && t.ttl ? ' for ' + ttlWords(t.ttl) : '')), h('span', {}, t.class ? shortName(t.class) : cap(t.text))]
        : [h('b', {}, 'Second look asked'), details('q:' + t.ts, 'What afw asked', h('p', {}, tidy(t.text)))])))));
    if (v.known) body.push(h('p', { class: 'dim' }, 'First seen ' + when(v.first) + ' · last seen ' + when(v.last)));
    return body;
  });
  if (p.hidden) { p.hidden = false; $('scrim').hidden = false; $('close').focus(); }
}
function syncPanel() {
  const addr = route().params.get('s'), p = $('panel');
  if (addr) { showSource(addr); return; }
  if (!p.hidden) {
    p.hidden = true; $('scrim').hidden = true; p.replaceChildren(); delete S.painted.panel;
    const back = opener && document.querySelector('[data-k="' + CSS.escape(opener) + '"]');
    if (back) back.focus();
  }
}

// ---- loop ------------------------------------------------------------------
function render() {
  if (!token) return gate();
  chrome();
  const r = route(), main = $('main');
  if (S.view !== r.view) {
    S.view = r.view; S.armed = null; if (!S.justActed) S.flash = null; S.painted = {};
    main.replaceChildren(...(r.view === 'activity' ? shellActivity() : [h('div', { id: 'body' })]));
    window.scrollTo(0, 0);
  }
  S.justActed = false;
  const half = Math.floor(Date.now() / 30000); // countdowns move on even when nothing else changes
  if (r.view === 'now') paint($('body'), JSON.stringify([S.st && Object.assign({}, S.st, { now: 0 }), S.armed, S.flash, half]), viewNow);
  else if (r.view === 'activity') viewActivity();
  else if (r.view === 'coverage') paint($('body'), JSON.stringify([S.cov, S.allAssets, S.cell]), viewCoverage);
  else paint($('body'), JSON.stringify([S.sys, S.st && S.st.mode, S.st && S.st.posture, S.armed, S.flash]), viewSystem);
}
async function tick(acted) {
  if (!token) return gate();
  if (acted) S.justActed = true;
  const view = route().view;
  try {
    S.st = await api('/api/state');
    S.okAt = Date.now(); S.failing = false;
    if (view === 'activity' && S.act.pages === 1) { const r = await api('/api/activity?' + new URLSearchParams({ show: S.act.show, q: S.act.q })); S.act.items = r.items; S.act.more = r.more; }
    if (view === 'coverage') S.cov = await api('/api/coverage');
    if (view === 'system') S.sys = await api('/api/system');
  } catch (e) { if (e.message === 'token') return; S.failing = true; }
  render();
  const open = route().params.get('s');
  if (open && !S.failing) showSource(open);
}
window.addEventListener('hashchange', () => { render(); syncPanel(); tick(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('panel').hidden) closeSource(); });
$('scrim').addEventListener('click', closeSource);
document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
setInterval(() => { if (!document.hidden && !S.stopped) tick(); else chrome(); }, 5000);
render(); syncPanel(); tick();
