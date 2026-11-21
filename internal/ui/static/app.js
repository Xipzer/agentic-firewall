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
// One pictogram per kind of attack (Phosphor, see icons.js), drawn as SVG
// nodes. State is never an icon: it is the square mark, whose fill is the
// severity (hollow = watching, half = slowed, solid = blocked).
const SVG = 'http://www.w3.org/2000/svg';
function icon(name) {
  const s = document.createElementNS(SVG, 'svg');
  s.setAttribute('viewBox', '0 0 256 256'); s.setAttribute('class', 'ic'); s.setAttribute('aria-hidden', 'true');
  for (const d of PH[name] || PH.question) { const n = document.createElementNS(SVG, 'path'); n.setAttribute('d', d); s.append(n); }
  return s;
}
const mark = (tone, extra) => h('i', { class: 'mk is-' + tone + (extra ? ' ' + extra : ''), 'aria-hidden': 'true' });

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
const STAGE = { recon: ['binoculars', 'Scanned'], access: ['key', 'Guessed passwords'], decoy: ['target', 'Hit a decoy'], c2: ['flag', 'Called a bad address'] };
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
  if (c.startsWith('lateral.')) return 'house';
  if (c.startsWith('c2.') || c.includes('known-bad')) return 'flag';
  if (c.includes('chain')) return 'link';
  if (c.includes('bruteforce')) return 'key';
  if (c.includes('decoy')) return 'target';
  if (c.startsWith('dos.')) return 'waves';
  if (c.startsWith('recon.')) return 'binoculars';
  if (c.startsWith('exfil.')) return 'download-simple';
  if (c.startsWith('defence.')) return 'shield';
  if (c.startsWith('peer.')) return 'users';
  return 'warning';
}
const ACT = { drop: ['Blocked', 'Would block'], throttle: ['Slowed', 'Would slow'], observe: ['Watching', 'Watching'], allow: ['Unblocked', 'Unblocked'] };
const isWould = (action, mode) => mode === 'shadow' && (action === 'drop' || action === 'throttle');
const actWord = (action, mode) => (ACT[action] || [action, action])[isWould(action, mode) ? 1 : 0];
const kind = cls => h('span', { class: 'kind' }, icon(classIcon(cls)), h('span', {}, shortName(cls)));
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
const VIEWS = [['now', 'Now'], ['activity', 'Activity'], ['coverage', 'Coverage'], ['system', 'System']];
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
  return [h('button', { 'data-k': key, class: 'go', onclick: run }, confirmLabel), h('button', { 'data-k': key + ':no', class: 'text', onclick: () => { S.armed = null; repaint(); } }, 'Cancel')];
}
async function act(body, done) {
  try { await api('/api/do', body); S.flash = done || null; if (body.action === 'panic') S.stopped = true; }
  catch (e) { if (e.message !== 'token') S.flash = 'That did not work: ' + e.message; }
  S.armed = null;
  await tick(true);
}
const none = (...text) => h('p', { class: 'none' }, text);
const addr = a => h('button', { class: 'addr', 'data-k': 'src:' + a, onclick: e => openSource(a, e.currentTarget) }, a);
const more = (key, label, ...body) => h('details', { 'data-k': key }, h('summary', {}, label), body);
const head = (text, n) => h('h2', {}, text, n ? h('small', {}, ' ' + n) : null);
function pathOf(steps) {
  return h('div', { class: 'path' }, steps.map((s, i) => [i ? h('span', { class: 'to', 'aria-hidden': 'true' }, '\u2192') : null,
    h('span', { class: 'step' + (s.tone ? ' tone is-' + s.tone : '') }, s.tone ? mark(s.tone) : icon(s.ic), s.name)]));
}

// ---- frame -----------------------------------------------------------------
function chrome() {
  const st = S.st, r = route();
  $('node').textContent = st ? ' ' + st.node : '';
  const fresh = $('fresh'), age = Math.round((Date.now() - S.okAt) / 1000);
  fresh.className = 'fresh' + (S.failing || S.stopped ? ' stale' : '');
  fresh.textContent = S.stopped ? 'afw has stopped' : S.failing ? 'Cannot reach afw' : !S.okAt ? '' : age < 8 ? 'live' : age + ' s behind';
  const n = st ? st.attention.length : 0;
  paint($('nav'), r.view + n, () => VIEWS.map(([id, name]) => h('a', { href: '#/' + id, 'aria-current': id === r.view ? 'page' : null }, name,
    id === 'now' && n ? h('sup', { 'aria-label': n + ' need you' }, n) : null)));
}
function gate() {
  $('nav').hidden = true;
  $('main').replaceChildren(h('h1', { class: 'state' }, 'This page needs its link.'),
    h('p', { class: 'lede' }, 'On the machine running afw, run ', h('code', {}, 'sudo afw ui'), ' and open the address it prints.'));
}

// ---- Now -------------------------------------------------------------------
function needRow(a, i, ro) {
  const key = 'need:' + (a.do || a.title) + ':' + (a.subject || i);
  let title = a.title, gist = '', acts = [], extra = [];
  if (a.do === 'confirm') {
    title = 'Can you still get in?';
    gist = cap(tidy(a.detail).replace(/^Blocking was switched on recently\. /, '').replace(/, in case.*$/, '.').replace(/^It switches itself off/, 'Blocking turns itself off'));
    if (!ro) acts.push(h('button', { class: 'go', 'data-k': 'confirm', onclick: () => act({ action: 'confirm' }, 'Confirmed. Blocking stays on.') }, 'Yes, keep blocking'));
  } else if (a.do === 'breakglass-off') {
    title = 'Emergency mode is on'; gist = 'Known users first. Everyone else is limited.';
    if (!ro) acts.push(twoStep('bg:off', 'Turn off', 'Yes, turn off', () => act({ action: 'breakglass', value: 'off' }, 'Emergency mode is off. It returns by itself if the flood is still hurting.')));
    extra.push(more(key, 'Why it came on', h('p', {}, a.detail)));
  } else if (a.do === 'adviser-resume') {
    title = 'AI adviser suspended'; gist = 'It gave answers an honest one would not.';
    if (!ro) acts.push(twoStep('adv', 'Resume', 'Yes, resume', () => act({ action: 'adviser-resume' }, 'The adviser was resumed.')));
    extra.push(more(key, 'What happened', h('p', {}, a.detail)));
  } else if (a.do === 'open-system') {
    acts.push(h('a', { href: '#/system' }, 'Open System')); extra.push(more(key, 'Details', h('p', {}, a.detail)));
  } else {
    const cls = a.title, m = cls.match(/chain\.(.+?)(\.distributed)?$/);
    title = shortName(cls);
    if (cls.startsWith('lateral.') || cls.startsWith('c2.')) { title = 'A device inside is misbehaving'; gist = 'It acts like an attacker. afw is watching it, not blocking it.'; }
    if (m) extra.push(pathOf(m[1].split('-').map(p => ({ ic: (STAGE[p] || ['question'])[0], name: (STAGE[p] || [0, p])[1] }))));
    const srcs = (a.sources || []).filter(s => s !== '0.0.0.0/0');
    extra.push(h('div', { class: 'meta' }, srcs.slice(0, 5).map(addr), srcs.length > 5 ? '+' + (srcs.length - 5) + ' more' : null, a.since ? 'since ' + when(a.since) : null));
    extra.push(more(key, 'What afw is asking', h('p', {}, tidy(a.detail))));
  }
  return h('div', { class: 'need is-' + a.level }, h('div', { class: 'body' }, h('h3', {}, mark(a.level), title), gist ? h('p', { class: 'gist' }, gist) : null, extra),
    acts.length ? h('div', { class: 'acts' }, acts) : null);
}
function leftPct(since, until) {
  const end = new Date(until) - 0, start = new Date(since) - 0, left = Math.max(0, end - Date.now());
  return [start > 0 && end > start ? Math.max(2, Math.min(100, 100 * left / (end - start))) : 100, left];
}
function viewNow() {
  const st = S.st;
  if (!st) return h('p', { class: 'loading' }, 'afw is loading.');
  const out = [], ro = st.read_only, would = st.mode !== 'enforce', n = st.attention.length;
  if (S.flash) out.push(h('p', { class: 'say', role: 'status' }, S.flash));
  const urgent = st.attention.some(a => a.level === 'act');
  const blocked = st.restricted.filter(r => r.action === 'drop').length, slowed = st.restricted.length - blocked;
  let tone = 'ok', word = 'All clear.';
  if (st.posture === 'breakglass') { tone = 'bad'; word = 'Under attack.'; }
  else if (n) { tone = urgent ? 'bad' : 'warn'; word = n === 1 ? 'One thing needs you.' : n + ' things need you.'; }
  else if (would) { tone = 'idle'; word = 'Watching only.'; }
  out.push(h('h1', { class: 'state is-' + tone }, mark(tone, 'big'), h('span', { class: 'word' }, word)));
  const fig = (v, label, t, href) => h('a', { class: 'is-' + t + (v ? '' : ' zero'), href }, mark(v ? t : 'off', would && v ? 'would' : ''), h('b', {}, num(v)), h('span', {}, label));
  out.push(h('div', { class: 'tally' },
    fig(blocked, would ? 'would block' : 'blocked', 'drop', '#/activity?show=drop'), fig(slowed, would ? 'would slow' : 'slowed', 'throttle', '#/activity?show=throttle'), fig(st.watching, 'watched', 'observe', '#/activity?show=observe'),
    h('span', { class: 'mode mute' }, st.posture === 'breakglass' ? 'Emergency mode: known users first' : would ? 'Blocking is off' : 'Blocking is on',
      would && !ro ? twoStep('mode:enforce', 'Start blocking', 'Yes, start', () => act({ action: 'mode', value: 'enforce' }, 'Blocking is on.')) : null)));

  const p = st.pulse, tot = p.blocked.map((b, i) => b + p.slowed[i] + p.watched[i]), peak = Math.max(1, ...tot), sum = tot.reduce((x, y) => x + y, 0);
  out.push(h('figure', { class: 'pulse' },
    h('div', { class: 'bars', role: 'img', 'aria-label': sum + ' decisions in the last hour, per minute' }, tot.map((t, i) => {
      const bar = h('i', { class: p.blocked[i] ? 'b' : p.slowed[i] ? 's' : t ? 'w' : '', title: t ? (59 - i) + ' min ago: ' + [p.blocked[i] && p.blocked[i] + ' blocked', p.slowed[i] && p.slowed[i] + ' slowed', p.watched[i] && p.watched[i] + ' watched'].filter(Boolean).join(', ') : null });
      bar.style.height = t ? 22 + 78 * Math.sqrt(t / peak) + '%' : '0';
      return bar;
    })),
    h('figcaption', {}, h('span', {}, 'an hour ago'), h('span', {}, sum ? plural(sum, 'decision', 'decisions') + ' in the last hour' : 'a quiet hour'), h('span', {}, 'now'))));

  if (n) { out.push(head('Needs you', n)); st.attention.forEach((a, i) => out.push(needRow(a, i, ro))); }
  if (st.handled) out.push(h('p', { class: 'lede', }, plural(st.handled, 'more incident', 'more incidents') + ' handled by afw. ', h('a', { href: '#/activity?show=review' }, 'Review them')));

  out.push(head(would ? 'Would be restricted' : 'Restricted now', st.restricted.length || ''));
  if (!st.restricted.length) out.push(none('Nothing is restricted.'));
  else out.push(h('div', { class: 'rows restricted' }, st.restricted.map(r => {
    const [pct, left] = leftPct(r.since, r.until);
    const row = h('div', { class: 'row timed is-' + r.action },
      mark(r.action, would ? 'would' : ''), addr(r.subject), kind(r.class),
      h('span', { class: 'left num mute' }, span(left) + ' left'),
      h('span', { class: 'undo acts' }, ro || would ? null : twoStep('unblock:' + r.subject, 'Unblock', 'Unblock 1 h', () => act({ action: 'unblock', subject: r.subject }, r.subject + ' unblocked for an hour.'), 'text')));
    row.style.setProperty('--left', pct + '%');
    return row;
  })));
  return out;
}

// ---- Activity --------------------------------------------------------------
const SHOW = [['', 'All', ''], ['drop', 'Blocked', 'drop'], ['throttle', 'Slowed', 'throttle'], ['observe', 'Watching', 'observe'], ['review', 'Unsure', '']];
function shellActivity() {
  let timer;
  const a = S.act, want = route().params.get('show');
  if (want != null && SHOW.some(x => x[0] === want)) { a.show = want; a.pages = 1; }
  return [h('div', { class: 'picks' }, h('span', { class: 'group', id: 'filters', role: 'group', 'aria-label': 'Show' }),
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
// One attacker usually climbs: watched, then slowed, then blocked. The list
// shows where each one ended up; the steps are in its history.
function steps(items) {
  const out = [];
  for (const d of items) {
    const last = out[out.length - 1];
    if (last && last.d.subject === d.subject && new Date(last.d.ts) - new Date(d.ts) < 15 * 60000) last.review = last.review || d.escalated;
    else out.push({ d, review: d.escalated });
  }
  return out;
}
function viewActivity() {
  const a = S.act, mode = S.st ? S.st.mode : 'enforce';
  paint($('filters'), a.show, () => SHOW.map(([id, name, tone]) => h('button', { class: 'pick' + (tone ? ' is-' + tone : ''), 'aria-pressed': String(a.show === id), 'data-k': 'show:' + id, onclick: () => { a.show = id; a.pages = 1; loadActivity(); } }, tone ? mark(tone) : null, name)));
  paint($('act'), JSON.stringify([a.items.length, a.items[0], a.items[a.items.length - 1], a.more, a.pages, mode]), () => {
    if (!a.items.length) return a.q || a.show
      ? none('Nothing matches. ', h('button', { class: 'text', onclick: () => { a.q = ''; a.show = ''; $('find').value = ''; loadActivity(); } }, 'Clear filters'))
      : none('No decisions yet. They appear the moment something suspicious happens.');
    const out = [a.pages > 1 ? h('p', { class: 'lede' }, 'Showing older decisions. ', h('button', { class: 'text', onclick: () => { a.pages = 1; loadActivity(); } }, 'Back to latest')) : null];
    let day = null, list = null;
    for (const { d } of steps(a.items)) {
      const name = dayName(d.ts);
      if (name !== day) { day = name; out.push(h('h2', { class: 'day' }, name)); list = h('div', { class: 'rows activity' }); out.push(list); }
      list.append(h('button', { class: 'row is-' + d.action, 'data-k': 'dec:' + d.id, 'aria-label': clock(new Date(d.ts)) + ', ' + d.subject + ', ' + actWord(d.action, d.mode) + ', ' + shortName(d.class), onclick: e => openSource(d.subject, e.currentTarget) },
        h('span', { class: 'num mute' }, clock(new Date(d.ts))), mark(d.action, isWould(d.action, d.mode) ? 'would' : ''),
        h('span', { class: 'addr clip' }, d.subject), kind(d.class),
        h('span', { class: 'end num mute' }, d.action !== 'allow' && d.action !== 'observe' && d.ttl ? ttlWords(d.ttl) : '')));
    }
    if (a.more) out.push(h('p', { class: 'lede' }, h('button', { 'data-k': 'older', onclick: () => loadActivity(true) }, 'Show older')));
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
  const all = c.attack_universe, count = t => all.filter(r => tone(r) === t).length, pick = all.find(r => r.class === S.cell);
  const WORD = { yes: 'afw sees this and stops it.', partial: 'afw handles this only partly.', no: 'afw cannot stop this on its own.' };
  const hit = a => Object.keys(a.classes || {}).length ? 1 : 0;
  const ranked = c.assets.filter(a => a.flows_last_hour || hit(a)).sort((x, y) => hit(y) - hit(x) || y.flows_last_hour - x.flows_last_hour);
  const assets = ranked.slice(0, S.allAssets ? 500 : 6), max = Math.max(1, ...ranked.map(a => a.flows_last_hour));
  return [
    h('h1', { class: 'state is-' + (count('no') ? 'bad' : 'ok') }, h('span', { class: 'word' }, count('no') + ' gaps'), h('span', {}, 'in ' + all.length + ' attack types.')),
    h('p', { class: 'lede' }, 'One square per attack type. A number is how often it has been seen here.'),
    h('div', { class: 'heat' }, fams.map(f => [h('div', { class: 'fam' }, cap(f.name)), h('div', { class: 'cells' }, f.rows.map(r =>
      h('button', { class: 'cell is-' + tone(r) + (r.seen ? ' seen' : ''), 'aria-pressed': String(S.cell === r.class), 'data-k': 'cell:' + r.class, title: className(r.class),
        'aria-label': className(r.class) + '. ' + WORD[tone(r)] + (r.seen ? ' Seen here ' + r.seen + ' times.' : ''), onclick: () => { S.cell = S.cell === r.class ? null : r.class; repaint(); } }, r.seen ? (r.seen > 99 ? '99+' : r.seen) : null)))])),
    h('div', { class: 'key' }, h('span', { class: 'is-yes' }, mark('yes'), count('yes') + ' handled'), h('span', { class: 'is-partial' }, mark('partial'), count('partial') + ' partly'), h('span', { class: 'is-no' }, mark('no'), count('no') + ' gaps')),
    h('div', { class: 'picked' }, pick ? [h('h3', { class: 'tone is-' + tone(pick) }, className(pick.class)), h('p', { class: 'mute' }, WORD[tone(pick)] + ' ' + (pick.seen ? 'Seen here ' + plural(pick.seen, 'time', 'times') + '.' : pick.see === 'no' ? 'afw could not tell if it happened here.' : 'Not seen here yet.'))]
      : h('p', { class: 'mute' }, 'Pick a square to see what it is.')),

    head('Most targeted', 'connections in the last hour'),
    !assets.length ? none('Nothing has been targeted yet.') : h('div', { class: 'rows targets' }, assets.map(a => {
      const [name, where] = assetLabel(a.asset), kinds = Object.keys(a.classes || {}).map(shortName).filter((v, i, x) => x.indexOf(v) === i);
      const fill = h('i'); fill.style.width = Math.max(1, 100 * a.flows_last_hour / max) + '%';
      return h('div', { class: 'row is-' + (kinds.length ? 'drop' : 'observe') }, h('span', { class: 'who' }, name, h('small', {}, [where, kinds.join(', ')].filter(Boolean).join(' \u00b7 '))),
        h('div', { class: 'bar', role: 'img', 'aria-label': a.flows_last_hour + ' connections' }, fill), h('b', { class: 'end num' }, num(a.flows_last_hour)));
    })),
    ranked.length > assets.length && !S.allAssets ? h('p', { class: 'lede' }, h('button', { class: 'text', onclick: () => { S.allAssets = true; repaint(); } }, 'Show all ' + ranked.length)) : null,
  ];
}

// ---- System ----------------------------------------------------------------
const FEED = { drop: 'blocks', throttle: 'slows', observe: 'adds suspicion', benign: 'marks research scanners' };
function viewSystem() {
  const y = S.sys, st = S.st;
  if (!y || !st) return h('p', { class: 'loading' }, 'Loading system details.');
  const s = y.status, ro = st.read_only, out = [];
  if (S.flash) out.push(h('p', { class: 'say', role: 'status' }, S.flash));
  const sens = s.sensors, enf = s.enforcer || {}, press = (s.engine || {}).pressure || {}, dec = s.decoys, adv = s.adviser || {}, x = s.crosstalk || {}, feeds = s.feeds || [];
  const badFeeds = feeds.filter(f => f.error && f.error !== 'not loaded yet').length;
  const parts = [
    ['Sensors', !sens ? 'off' : sens.overflow ? 'warn' : 'ok', !sens ? 'Simulated traffic' : sens.overflow ? 'Overloaded at some point' : 'Seeing traffic',
      [sens ? num(sens.nflog_packets) + ' connections sampled, ' + num(sens.conntrack_events) + ' events' + (sens.overflow ? ', ' + num(sens.overflow) + ' missed' : '') + '.' : null,
        num(Math.round(press.NewPerSec || 0)) + ' new connections a second right now' + (s.posture && s.posture.baseline_per_sec >= 1 ? ' (usual: ' + num(Math.round(s.posture.baseline_per_sec)) + ')' : '') + '.']],
    ['Firewall rules', s.enforcer_error ? 'bad' : st.mode === 'enforce' ? 'ok' : 'off', s.enforcer_error ? 'Cannot read its own rules' : st.mode === 'enforce' ? 'Installed' : 'None installed (watch-only)',
      [s.enforcer_error || 'Stopped so far: ' + num(enf.drop_verdict_packets) + ' packets from blocked sources, ' + num(enf.drop_reputation_packets) + ' from threat lists, ' + num(enf.drop_egress_packets) + ' outgoing to known-bad addresses, ' + num(enf.throttled_packets) + ' slowed.']],
    ['Threat lists', !feeds.length ? 'off' : badFeeds ? 'warn' : 'ok', !feeds.length ? 'None set up' : badFeeds ? badFeeds + ' failed to update' : feeds.length + ' up to date',
      feeds.map(f => f.name + ' (' + (FEED[f.action] || f.action) + '): ' + num(f.entries) + ' entries' + (f.error ? '. ' + f.error : f.updated ? ', updated ' + when(f.updated) : '') + '.')],
    ['Decoys', !dec ? 'off' : (dec.ports || []).length ? 'ok' : 'warn', !dec ? 'Off' : (dec.ports || []).length ? plural(dec.touches, 'touch', 'touches') + ' on ' + dec.ports.length + ' ports' : 'No port could be opened',
      [dec ? 'Listening on ' + ((dec.ports || []).join(', ') || 'nothing') + '. ' + num(dec.held_now) + ' held right now.' + (dec.skipped ? ' ' + dec.skipped + ' skipped: something real uses them.' : '') : 'List unused ports under canary in the config.']],
    ['AI adviser', !adv.door ? 'off' : adv.suspended ? 'bad' : 'ok', !adv.door ? 'Not connected' : adv.suspended ? 'Suspended' : 'Connected',
      [adv.door ? num(adv.accepted) + ' suggestions heard, ' + num(adv.refused) + ' refused, ' + plural(adv.strikes, 'strike', 'strikes') + '.' : 'afw works without one.']],
    ['Other afw nodes', y.peers ? 'ok' : 'off', y.peers ? plural(y.peers, 'node', 'nodes') + ' linked' : 'None linked', y.peers ? [num(x.accepted) + ' warnings received, ' + num(x.rejected) + ' rejected, ' + num(x.sent) + ' sent.'] : []],
    ['Safety limit', s.budget_denied ? 'warn' : 'ok', s.budget_denied ? plural(s.budget_denied, 'action', 'actions') + ' held back' : 'Never reached', []],
    ['Record', s.journal_dropped ? 'warn' : 'ok', s.journal_dropped ? num(s.journal_dropped) + ' lines dropped' : 'Complete', [y.log_path]],
  ];
  const wrong = parts.filter(p => p[1] === 'bad' || p[1] === 'warn').length;
  out.push(h('h1', { class: 'state is-' + (wrong ? 'warn' : 'ok') }, mark(wrong ? 'warn' : 'ok', 'big'), h('span', { class: 'word' }, wrong ? (wrong === 1 ? 'One part needs a look.' : wrong + ' parts need a look.') : 'afw is healthy.')));
  out.push(head('Parts'), h('div', { class: 'rows health' }, parts.map(([name, tone, state, lines]) => h('div', { class: 'row is-' + tone }, mark(tone), h('b', {}, name),
    h('span', { class: 'more' }, lines.filter(Boolean).length ? more('part:' + name, state, lines.filter(Boolean).map(t => h('p', {}, t))) : h('span', { class: 'mute' }, state))))));

  out.push(head('Never blocked'), (s.protected || []).length ? h('p', { class: 'none' }, s.protected.map((p, i) => [i ? ', ' : null, h('span', { class: 'addr' }, p.replace(/\/(32|128)$/, ''))]))
    : none('Nothing is protected. Add your router and admin machine to the config.'));

  out.push(head('Controls'));
  if (ro) out.push(none('Read-only here. Controls are only on the machine itself.'));
  else {
    const sw = (key, on, name, hint, turnOn, turnOff) => h('div', { class: 'ctl' }, h('b', {}, name), h('p', {}, hint), h('div', { class: 'acts' },
      S.armed === key ? [h('button', { class: 'go', 'data-k': key, onclick: on ? turnOff : turnOn }, on ? 'Yes, turn off' : 'Yes, turn on'), h('button', { class: 'text', 'data-k': key + ':no', onclick: () => { S.armed = null; repaint(); } }, 'Cancel')]
        : h('button', { class: 'switch', role: 'switch', 'aria-checked': String(on), 'aria-label': name, 'data-k': key, onclick: () => { S.armed = key; repaint(); } })));
    out.push(
      sw('sw:block', st.mode === 'enforce', 'Blocking', st.mode === 'enforce' ? 'afw acts on what it sees.' : 'afw only records what it would do.',
        () => act({ action: 'mode', value: 'enforce' }, 'Blocking is on.'), () => act({ action: 'mode', value: 'shadow' }, 'Watch-only. Nothing is blocked.')),
      sw('sw:bg', st.posture === 'breakglass', 'Emergency mode', 'For a flood: known users first, everyone else limited. afw turns it on by itself.',
        () => act({ action: 'breakglass', value: 'on' }, 'Emergency mode is on for an hour.'), () => act({ action: 'breakglass', value: 'off' }, 'Emergency mode is off.')),
      h('div', { class: 'ctl' }, h('b', {}, 'Off switch'), h('p', {}, S.armed === 'panic' ? 'Deletes every afw rule and stops afw. Type remove to confirm.' : 'Removes everything afw put in the firewall and stops it.'),
        h('div', { class: 'acts' }, S.armed === 'panic' ? [h('input', { type: 'text', id: 'sure', 'aria-label': 'Type remove to confirm', autocomplete: 'off', 'data-k': 'sure', placeholder: 'remove' }),
          h('button', { class: 'stop', 'data-k': 'panic', onclick: () => { if ($('sure').value.trim().toLowerCase() === 'remove') act({ action: 'panic' }, 'afw removed its rules and stopped.'); else $('sure').focus(); } }, 'Remove'),
          h('button', { class: 'text', onclick: () => { S.armed = null; repaint(); } }, 'Cancel')]
          : h('button', { class: 'stop', 'data-k': 'panic', onclick: () => { S.armed = 'panic'; repaint(); } }, 'Remove all rules'))));
  }
  out.push(h('p', { class: 'foot' }, s.node + ', ' + (s.role === 'gateway' ? 'protecting the whole network' : 'protecting this machine') + ', up ' + span(Date.now() - new Date(st.started)) + ', version ' + st.version));
  return out;
}

// ---- one source ------------------------------------------------------------
function openSource(a, from) {
  opener = from ? from.getAttribute('data-k') : null;
  const r = route(); r.params.set('s', a);
  location.hash = '#/' + r.view + '?' + r.params;
}
function closeSource() {
  const r = route(); r.params.delete('s');
  const qs = r.params.toString();
  location.hash = '#/' + r.view + (qs ? '?' + qs : '');
}
async function showSource(a) {
  const p = $('panel');
  let v, err;
  try { v = await api('/api/source?q=' + encodeURIComponent(a)); } catch (e) { if (e.message === 'token') return; err = e.message; }
  if (route().params.get('s') !== a) return;
  const st = S.st || {};
  paint(p, JSON.stringify([a, v, err, st.mode, st.read_only, S.armed, Math.floor(Date.now() / 30000)]), () => {
    const close = h('button', { id: 'close', 'data-k': 'close', 'aria-label': 'Close', onclick: closeSource }, '\u00d7');
    if (err) return [h('div', { class: 'phead' }, h('h1', { id: 'panel-title' }, a), close), none(err)];
    const r = v.restricted, l = v.latest, would = st.mode !== 'enforce', key = 'punblock:' + v.subject;
    const tone = r ? r.action : 'off';
    const body = [h('div', { class: 'phead' }, h('h1', { id: 'panel-title' }, v.subject), close),
      h('p', { class: 'pstate is-' + tone }, mark(tone, r && would ? 'would' : ''), r ? [h('b', { class: 'tone' }, actWord(r.action, st.mode)), h('span', {}, span(new Date(r.until) - Date.now()) + ' left')] : h('span', {}, 'Not restricted'))];
    if (r) { const fill = h('i'); fill.style.width = leftPct(l && l.ts, r.until)[0] + '%'; body.push(h('div', { class: 'bar is-' + r.action }, fill)); }
    const facts = [v.protected && 'Never blocked', v.known_user && 'Regular user', v.inside && 'Inside your network'].filter(Boolean);
    if (facts.length) body.push(h('p', { class: 'facts' }, facts.map(t => h('span', { class: 'is-ok' }, mark('ok'), t))));
    if (r && st.mode && !st.read_only && !would) body.push(h('p', { class: 'acts facts' }, S.armed !== key
      ? h('button', { 'data-k': key, onclick: () => { S.armed = key; showSource(a); } }, 'Unblock')
      : [h('button', { class: 'go', 'data-k': key, onclick: async () => { await act({ action: 'unblock', subject: v.subject }, v.subject + ' unblocked for an hour.'); showSource(a); } }, 'Unblock for 1 hour'),
        h('button', { class: 'text', 'data-k': key + ':no', onclick: () => { S.armed = null; showSource(a); } }, 'Cancel')]));
    if (!v.known && !r) body.push(none('afw has no record of this address.'));

    let story = [];
    const chain = l && (l.class || '').match(/chain\.(.+?)(\.distributed)?$/);
    if (chain) story = chain[1].split('-').map(x => ({ name: (STAGE[x] || [0, x])[1], ic: (STAGE[x] || ['question'])[0] }));
    else for (const t of v.timeline.filter(t => t.kind === 'decision').reverse()) {
      const name = shortName(t.class);
      if (!story.length || story[story.length - 1].name !== name) story.push({ name, ic: classIcon(t.class) });
    }
    if (story.length) body.push(head('What happened'), pathOf(story.slice(-4).concat(l ? [{ name: actWord(l.action, st.mode), tone: l.action }] : [])));

    if (l && (l.signals || []).length) {
      const at = (l.summary || '').indexOf(l.reason), extra = at >= 0 ? l.summary.slice(at + l.reason.length).replace(/^\./, '').trim() : '';
      body.push(head('Evidence', 'bar = how much it counted'), h('div', { class: 'rows proof' }, l.signals.map(g => {
        const fill = h('i'); fill.style.width = Math.round(100 * Math.min(1, g.weight)) + '%';
        return h('div', { class: 'row is-' + (g.spoofable ? 'throttle' : 'drop') }, h('span', {}, cap(g.detail || g.name), g.spoofable ? h('small', {}, 'could be faked') : null),
          h('div', { class: 'bar' + (g.spoofable ? ' faked' : ''), role: 'img', 'aria-label': Math.round(g.weight * 100) + ' percent' }, fill));
      })), extra ? h('p', { class: 'lede' }, extra) : null);
    }
    if (v.timeline.length) body.push(head('History'), h('div', { class: 'rows history' }, v.timeline.map(t => h('div', { class: 'row is-' + (t.kind === 'decision' ? t.action : 'off') },
      h('span', { class: 'num mute' }, clock(new Date(t.ts))), mark(t.kind === 'decision' ? t.action : 'off'),
      t.kind === 'decision' ? h('span', {}, h('b', {}, actWord(t.action, st.mode) + (t.action !== 'allow' && t.action !== 'observe' && t.ttl ? ' for ' + ttlWords(t.ttl) : '')), h('span', { class: 'mute' }, ' ' + (t.class ? shortName(t.class) : cap(t.text))))
        : more('q:' + t.ts, 'afw asked for a second look', h('p', {}, tidy(t.text)))))));
    if (v.known) body.push(h('p', { class: 'foot' }, 'First seen ' + when(v.first) + ', last seen ' + when(v.last) + '.'));
    return body;
  });
  if (p.hidden) { p.hidden = false; $('scrim').hidden = false; $('close').focus(); }
}
function syncPanel() {
  const a = route().params.get('s'), p = $('panel');
  if (a) { showSource(a); return; }
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
  const half = Math.floor(Date.now() / 30000); // time left moves on even when nothing else changes
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
