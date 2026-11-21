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
const STAGE = { recon: 'scanning', access: 'password guessing', decoy: 'touching a decoy', c2: 'contacting a known-bad address' };
function className(c) {
  if (!c) return '';
  let many = '';
  if (c.endsWith('.distributed')) { c = c.slice(0, -12); many = ', from many addresses'; }
  let inside = '';
  let m = c.match(/^(lateral\.)?chain\.(.+)$/);
  if (m) {
    const steps = m[2].split('-').map(s => STAGE[s] || s).join(', then ');
    return (m[1] ? 'Inside device: break-in chain: ' : 'Break-in chain: ') + steps + many;
  }
  if (CLASS[c]) return CLASS[c] + many;
  if (c.startsWith('lateral.')) { inside = 'Inside device: '; c = c.slice(8); }
  for (let k = c; k; k = k.includes('.') ? k.slice(0, k.lastIndexOf('.')) : '') {
    const hit = CLASS[k] || CLASS['recon.' + k] || CLASS['access.' + k];
    if (hit) return inside + (inside ? hit.charAt(0).toLowerCase() + hit.slice(1) : hit) + many;
  }
  return inside + c + many;
}
function actionTag(action, mode) {
  const would = mode === 'shadow' && (action === 'drop' || action === 'throttle');
  const word = { drop: would ? 'Would block' : 'Blocked', throttle: would ? 'Would slow' : 'Slowed', observe: 'Watching', allow: 'Unblocked' }[action] || action;
  return h('span', { class: 'tag ' + action + (would ? ' would' : '') }, word);
}
const PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'Mail', 53: 'DNS', 80: 'Web', 443: 'Web (HTTPS)', 445: 'File sharing', 2323: 'Telnet (alt)', 3306: 'MySQL', 3389: 'Remote desktop', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'Web (alt)', 8443: 'Web (alt HTTPS)', 9200: 'Elasticsearch' };
function assetLabel(a) {
  let m = a.match(/^(.*) \(outbound\)$/);
  if (m) return 'Outgoing from ' + m[1];
  m = a.match(/^(.*)\/(\d+)\/(tcp|udp)$/);
  if (m) return 'Port ' + m[2] + (PORTS[m[2]] ? ' (' + PORTS[m[2]] + ')' : m[3] === 'udp' ? ' (UDP)' : '') + ' on ' + m[1];
  return a;
}
const cap = t => t ? t.charAt(0).toUpperCase() + t.slice(1) : '';
const num = n => Number(n || 0).toLocaleString('en-GB');
const plural = (n, one, many) => num(n) + ' ' + (n === 1 ? one : many);
function when(ts) {
  const d = new Date(ts), now = new Date();
  if (isNaN(d) || d.getFullYear() < 2000) return '';
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  const day = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 864e5);
  if (diff === 0) return time;
  if (diff === 1) return 'Yesterday ' + time;
  return d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' }) + ' ' + time;
}
function span(ms) {
  const m = Math.max(0, Math.round(ms / 60000));
  if (m < 1) return 'under a minute';
  if (m < 60) return m + ' min';
  const hrs = Math.floor(m / 60), rest = m % 60;
  if (hrs < 24) return hrs + ' h' + (rest ? ' ' + rest + ' min' : '');
  return Math.floor(hrs / 24) + ' d ' + (hrs % 24) + ' h';
}
const endsIn = until => 'ends in ' + span(new Date(until) - Date.now());
function ttlWords(ttl) {
  const m = /^([0-9.]+)(ms|s|m|h|d)$/.exec(ttl || '');
  return m ? span(parseFloat(m[1]) * { ms: 1, s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2]]) : ttl;
}

// ---- state -----------------------------------------------------------------
const VIEWS = [['now', 'Now'], ['activity', 'Activity'], ['coverage', 'Coverage'], ['system', 'System']];
const S = { st: null, okAt: 0, failing: false, stopped: false, view: '', act: { items: [], more: false, show: '', q: '', pages: 1 }, cov: null, sys: null, armed: null, flash: null, painted: {} };
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
  const k = document.activeElement && el.contains(document.activeElement) ? document.activeElement.getAttribute('data-k') : null;
  el.replaceChildren(...[build()].flat(3).filter(x => x != null && x !== false));
  if (k) { const again = el.querySelector('[data-k="' + CSS.escape(k) + '"]'); if (again) again.focus(); }
}
const repaint = () => { S.painted = {}; render(); };

// A risky action takes two presses, in place. No pop-up dialogs.
function twoStep(key, label, confirmLabel, run, cls) {
  if (S.armed !== key) return h('button', { 'data-k': key, class: cls === 'danger' ? '' : cls, onclick: () => { S.armed = key; repaint(); } }, label);
  return h('span', { class: 'row-actions' },
    h('button', { 'data-k': key, class: cls || 'primary', onclick: run }, confirmLabel),
    h('button', { 'data-k': key + ':no', onclick: () => { S.armed = null; repaint(); } }, 'Cancel'));
}
async function act(body, done) {
  try {
    await api('/api/do', body);
    S.armed = null; S.flash = done || null;
    if (body.action === 'panic') S.stopped = true;
  } catch (e) { if (e.message !== 'token') S.flash = 'That did not work: ' + e.message; S.armed = null; }
  await tick(true);
}
const empty = (text, ...way) => h('div', { class: 'empty' }, h('p', {}, text), way);
const sourceChip = addr => h('button', { class: 'chip', 'data-k': 'src:' + addr, onclick: e => openSource(addr, e.currentTarget) }, addr);

// ---- header and navigation -------------------------------------------------
function chrome() {
  const st = S.st, r = route();
  $('node').textContent = st ? st.node : '';
  const pill = $('status');
  if (st) {
    const emergency = st.posture === 'breakglass';
    pill.textContent = emergency ? 'Emergency mode' : st.mode === 'enforce' ? 'Blocking' : 'Watch-only';
    pill.className = 'pill ' + (emergency ? 'emergency' : st.mode === 'enforce' ? 'on' : 'watch');
  }
  const fresh = $('fresh'), age = Math.round((Date.now() - S.okAt) / 1000);
  fresh.className = 'dim fresh' + (S.failing ? ' stale' : '');
  fresh.textContent = S.stopped ? 'afw has stopped' : S.failing ? "Can't reach afw. Retrying." : !S.okAt ? '' : age < 8 ? 'Updated just now' : 'Updated ' + age + ' s ago';
  const urgent = st ? st.attention.filter(a => a.level === 'act').length : 0;
  paint($('nav'), r.view + urgent, () => VIEWS.map(([id, name]) =>
    h('a', { href: '#/' + id, 'aria-current': id === r.view ? 'page' : null }, name,
      id === 'now' && urgent ? h('span', { class: 'count', 'aria-label': urgent + ' need you' }, urgent) : null)));
}
function gate() {
  $('nav').hidden = true;
  $('main').replaceChildren(empty('This page needs its access link.',
    h('p', { class: 'note' }, 'On the machine running afw, run ', h('code', {}, 'sudo afw ui'), ' and open the address it prints.')));
}

// ---- Now -------------------------------------------------------------------
function viewNow() {
  const st = S.st;
  if (!st) return h('p', { class: 'loading' }, 'afw is loading.');
  const out = [];
  if (S.flash) out.push(h('div', { class: 'banner', role: 'status' }, S.flash));
  const ro = st.read_only;
  if (st.mode !== 'enforce') {
    out.push(h('p', { class: 'lead watch' }, 'Watch-only.'),
      h('p', { class: 'sec' }, 'afw is recording what it would do and blocking nothing.'),
      ro ? null : h('div', { class: 'row-actions' }, twoStep('mode:enforce', 'Start blocking', 'Yes, start blocking',
        () => act({ action: 'mode', value: 'enforce' }, 'Blocking is on. Confirm below once you have checked you can still reach this machine.'), 'primary')));
  } else if (st.posture === 'breakglass') {
    out.push(h('p', { class: 'lead bad' }, 'Emergency mode is on.'), h('p', { class: 'sec' }, 'Blocking continues. Known users are served first.'));
  } else {
    out.push(h('p', { class: 'lead ok' }, 'Blocking is on.'), h('p', { class: 'sec' }, 'Every block and slow-down expires on its own.'));
  }

  out.push(h('h2', {}, 'Needs you'));
  if (!st.attention.length) out.push(h('p', { class: 'note' }, 'Nothing needs you right now.'));
  const handledLine = st.handled ? h('p', { class: 'note' }, plural(st.handled, 'other incident is', 'other incidents are') + ' open. afw has dealt with ' + (st.handled === 1 ? 'it' : 'them') + ' and noted ' + (st.handled === 1 ? 'it' : 'them') + ' for review. ',
    h('a', { href: '#/activity?show=review' }, 'See them in Activity')) : null;
  for (const [i, a] of st.attention.entries()) {
    const isClass = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(a.title) || a.title === 'chain';
    const btn = [];
    if (!ro && a.do === 'confirm') btn.push(h('button', { class: 'primary', 'data-k': 'confirm', onclick: () => act({ action: 'confirm' }, 'Confirmed. Blocking stays on.') }, 'I can still reach it: keep blocking'));
    if (!ro && a.do === 'breakglass-off') btn.push(twoStep('bg:off', 'Turn emergency mode off', 'Yes, turn it off', () => act({ action: 'breakglass', value: 'off' }, 'Emergency mode was turned off. It comes back on its own if the flood is still hurting.')));
    if (!ro && a.do === 'adviser-resume') btn.push(twoStep('adv', 'Resume the adviser', 'Yes, resume it', () => act({ action: 'adviser-resume' }, 'The adviser was resumed.')));
    if (a.do === 'open-system') btn.push(h('a', { href: '#/system' }, 'Open System'));
    const srcs = (a.sources || []).filter(s => s !== '0.0.0.0/0');
    out.push(h('div', { class: 'card ' + a.level },
      h('h3', {}, isClass ? className(a.title) : a.title),
      a.detail ? h('p', {}, a.detail.replace(/^\[[^\]]*\]\s*/, '')) : null,
      srcs.length ? h('p', {}, srcs.slice(0, 6).map(sourceChip), srcs.length > 6 ? h('span', { class: 'dim' }, '+' + (srcs.length - 6) + ' more') : null) : null,
      a.since ? h('p', { class: 'dim' }, 'Since ' + when(a.since)) : null,
      btn.length ? h('div', { class: 'row-actions' }, btn) : null));
    void i;
  }

  if (handledLine) out.push(handledLine);
  const would = st.mode !== 'enforce';
  out.push(h('h2', {}, (would ? 'Would be restricted right now' : 'Restricted right now') + (st.restricted.length ? ' (' + num(st.restricted.length) + ')' : '')));
  if (!st.restricted.length) out.push(h('p', { class: 'note' }, would ? 'afw would not be restricting anything right now.' : 'Nothing is restricted right now.'));
  else out.push(h('ul', { class: 'list' }, st.restricted.map(r => h('li', {}, h('div', { class: 'item r' },
    h('span', { class: 'who' }, sourceChip(r.subject)),
    h('span', { class: 'what' }, actionTag(r.action, st.mode)),
    h('span', { class: 'why' }, r.class ? h('b', {}, className(r.class) + '. ') : null, cap(r.reason || ''),
      r.unproven ? ' Slowed, not blocked, because this evidence could be faked.' : '', r.advised ? ' Suggested by another afw or the adviser.' : ''),
    h('span', { class: 'end' }, endsIn(r.until)),
    ro || would ? h('span') : twoStep('unblock:' + r.subject, 'Unblock', 'Unblock for 1 hour', () => act({ action: 'unblock', subject: r.subject }, r.subject + ' was unblocked and will be left alone for an hour.')))))));

  const d = st.day, parts = [];
  if (d.blocked) parts.push('blocked ' + plural(d.blocked, 'time', 'times'));
  if (d.slowed) parts.push('slowed ' + plural(d.slowed, 'source', 'sources'));
  if (d.watched) parts.push('put ' + plural(d.watched, 'source', 'sources') + ' under watch');
  out.push(h('h2', {}, 'Last 24 hours'), h('p', { class: 'note' },
    parts.length ? 'afw ' + (would ? 'would have ' : '') + parts.join(', ').replace(/, ([^,]*)$/, ' and $1') + '. ' : 'Nothing was restricted or flagged. ',
    st.known_users ? 'It recognises ' + plural(st.known_users, 'regular user', 'regular users') + ', who are never restricted on evidence that could be faked. ' : '',
    h('a', { href: '#/activity' }, 'See every decision')));
  return out;
}

// ---- Activity --------------------------------------------------------------
const SHOW = [['', 'All'], ['drop', 'Blocked'], ['throttle', 'Slowed'], ['observe', 'Watching'], ['review', 'Passed up for review']];
function shellActivity() {
  let timer;
  const a = S.act;
  const want = route().params.get('show');
  if (want != null && SHOW.some(x => x[0] === want)) { a.show = want; a.pages = 1; }
  return [h('div', { class: 'filters' }, h('span', { class: 'group', id: 'filters', role: 'group', 'aria-label': 'Show' }),
    h('input', { type: 'search', id: 'find', 'aria-label': 'Find an address', placeholder: 'Find an address', value: a.q,
      oninput: e => { clearTimeout(timer); const v = e.target.value.trim(); timer = setTimeout(() => { a.q = v; a.pages = 1; loadActivity(); }, 300); } })),
  h('div', { id: 'act' })];
}
async function loadActivity(older) {
  const a = S.act, p = new URLSearchParams({ show: a.show, q: a.q });
  if (older && a.items.length) p.set('before', a.items[a.items.length - 1].ts);
  try {
    const r = await api('/api/activity?' + p);
    a.items = older ? a.items.concat(r.items) : r.items; a.more = r.more;
    if (older) a.pages++;
  } catch (e) { /* the header already says afw is unreachable */ }
  render();
}
// One attacker usually climbs a ladder: watched, then slowed, then blocked.
// The list shows where each one ended up; the steps are in its history.
function steps(items) {
  const out = [];
  for (const d of items) {
    const last = out[out.length - 1];
    if (last && last.d.subject === d.subject && new Date(last.d.ts) - new Date(d.ts) < 15 * 60000) { last.earlier++; last.review = last.review || d.escalated; }
    else out.push({ d, earlier: 0, review: d.escalated });
  }
  return out;
}
function viewActivity() {
  const a = S.act, mode = S.st ? S.st.mode : 'enforce';
  paint($('filters'), a.show, () => SHOW.map(([id, name]) => h('button', { 'aria-pressed': String(a.show === id), 'data-k': 'show:' + id, onclick: () => { a.show = id; a.pages = 1; loadActivity(); } }, name)));
  paint($('act'), JSON.stringify([a.items.length, a.items[0], a.items[a.items.length - 1], a.more, a.pages, mode]), () => {
    if (!a.items.length) return empty(a.q || a.show ? 'No decisions match.' : 'afw has not made any decisions yet.',
      a.q || a.show ? h('button', { onclick: () => { a.q = ''; a.show = ''; $('find').value = ''; loadActivity(); } }, 'Clear filters') : h('p', { class: 'dim' }, 'They appear here as soon as something suspicious happens.'));
    return [a.pages > 1 ? h('p', { class: 'note' }, 'Showing older decisions, so this list is not refreshing. ', h('button', { class: 'quiet', onclick: () => { a.pages = 1; loadActivity(); } }, 'Back to latest')) : null,
      h('ul', { class: 'list' }, steps(a.items).map(({ d, earlier, review }) => h('li', {}, h('button', { class: 'item', 'data-k': 'dec:' + d.id, onclick: e => openSource(d.subject, e.currentTarget) },
        h('span', { class: 'when' }, when(d.ts)),
        h('span', { class: 'who' }, d.subject),
        h('span', { class: 'what' }, actionTag(d.action, d.mode)),
        h('span', { class: 'why' }, d.class ? h('b', {}, className(d.class) + '. ') : null, cap(d.reason)),
        h('span', { class: 'end' }, d.action !== 'allow' && d.action !== 'observe' && d.ttl ? 'for ' + ttlWords(d.ttl) : '',
          earlier ? h('span', { class: 'sub' }, plural(earlier, 'earlier step', 'earlier steps')) : null,
          review ? h('span', { class: 'sub warn' }, 'to review') : null))))),
      a.more ? h('div', { class: 'row-actions' }, h('button', { 'data-k': 'older', onclick: () => loadActivity(true) }, 'Show older')) : null];
  });
}

// ---- Coverage --------------------------------------------------------------
const YN = { yes: 'Yes', partial: 'Partly', no: 'No' };
function viewCoverage() {
  const c = S.cov;
  if (!c) return h('p', { class: 'loading' }, 'Loading coverage.');
  const all = c.attack_universe;
  const seen = all.filter(r => r.seen > 0).sort((x, y) => y.seen - x.seen);
  const gaps = all.filter(r => r.see !== 'yes' || r.act !== 'yes');
  const quiet = all.filter(r => r.see === 'yes' && r.act === 'yes' && !r.seen);
  const tag = v => h('span', { class: 'tag ' + v }, YN[v] || v);
  const assets = c.assets.slice(0, S.allAssets ? 500 : 12);
  return [
    h('h2', {}, 'Seen here'),
    !seen.length ? empty('No attacks have been seen yet.') : h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Attack'), h('th', {}, 'afw stops it'), h('th', { class: 'num' }, 'Times'))),
      h('tbody', {}, seen.map(r => h('tr', {}, h('td', {}, className(r.class)), h('td', {}, tag(r.act)), h('td', { class: 'num' }, num(r.seen))))))),

    h('h2', {}, 'What afw cannot fully handle on its own'),
    h('p', { class: 'note' }, 'Listed on purpose, so the gaps are known rather than discovered in an incident.'),
    h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Attack'), h('th', {}, 'Sees it'), h('th', {}, 'Stops it'))),
      h('tbody', {}, gaps.map(r => h('tr', {}, h('td', {}, className(r.class)), h('td', {}, tag(r.see)), h('td', {}, tag(r.act))))))),

    quiet.length ? [h('h2', {}, 'Handled, not seen here yet'), h('p', { class: 'note' }, quiet.map(r => className(r.class)).join(', ') + '.')] : null,

    h('h2', {}, 'What is being targeted'),
    !c.assets.length ? empty('Nothing has been targeted yet.') : [
      h('p', { class: 'note' }, 'Your services and devices, with the ones seeing the most new sources first.'),
      h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Service or device'), h('th', { class: 'num' }, 'Connections, last hour'), h('th', { class: 'num' }, 'Different sources'), h('th', {}, 'Pattern'), h('th', {}, 'Attacks seen'))),
        h('tbody', {}, assets.map(a => h('tr', {}, h('td', {}, assetLabel(a.asset)), h('td', { class: 'num' }, num(a.flows_last_hour)), h('td', { class: 'num' }, num(a.source_ranges)),
          h('td', {}, a.discovery.state === 'saturating' ? 'A settled crowd' : a.discovery.state === 'scaling' ? 'New sources keep arriving' : a.saturation < 0.5 && a.flows_last_hour ? 'Mostly new sources' : h('span', { class: 'dim' }, 'too early to say')),
          h('td', {}, Object.keys(a.classes || {}).length ? Object.keys(a.classes).map(className).join(', ') : h('span', { class: 'dim' }, 'none'))))))),
      c.assets.length > assets.length ? h('div', { class: 'row-actions' }, h('button', { onclick: () => { S.allAssets = true; repaint(); } }, 'Show all ' + num(c.assets.length))) : null],
  ];
}

// ---- System ----------------------------------------------------------------
const FEED = { drop: 'blocks', throttle: 'slows', observe: 'adds suspicion', benign: 'marks research scanners' };
function viewSystem() {
  const y = S.sys, st = S.st;
  if (!y || !st) return h('p', { class: 'loading' }, 'Loading system details.');
  const s = y.status, ro = st.read_only, out = [];
  if (S.flash) out.push(h('div', { class: 'banner', role: 'status' }, S.flash));
  const fact = (k, v) => [h('dt', {}, k), h('dd', {}, v)];
  const sens = s.sensors, enf = s.enforcer || {}, press = (s.engine || {}).pressure || {}, dec = s.decoys, adv = s.adviser || {}, x = s.crosstalk;

  out.push(h('h2', {}, 'Health'), h('dl', { class: 'facts' },
    fact('Traffic', sens ? [h('span', { class: sens.overflow ? 'warn' : 'good' }, sens.overflow ? 'Overloaded at some point. ' : 'Seeing traffic. '),
      num(sens.nflog_packets) + ' new connections sampled, ' + num(sens.conntrack_events) + ' connection events' + (sens.overflow ? ', ' + num(sens.overflow) + ' not examined' : '') + '.']
      : h('span', { class: 'dim' }, 'No live sensors on this machine.')),
    fact('Right now', num(Math.round(press.NewPerSec || 0)) + ' new incoming connections a second' + (s.posture && s.posture.baseline_per_sec >= 1 ? ' (usual: about ' + num(Math.round(s.posture.baseline_per_sec)) + ')' : '') + '.'),
    fact('Firewall rules', s.enforcer_error ? h('span', { class: 'bad' }, 'afw cannot read its own rules: ' + s.enforcer_error)
      : st.mode !== 'enforce' ? 'Watch-only: no blocking rules are installed.'
      : 'Stopped so far: ' + num(enf.drop_verdict_packets) + ' packets from blocked sources, ' + num(enf.drop_reputation_packets) + ' from threat lists, ' + num(enf.drop_egress_packets) + ' outgoing to known-bad addresses, ' + num(enf.throttled_packets) + ' slowed' + (enf.breakglass_packets ? ', ' + num(enf.breakglass_packets) + ' turned away in emergency mode' : '') + '.'),
    fact('Decoys', !dec ? h('span', { class: 'dim' }, 'Off. List unused ports under canary in the config to turn them on.')
      : [(dec.ports || []).length ? 'Listening on ' + dec.ports.join(', ') + '. ' : h('span', { class: 'warn' }, 'No decoy port could be opened. '),
        plural(dec.touches, 'touch', 'touches') + ' so far, ' + num(dec.held_now) + ' held right now.', dec.skipped ? ' ' + plural(dec.skipped, 'port was', 'ports were') + ' skipped because something real uses them.' : '']),
    fact('AI adviser', !adv.door ? h('span', { class: 'dim' }, 'Not connected. afw works without one.')
      : [adv.suspended ? h('span', { class: 'bad' }, 'Suspended. ') : h('span', { class: 'good' }, 'Connected. '), num(adv.accepted) + ' suggestions heard, ' + num(adv.refused) + ' refused, ' + plural(adv.strikes, 'strike', 'strikes') + '.']),
    fact('Other afw nodes', !y.peers ? h('span', { class: 'dim' }, 'None linked.') : plural(y.peers, 'node', 'nodes') + ' linked. ' + num((x || {}).accepted) + ' warnings received, ' + num((x || {}).rejected) + ' rejected, ' + num((x || {}).sent) + ' sent.'),
    fact('Limits', (s.budget_denied ? [h('span', { class: 'warn' }, plural(s.budget_denied, 'action was', 'actions were') + ' held back by the safety limit. ')] : ['No action has hit the safety limit. ']).concat(
      s.journal_dropped ? [h('span', { class: 'warn' }, num(s.journal_dropped) + ' log lines dropped.')] : []))));

  out.push(h('h2', {}, 'Threat lists'));
  if (!(s.feeds || []).length) out.push(empty('No threat lists are configured.', h('p', { class: 'dim' }, 'afw works without them. The example config lists eight.')));
  else out.push(h('div', { class: 'scroll' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'List'), h('th', {}, 'What it does'), h('th', { class: 'num' }, 'Entries'), h('th', {}, 'Last updated'))),
    h('tbody', {}, s.feeds.map(f => h('tr', {}, h('td', {}, f.name), h('td', {}, FEED[f.action] || f.action), h('td', { class: 'num' }, num(f.entries)),
      h('td', {}, f.error ? h('span', { class: f.entries ? 'warn' : 'bad' }, (f.entries ? 'Using the last good copy. ' : '') + f.error) : when(f.updated) || h('span', { class: 'dim' }, 'not yet'))))))));

  out.push(h('h2', {}, 'Never blocked'), (s.protected || []).length
    ? h('p', {}, s.protected.map(p => h('span', { class: 'chip' }, p.replace(/\/(32|128)$/, ''))))
    : h('p', { class: 'note warn' }, 'Nothing is protected. Add your router and admin machine under protected in the config.'));

  out.push(h('h2', {}, 'About'), h('dl', { class: 'facts' },
    fact('This machine', s.node + ', protecting ' + (s.role === 'gateway' ? 'everything routed through it' : 'itself')),
    fact('Running for', span(Date.now() - new Date(st.started))), fact('Version', st.version), fact('Full record', h('code', {}, y.log_path))));

  out.push(h('h2', {}, 'Controls'));
  if (ro) { out.push(h('p', { class: 'note' }, 'This view is read-only. Actions are only available on the machine itself.')); return out; }
  out.push(h('dl', { class: 'facts' },
    fact('Blocking', [h('p', { class: 'dim' }, st.mode === 'enforce' ? 'afw is acting on what it sees.' : 'afw is only recording what it would do.'), st.mode === 'enforce'
      ? twoStep('mode:shadow', 'Switch to watch-only', 'Yes, stop blocking', () => act({ action: 'mode', value: 'shadow' }, 'Watch-only. afw is blocking nothing.'))
      : twoStep('mode:enforce', 'Start blocking', 'Yes, start blocking', () => act({ action: 'mode', value: 'enforce' }, 'Blocking is on.'), 'primary')]),
    fact('Emergency mode', [h('p', { class: 'dim' }, 'For a flood: serves known users and your own devices first and limits everyone else. afw turns it on by itself when needed.'), st.posture === 'breakglass'
      ? twoStep('bg:off', 'Turn off', 'Yes, turn it off', () => act({ action: 'breakglass', value: 'off' }, 'Emergency mode was turned off.'))
      : twoStep('bg:on', 'Turn on for an hour', 'Yes, turn it on', () => act({ action: 'breakglass', value: 'on' }, 'Emergency mode is on for an hour.'))]),
    fact("Remove afw's rules", S.armed === 'panic'
      ? h('div', {}, h('p', { class: 'sec' }, 'This deletes every afw rule and stops afw. Nothing will be filtered. Type remove to confirm.'),
        h('div', { class: 'row-actions' }, h('input', { type: 'text', id: 'sure', 'aria-label': 'Type remove to confirm', autocomplete: 'off', 'data-k': 'sure' }),
          h('button', { class: 'danger', 'data-k': 'panic', onclick: () => { if ($('sure').value.trim().toLowerCase() === 'remove') act({ action: 'panic' }, 'afw removed all its rules and stopped.'); else $('sure').focus(); } }, 'Remove all rules and stop'),
          h('button', { onclick: () => { S.armed = null; repaint(); } }, 'Cancel')))
      : [h('p', { class: 'dim' }, 'The off switch. Deletes everything afw put in the firewall and stops it.'), h('button', { 'data-k': 'panic', onclick: () => { S.armed = 'panic'; repaint(); } }, 'Remove all rules and stop')])));
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
    const body = [h('div', { class: 'panel-head' }, h('h1', { id: 'panel-title' }, v ? v.subject : addr), h('button', { id: 'close', 'data-k': 'close', 'aria-label': 'Close', onclick: closeSource }, 'Close'))];
    if (err) return body.concat(empty(err));
    const r = v.restricted, would = st.mode !== 'enforce', key = 'punblock:' + v.subject;
    body.push(h('p', { class: 'note' }, r ? [actionTag(r.action, st.mode), ' until ' + when(r.until) + ' (' + endsIn(r.until) + ').'] : 'Not restricted right now.'));
    if (v.protected) body.push(h('p', { class: 'note good' }, 'Protected: afw will never restrict this address.'));
    if (v.known_user) body.push(h('p', { class: 'note good' }, 'Regular user: only proven evidence counts against it.'));
    if (v.inside) body.push(h('p', { class: 'note' }, 'Inside your network: afw watches it and tells you, but does not block it.'));
    if (r && st.mode && !st.read_only && !would) body.push(h('div', { class: 'row-actions' }, S.armed !== key
      ? h('button', { 'data-k': key, onclick: () => { S.armed = key; showSource(addr); } }, 'Unblock')
      : [h('button', { class: 'primary', 'data-k': key, onclick: async () => { await act({ action: 'unblock', subject: v.subject }, v.subject + ' was unblocked and will be left alone for an hour.'); showSource(addr); } }, 'Unblock for 1 hour'),
        h('button', { 'data-k': key + ':no', onclick: () => { S.armed = null; showSource(addr); } }, 'Cancel')]));
    if (!v.known && !r) body.push(empty('afw has no record of this address.'));
    if (v.latest) {
      const l = v.latest, at = (l.summary || '').indexOf(l.reason);
      const extra = at >= 0 ? l.summary.slice(at + l.reason.length).replace(/^\./, '').trim() : '';
      body.push(h('h2', {}, 'Why'), h('div', { class: 'card' },
        h('h3', {}, l.class ? className(l.class) : 'Decision'),
        (l.signals || []).length ? h('ul', { class: 'evidence' }, l.signals.map(g => h('li', {}, cap(g.detail || g.name) + '.', g.spoofable ? [' ', h('span', { class: 'faked' }, 'could be faked')] : null))) : h('p', {}, cap(l.reason)),
        extra ? h('p', { class: 'dim' }, extra) : null));
    }
    const kinds = (v.classes || []).filter(c => !v.classes.some(o => o !== c && o.startsWith(c) && c.includes('chain.')));
    if (kinds.length > 1) body.push(h('h2', {}, 'Everything it has done'), h('p', {}, kinds.map(c => h('span', { class: 'chip label' }, className(c)))));
    if (v.timeline.length) body.push(h('h2', {}, 'History'), h('ul', { class: 'timeline' }, v.timeline.map(t => h('li', {},
      h('span', { class: 'when' }, when(t.ts)), t.kind === 'decision'
        ? [actionTag(t.action, st.mode), t.action !== 'allow' && t.action !== 'observe' && t.ttl ? ' for ' + ttlWords(t.ttl) + '. ' : ' ', cap(t.text)]
        : ['Passed up for review. ', h('span', { class: 'sec' }, t.text.replace(/^\[[^\]]*\]\s*/, ''))]))));
    if (v.known) body.push(h('p', { class: 'note dim' }, 'First seen ' + when(v.first) + ', last seen ' + when(v.last) + '.'));
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
    S.view = r.view; S.armed = null; S.flash = S.flash && S.justActed ? S.flash : null; S.painted = {};
    main.replaceChildren(...(r.view === 'activity' ? shellActivity() : [h('div', { id: 'body' })]));
    window.scrollTo(0, 0);
  }
  S.justActed = false;
  const half = Math.floor(Date.now() / 30000); // countdowns move on even when nothing else changes
  if (r.view === 'now') paint($('body'), JSON.stringify([S.st && Object.assign({}, S.st, { now: 0 }), S.armed, S.flash, half]), viewNow);
  else if (r.view === 'activity') viewActivity();
  else if (r.view === 'coverage') paint($('body'), JSON.stringify([S.cov, S.allAssets]), viewCoverage);
  else paint($('body'), JSON.stringify([S.sys, S.st && S.st.mode, S.st && S.st.posture, S.armed, S.flash]), viewSystem);
}
async function tick(acted) {
  if (!token) return gate();
  if (acted) S.justActed = true;
  const view = route().view;
  try {
    S.st = await api('/api/state');
    S.okAt = Date.now(); S.failing = false;
    if (view === 'activity' && S.act.pages === 1) { const p = new URLSearchParams({ show: S.act.show, q: S.act.q }); const r = await api('/api/activity?' + p); S.act.items = r.items; S.act.more = r.more; }
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
