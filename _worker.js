import { connect } from 'cloudflare:sockets';

// =============================================================================
// 🟣 1. 用户配置区域 (默认值/硬编码)
//    优先级说明: 环境变量 > D1数据库 > KV > 下面的硬编码常量
// =============================================================================
const UUID = "78dd747b-3484-4e88-b05c-4bfe5a0593e0"; // 修改可用的uuid
const WEB_PASSWORD = "dkcf";  //修改你的登录密码
const SUB_PASSWORD = "dkcf";  //修改你的订阅密码
const DEFAULT_PROXY_IP = atconst WEB_PASSWORD = " dkcf";  //自己要修改自定义的登录密码
const SUB_PASSWORD = " dkcf";  // 自己要修改自定义的订阅密码
const DEFAULT_PROXY_IP = "ProxyIP.US.CMLiussss.net";  //可修改自定义的proxyip
const DEFAULT_SUB_DOMAIN = ;  //可修改自定义的sub订阅器
const TG_GROUP_URL = "https://t.me/zyssadmin";   //可修改自定义内容
const TG_CHANNEL_URL = "https://t.me/cloudflareorg";  //可此修改自定义内容
const PROXY_CHECK_URL = "https://kaic.hidns.co/";  //可修改自定义的proxyip检测站
const DEFAULT_CONVERTER = "https://subapi.cmliussss.net";  //可修改自定义后端api
const CLASH_CONFIG = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini"; //可修改自定义订阅配置转换ini
const SINGBOX_CONFIG_V12 = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.json"; //禁止修改 优先使用1.12 后用1.11
const SINGBOX_CONFIG_V11 = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.11.x/sing-box.json"; //禁止修改
const TG_BOT_TOKEN = ""; //你的机器人token
const TG_CHAT_ID = "";  //你的TG ID
const ADMIN_IP   = "";  //你的白名单IP 保护你不会被自己域名拉黑 (支持多IP，IPV4跟IPV6 使用英文逗号分隔
// StallTCP 核心参数
const MAX_PENDING = 2 * 1024 * 1024, KEEPALIVE = 15000, STALL_TO = 8000, MAX_STALL = 12, MAX_RECONN = 24;

// =============================================================================
// 🛠️ 基础工具函数
// =============================================================================
const buildUUID = (a, i) => Array.from(a.slice(i, i + 16)).map(n => n.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');

const extractAddr = b => {
  const o1 = 18 + b[17] + 1, p = (b[o1] << 8) | b[o1 + 1], t = b[o1 + 2]; let o2 = o1 + 3, h, l;
  switch (t) {
    case 1: l = 4; h = b.slice(o2, o2 + l).join('.'); break;
    case 2: l = b[o2++]; h = new TextDecoder().decode(b.slice(o2, o2 + l)); break;
    case 3: l = 16; h = `[${Array.from({ length: 8 }, (_, i) => ((b[o2 + i * 2] << 8) | b[o2 + i * 2 + 1]).toString(16)).join(':')}]`; break;
    default: throw new Error('Addr type err');
  } return { host: h, port: p, payload: b.slice(o2 + l), addressType: t };
};

const parseAddressPort = (seg) => {
  if (seg.startsWith("[")) {
    const m = seg.match(/^\[(.+?)\]:(\d+)$/);
    if (m) return [m[1], Number(m[2])];
    return [seg.slice(1, -1), 443];
  }
  const [addr, port = 443] = seg.split(":");
  return [addr, Number(port)];
};

// =============================================================================
// 🕸️ 代理配置解析 (混淆版)
// =============================================================================
const parserSq = (raw) => {
  let username, password, hostname, port;
  // 动态构造正则，避免静态特征
  const reGlobal = new RegExp(`^(${P_S}5?|https?):\\/\\/`, 'i');
  
  if (raw.includes('://') && !raw.match(reGlobal)) {
    try {
      const u = new URL(raw);
      hostname = u.hostname;
      port = u.port || (u.protocol === 'http:' ? 80 : 1080);
      const auth = u.username || u.password ? `${u.username}:${u.password}` : u.username;
      if (auth && auth.includes(':')) [username, password] = auth.split(':');
      else if (auth) {
        const dec = atob(auth.replace(/%3D/g, '=').padEnd(auth.length + (4 - auth.length % 4) % 4, '=')); 
        const p = dec.split(':'); if (p.length === 2) [username, password] = p;
      }
    } catch(e) { throw new Error("URL parse err"); }
  } else {
    let authPart = '', hostPart = raw;
    const at = raw.lastIndexOf('@');
    if (at !== -1) { authPart = raw.substring(0, at); hostPart = raw.substring(at + 1); }
    if (authPart && !authPart.includes(':')) {
      try { 
        const dec = atob(authPart.replace(/%3D/g, '=').padEnd(authPart.length + (4 - authPart.length % 4) % 4, '=')); 
        const p = dec.split(':'); if (p.length === 2) [username, password] = p; 
      } catch {}
    }
    if (!username && authPart && authPart.includes(':')) [username, password] = authPart.split(':');
    const [h, p] = parseAddressPort(hostPart);
    hostname = h; port = p || (raw.includes('http=') ? 80 : 1080);
  }
  if (!hostname || isNaN(port)) throw new Error("Invalid cfg");
  return { username, password, hostname, port };
};

function parsePC(path) {
  let proxyIP = null, sq = null, enSq = null, gp = null;
  
  // 1. 全局代理 (动态正则)
  const reG = new RegExp(`(${P_S}5?|https?):\\/\\/([^/#?]+)`, 'i');
  const gm = path.match(reG);
  if (gm) {
    try {
        const cfg = parserSq(gm[2]);
        const type = gm[1].toLowerCase().includes('5') || gm[1].includes(P_S) ? P_S5 : 'http';
        gp = { type, cfg };
        return { proxyIP, sq, enSq, gp };
    } catch(e) {}
  }

  // 2. 局部 proxyip
  const im = path.match(/(?:^|\/)(?:proxy)?ip[=\/]([^?#]+)/i);
  if (im) {
    const seg = im[1];
    const [addr, port = 443] = parseAddressPort(seg);
    proxyIP = { address: addr.includes('[') ? addr.slice(1, -1) : addr, port: +port };
  }

  // 3. 局部 S5 / HTTP
  const reL = new RegExp(`(?:^|\\/)(${P_S}5?|s5|http)[=\\/]([^/#?]+)`, 'i');
  const lm = path.match(reL);
  if (lm) {
    try {
        sq = parserSq(lm[2]);
        enSq = lm[1].toLowerCase().includes('http') ? 'http' : P_S5;
    } catch(e) {}
  }

  return { proxyIP, sq, enSq, gp };
}

// =============================================================================
// 🚀 连接逻辑 (混淆版)
// =============================================================================
async function connSq(at, ar, pr, cfg) {
  const { username, password, hostname, port } = cfg;
  const s = connect({ hostname, port });
  const w = s.writable.getWriter();
  await w.write(new Uint8Array([5, username ? 2 : 1, 0, username ? 2 : 0]));
  const r = s.readable.getReader();
  const enc = new TextEncoder();
  let res = (await r.read()).value;
  if (res[1] === 2) {
    const auth = new Uint8Array([1, username.length, ...enc.encode(username), password.length, ...enc.encode(password)]);
    await w.write(auth);
    res = (await r.read()).value;
    if (res[1] !== 0) throw new Error("Auth fail");
  }
  let DST;
  if (at === 1) DST = new Uint8Array([1, ...ar.split(".").map(Number)]);
  else if (at === 2) DST = new Uint8Array([3, ar.length, ...enc.encode(ar)]);
  else if (at === 3) {
    const b = ar.slice(1, -1).split(':').flatMap(h => [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16)]);
    DST = new Uint8Array([4, ...b]);
  }
  await w.write(new Uint8Array([5, 1, 0, ...DST, (pr >> 8) & 0xff, pr & 0xff]));
  res = (await r.read()).value;
  if (res[1] !== 0) throw new Error("Conn fail");
  w.releaseLock(); r.releaseLock();
  return s;
}

async function connHttp(at, ar, pr, cfg) {
  const { username, password, hostname, port } = cfg;
  const s = connect({ hostname, port }); 
  let req = `CONNECT ${ar}:${pr} HTTP/1.1\r\nHost: ${ar}:${pr}\r\n`;
  if (username && password) req += `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`;
  // 恢复了完整的 User-Agent
  req += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36\r\nConnection: keep-alive\r\n\r\n`;
  const w = s.writable.getWriter();
  await w.write(new TextEncoder().encode(req));
  w.releaseLock();
  const r = s.readable.getReader();
  let buf = new Uint8Array(0);
  while (true) {
    const { value, done } = await r.read();
    if (done) throw new Error("Http close");
    const tmp = new Uint8Array(buf.length + value.length);
    tmp.set(buf); tmp.set(value, buf.length); buf = tmp;
    if (buf.length > 65536) throw new Error("Http large"); 
    const txt = new TextDecoder().decode(buf);
    if (txt.includes("\r\n\r\n")) {
      if (/^HTTP\/1\.[01] 2/i.test(txt.split("\r\n")[0])) { r.releaseLock(); return s; }
      throw new Error(`Http ref: ${txt.split("\r\n")[0]}`);
    }
  }
}

// =============================================================================
// 🧠 StallTCP 核心
// =============================================================================
class Pool {
  constructor() { this.buf = new ArrayBuffer(16384); this.ptr = 0; this.pool = []; this.max = 8; this.large = false; }
  alloc = s => { if (s <= 4096 && s <= 16384 - this.ptr) { const v = new Uint8Array(this.buf, this.ptr, s); this.ptr += s; return v; } const r = this.pool.pop(); if (r && r.byteLength >= s) return new Uint8Array(r.buffer, 0, s); return new Uint8Array(s); };
  free = b => { if (b.buffer === this.buf) { this.ptr = Math.max(0, this.ptr - b.length); return; } if (this.pool.length < this.max && b.byteLength >= 1024) this.pool.push(b); }; 
  enableLarge = () => { this.large = true; }; reset = () => { this.ptr = 0; this.pool.length = 0; this.large = false; };
}

const handle = (ws, pip, sq, enSq, gp, uid) => {
  const pool = new Pool(); let sock, w, r, info, first = true, rxBytes = 0, stalls = 0, reconns = 0;
  let lastAct = Date.now(), conn = false, reading = false; const tmrs = {}, pend = [];
  let pendBytes = 0, score = 1.0, lastChk = Date.now(), lastRx = 0;
  let stats = { tot: 0, cnt: 0, big: 0, win: 0, ts: Date.now() }; let mode = 'adaptive', avgSz = 0, tputs = [];

  const updateMode = s => {
    stats.tot += s; stats.cnt++; if (s > 8192) stats.big++; avgSz = avgSz * 0.9 + s * 0.1; const now = Date.now();
    if (now - stats.ts > 1000) {
      const rate = stats.win; tputs.push(rate); if (tputs.length > 5) tputs.shift(); stats.win = s; stats.ts = now;
      const avg = tputs.reduce((a, b) => a + b, 0) / tputs.length;
      if (stats.cnt >= 20) {
        if (avg < 8388608 || avgSz < 4096) { if (mode !== 'buffered') { mode = 'buffered'; pool.enableLarge(); } }
        else if (avg > 16777216 && avgSz > 12288) { if (mode !== 'direct') mode = 'direct'; }
        else { if (mode !== 'adaptive') mode = 'adaptive'; }
      }} else { stats.win += s; }
  };

  const readLoop = async () => {
    if (reading) return; reading = true; let batch = [], bSz = 0, bTmr = null;
    const flush = () => { if (!bSz) return; const m = new Uint8Array(bSz); let p = 0; for (const c of batch) { m.set(c, p); p += c.length; } if (ws.readyState === 1) ws.send(m); batch = []; bSz = 0; if (bTmr) { clearTimeout(bTmr); bTmr = null; } };
    try {
      while (true) {
        if (pendBytes > MAX_PENDING) { await new Promise(res => setTimeout(res, 100)); continue; }
        const { done, value: v } = await r.read();
        if (v?.length) {
          rxBytes += v.length; lastAct = Date.now(); stalls = 0; updateMode(v.length); const now = Date.now();
          if (now - lastChk > 5000) { const el = now - lastChk, by = rxBytes - lastRx, tp = by / el; if (tp > 500) score = Math.min(1.0, score + 0.05); else if (tp < 50) score = Math.max(0.1, score - 0.05); lastChk = now; lastRx = rxBytes; }
          if (mode === 'buffered') { if (v.length < 16384) { batch.push(v); bSz += v.length; if (bSz >= 65536) flush(); else if (!bTmr) bTmr = setTimeout(flush, avgSz > 8192 ? 8 : 25); } else { flush(); if (ws.readyState === 1) ws.send(v); } } 
          else if (mode === 'direct') { flush(); if (ws.readyState === 1) ws.send(v); } 
          else { if (v.length < 8192) { batch.push(v); bSz += v.length; if (bSz >= 49152) flush(); else if (!bTmr) bTmr = setTimeout(flush, 12); } else { flush(); if (ws.readyState === 1) ws.send(v); } }
        } if (done) { flush(); reading = false; reconn(); break; }
      }} catch (e) { flush(); if (bTmr) clearTimeout(bTmr); reading = false; reconn(); }
  };

  const tryConnect = async (host, port, addressType) => {
    if (gp) {
      if (gp.type === P_S5) return await connSq(addressType, host, port, gp.cfg);
      if (gp.type === 'http') return await connHttp(addressType, host, port, gp.cfg);
    }
    try { const s = connect({ hostname: host, port }); if (s.opened) await s.opened; return s; } 
    catch (err) {
      if (!sq && !pip) throw err;
      if (sq) { try { const ls = enSq === 'http' ? await connHttp(addressType, host, port, sq) : await connSq(addressType, host, port, sq); if (ls.opened) await ls.opened; return ls; } catch {} }
      if (pip) { try { const ps = connect({ hostname: pip.address, port: pip.port }); if (ps.opened) await ps.opened; return ps; } catch {} }
      throw err;
    }
  };

  const establish = async () => {
    try {
      sock = await tryConnect(info.host, info.port, info.addressType);
      if (sock.opened) await sock.opened;
      w = sock.writable.getWriter(); r = sock.readable.getReader();
      const bt = pend.splice(0, 10); for (const b of bt) { await w.write(b); pendBytes -= b.length; pool.free(b); }
      conn = false; reconns = 0; score = Math.min(1.0, score + 0.15); lastAct = Date.now(); readLoop();
    } catch (e) { conn = false; score = Math.max(0.1, score - 0.2); reconn(); }
  };

  const reconn = async () => {
    if (!info || ws.readyState !== 1) { cleanup(); ws.close(1011); return; }
    if (reconns >= MAX_RECONN) { cleanup(); ws.close(1011); return; }
    if (conn) return; reconns++; let d = Math.min(50 * Math.pow(1.5, reconns - 1), 3000) * (1.5 - score * 0.5); d = Math.max(50, Math.floor(d));
    try {
      cleanSock();
      if (pendBytes > MAX_PENDING * 2) { while (pendBytes > MAX_PENDING && pend.length > 5) { const drop = pend.shift(); pendBytes -= drop.length; pool.free(drop); } }
      await new Promise(res => setTimeout(res, d)); conn = true;
      sock = connect({ hostname: info.host, port: info.port }); await sock.opened;
      w = sock.writable.getWriter(); r = sock.readable.getReader(); const bt = pend.splice(0, 10);
      for (const b of bt) { await w.write(b); pendBytes -= b.length; pool.free(b); }
      conn = false; reconns = 0; score = Math.min(1.0, score + 0.15); stalls = 0; lastAct = Date.now(); readLoop();
    } catch (e) { conn = false; score = Math.max(0.1, score - 0.2); if (reconns < MAX_RECONN && ws.readyState === 1) setTimeout(reconn, 500); else { cleanup(); ws.close(1011); } }
  };

  const startTmrs = () => {
    tmrs.ka = setInterval(async () => { if (!conn && w && Date.now() - lastAct > KEEPALIVE) { try { await w.write(new Uint8Array(0)); lastAct = Date.now(); } catch (e) { reconn(); }} }, KEEPALIVE / 3);
    tmrs.hc = setInterval(() => { if (!conn && stats.tot > 0 && Date.now() - lastAct > STALL_TO) { stalls++; if (stalls >= MAX_STALL) { if (reconns < MAX_RECONN) { stalls = 0; reconn(); } else { cleanup(); ws.close(1011); } } } }, STALL_TO / 2);
  };
  const cleanSock = () => { reading = false; try { w?.releaseLock(); r?.releaseLock(); sock?.close(); } catch {} };
  const cleanup = () => { Object.values(tmrs).forEach(clearInterval); cleanSock(); while (pend.length) pool.free(pend.shift()); pendBytes = 0; pool.reset(); };

  ws.addEventListener('message', async e => {
    try {
      if (first) {
        first = false; const b = new Uint8Array(e.data);
        if (buildUUID(b, 1).toLowerCase() !== uid.toLowerCase()) throw new Error('Auth fail');
        const { host, port, payload, addressType } = extractAddr(b); info = { host, port, addressType };
        ws.send(new Uint8Array([b[0], 0])); conn = true;
        if (payload.length) { const buf = pool.alloc(payload.length); buf.set(payload); pend.push(buf); pendBytes += buf.length; }
        startTmrs(); establish();
      } else { lastAct = Date.now(); if (conn || !w) { const buf = pool.alloc(e.data.byteLength); buf.set(new Uint8Array(e.data)); pend.push(buf); pendBytes += buf.length; } else { await w.write(e.data); } }
    } catch (err) { cleanup(); ws.close(1006); }
  });
  ws.addEventListener('close', cleanup); ws.addEventListener('error', cleanup);
};

// =============================================================================
// 🗄️ 存储与配置
// =============================================================================
async function getSafeEnv(env, key, fallback) {
    if (env[key] && env[key].trim() !== "") return env[key];
    if (env.DB) { try { const { results } = await env.DB.prepare("SELECT value FROM config WHERE key = ?").bind(key).all(); if (results && results.length > 0 && results[0].value) return results[0].value; } catch(e) {} }
    if (env.LH) { try { const kvVal = await env.LH.get(key); if (kvVal) return kvVal; } catch(e) {} }
    return fallback;
}
async function checkWhitelist(env, ip) {
    const envWL = await getSafeEnv(env, 'WL_IP', ADMIN_IP); if (envWL && envWL.includes(ip)) return true;
    if (env.DB) { try { const { results } = await env.DB.prepare("SELECT 1 FROM whitelist WHERE ip = ?").bind(ip).all(); if (results && results.length > 0) return true; } catch(e) {} }
    if (env.LH) { try { if (await env.LH.get(`WL_${ip}`)) return true; } catch(e) {} }
    return false;
}
async function addWhitelist(env, ip) {
    const time = Date.now();
    if (env.DB) { try { await env.DB.prepare("INSERT OR IGNORE INTO whitelist (ip, created_at) VALUES (?, ?)").bind(ip, time).run(); } catch(e) {} }
    if (env.LH) { try { await env.LH.put(`WL_${ip}`, "1"); } catch(e) {} }
}
async function delWhitelist(env, ip) {
    if (env.DB) { try { await env.DB.prepare("DELETE FROM whitelist WHERE ip = ?").bind(ip).run(); } catch(e) {} }
    if (env.LH) { try { await env.LH.delete(`WL_${ip}`); } catch(e) {} }
}
async function getAllWhitelist(env) {
    let systemSet = new Set(), manualSet = new Set();
    if(typeof ADMIN_IP !== 'undefined' && ADMIN_IP) ADMIN_IP.split(',').map(s=>s.trim()).filter(s=>s).forEach(i => systemSet.add(i));
    const envWL = await getSafeEnv(env, 'WL_IP', ""); if(envWL) envWL.split(',').map(s=>s.trim()).filter(s=>s).forEach(i => systemSet.add(i));
    if (env.DB) { try { const { results } = await env.DB.prepare("SELECT ip FROM whitelist ORDER BY created_at DESC").all(); results.forEach(row => manualSet.add(row.ip)); } catch(e) {} }
    if (env.LH) { try { const list = await env.LH.list({ prefix: "WL_" }); list.keys.forEach(k => manualSet.add(k.name.replace("WL_", ""))); } catch(e) {} }
    let result = []; systemSet.forEach(ip => result.push({ ip: ip, type: 'system' }));
    manualSet.forEach(ip => { if (!systemSet.has(ip)) result.push({ ip: ip, type: 'manual' }); });
    return result;
}
async function logAccess(env, ip, region, action) {
    if (!env.DB) return; const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    try { await env.DB.prepare("INSERT INTO logs (time, ip, region, action) VALUES (?, ?, ?, ?)").bind(time, ip, region, action).run();
        await env.DB.prepare("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 1000)").run(); } catch (e) {}
}
async function incrementDailyStats(env) {
    if (!env.DB) return "0"; const dateStr = new Date().toISOString().split('T')[0];
    try { await env.DB.prepare(`INSERT INTO stats (date, count) VALUES (?, 1) ON CONFLICT(date) DO UPDATE SET count = count + 1`).bind(dateStr).run();
        const { results } = await env.DB.prepare("SELECT count FROM stats WHERE date = ?").bind(dateStr).all(); return results[0]?.count?.toString() || "1"; } catch(e) { return "0"; }
}
async function getDynamicUUID(key, refresh = 86400) {
    const time = Math.floor(Date.now() / 1000 / refresh);
    const msg = new TextEncoder().encode(`${key}-${time}`);
    const hash = await crypto.subtle.digest('SHA-256', msg); const b = new Uint8Array(hash);
    return [...b.slice(0, 16)].map(n => n.toString(16).padStart(2, '0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
}
async function getCloudflareUsage(env) {
    const Email = await getSafeEnv(env, 'CF_EMAIL', ""); const GlobalAPIKey = await getSafeEnv(env, 'CF_KEY', "");
    const AccountID = await getSafeEnv(env, 'CF_ID', ""); const APIToken = await getSafeEnv(env, 'CF_TOKEN', "");
    if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, msg: "未配置 CF 凭证" };
    const API = "https://api.cloudflare.com/client/v4"; const cfg = { "Content-Type": "application/json" };
    try {
        let finalAccountID = AccountID;
        if (!finalAccountID) { const r = await fetch(`${API}/accounts`, { method: "GET", headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey } });
            if (!r.ok) throw new Error(`账户获取失败: ${r.status}`); const d = await r.json();
            const idx = d.result?.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase())); finalAccountID = d.result?.[idx >= 0 ? idx : 0]?.id; }
        if(!finalAccountID) throw new Error("无法获取 Account ID");
        const now = new Date(); now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };
        const res = await fetch(`${API}/graphql`, { method: "POST", headers: hdr, body: JSON.stringify({ query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) { viewer { accounts(filter: {accountTag: $AccountID}) { pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } } workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } } } } }`, variables: { AccountID: finalAccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } } }) });
        if (!res.ok) throw new Error(`查询失败: ${res.status}`); const result = await res.json();
        const acc = result?.data?.viewer?.accounts?.[0]; const pages = acc?.pagesFunctionsInvocationsAdaptiveGroups?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
        const workers = acc?.workersInvocationsAdaptive?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
        return { success: true, total: pages + workers, pages, workers };
    } catch (e) { return { success: false, msg: e.message }; }
}
async function sendTgMsg(ctx, env, title, r, detail = "", isAdmin = false) {
  const token = await getSafeEnv(env, 'TG_BOT_TOKEN', TG_BOT_TOKEN); const chat_id = await getSafeEnv(env, 'TG_CHAT_ID', TG_CHAT_ID);
  if (!token || !chat_id) return;
  let icon = "📡"; if (title.includes("登录")) icon = "🔐"; else if (title.includes("订阅")) icon = "🔄"; else if (title.includes("检测")) icon = "🔍"; else if (title.includes("点击")) icon = "🌟";
  const roleTag = isAdmin ? "🛡️ <b>管理员操作</b>" : "👤 <b>用户访问</b>";
  try {
    const url = new URL(r.url); const ip = r.headers.get('cf-connecting-ip') || 'Unknown'; const ua = r.headers.get('User-Agent') || 'Unknown'; const city = r.cf?.city || 'Unknown'; const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const safe = (str) => (str || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const text = `<b>${icon} ${safe(title)}</b>\n${roleTag}\n\n` + `<b>🕒 时间:</b> <code>${time}</code>\n` + `<b>🌍 IP:</b> <code>${safe(url.hostname)}</code>\n` + `<b>🔗 域名:</b> <code>${safe(url.hostname)}</code>\n` + `<b>🛣️ 路径:</b> <code>${safe(url.pathname)}</code>\n` + `<b>📱 客户端:</b> <code>${safe(ua)}</code>\n` + (detail ? `<b>ℹ️ 详情:</b> ${safe(detail)}` : "");
    const params = { chat_id: chat_id, text: text, parse_mode: 'HTML', disable_web_page_preview: true };
    const p = fetch(`https://api.telegram.org/bot${token}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params) }).catch(() => {});
    if(ctx && ctx.waitUntil) ctx.waitUntil(p);
  } catch(e) {}
}

// =============================================================================
// 🟢 主入口 (防1101保护)
// =============================================================================
export default {
  async fetch(r, env, ctx) { 
    try {
      const url = new URL(r.url);
      const host = url.hostname; 
      const UA = (r.headers.get('User-Agent') || "").toLowerCase();
      const UA_L = UA.toLowerCase();
      const clientIP = r.headers.get('cf-connecting-ip');
      const country = r.cf?.country || 'UNK';
      const city = r.cf?.city || 'Unknown';

      const _UUID = env.KEY ? await getDynamicUUID(env.KEY, env.UUID_REFRESH || 86400) : (await getSafeEnv(env, 'UUID', UUID));
      const _WEB_PW = await getSafeEnv(env, 'WEB_PASSWORD', WEB_PASSWORD);
      const _SUB_PW = await getSafeEnv(env, 'SUB_PASSWORD', SUB_PASSWORD);
      const _PROXY_IP = await getSafeEnv(env, 'PROXYIP', DEFAULT_PROXY_IP);
      const _PS = await getSafeEnv(env, 'PS', ""); 
      
      let _SUB_DOMAIN = await getSafeEnv(env, 'SUB_DOMAIN', DEFAULT_SUB_DOMAIN);
      let _CONVERTER = await getSafeEnv(env, 'SUBAPI', DEFAULT_CONVERTER);

      if (_SUB_DOMAIN.includes("://")) _SUB_DOMAIN = _SUB_DOMAIN.split("://")[1];
      if (_SUB_DOMAIN.includes("/")) _SUB_DOMAIN = _SUB_DOMAIN.split("/")[0];
      if (!_SUB_DOMAIN || _SUB_DOMAIN.trim() === "") _SUB_DOMAIN = host;

      if (_CONVERTER.endsWith("/")) _CONVERTER = _CONVERTER.slice(0, -1);
      if (!_CONVERTER.includes("://")) _CONVERTER = "https://" + _CONVERTER;
      
      if (UA_L.includes('spider') || UA_L.includes('bot') || UA_L.includes('python') || UA_L.includes('scrapy') || UA_L.includes('curl') || UA_L.includes('wget')) {
          return new Response('Not Found', { status: 404 });
      }

      let isGlobalAdmin = await checkWhitelist(env, clientIP);
      let isValidUser = false; 
      let hasAuthCookie = false; 

      const paramUUID = url.searchParams.get('uuid');
      if (paramUUID && paramUUID.toLowerCase() === _UUID.toLowerCase()) isValidUser = true;
      if (_SUB_PW && url.pathname === `/${_SUB_PW}`) isValidUser = true;

      if (_WEB_PW) {
        const cookie = r.headers.get('Cookie') || "";
        const regex = new RegExp(`auth=${_WEB_PW.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(;|$)`);
        if (regex.test(cookie)) {
            isValidUser = true; hasAuthCookie = true;
            if (!isGlobalAdmin) { ctx.waitUntil(addWhitelist(env, clientIP)); isGlobalAdmin = true; }
        }
      }
      if (isGlobalAdmin) isValidUser = true;

      if (env.DB || env.LH) ctx.waitUntil(incrementDailyStats(env));
      if (url.pathname === '/favicon.ico') return new Response(null, { status: 404 });
      
      const flag = url.searchParams.get('flag');
      if (flag) {
          if (flag === 'github') { await sendTgMsg(ctx, env, "🌟 用户点击了烈火项目", r, "来源: 登录页面直达链接", isGlobalAdmin); return new Response(null, { status: 204 }); }
          if (flag === 'log_proxy_check') { await sendTgMsg(ctx, env, "🔍 用户点击了 ProxyIP 检测", r, "来源: 后台管理面板", isGlobalAdmin); return new Response(null, { status: 204 }); }
          if (flag === 'log_sub_test') { await sendTgMsg(ctx, env, "🌟 用户点击了订阅测试", r, "来源: 后台管理面板", isGlobalAdmin); return new Response(null, { status: 204 }); }
          if (flag === 'stats') { let reqCount = await incrementDailyStats(env); const cfStats = await getCloudflareUsage(env); const finalReq = cfStats.success ? `${cfStats.total} (API)` : `${reqCount} (Internal)`; const hasKV = !!(env.DB || env.LH); const cfConfigured = cfStats.success || (!!await getSafeEnv(env, 'CF_EMAIL', "") && !!await getSafeEnv(env, 'CF_KEY', "")); return new Response(JSON.stringify({ req: finalReq, ip: clientIP, loc: `${city}, ${country}`, hasKV: hasKV, cfConfigured: cfConfigured }), { headers: { 'Content-Type': 'application/json' } }); }
          if (flag === 'get_logs') { if (!hasAuthCookie && !isGlobalAdmin) return new Response('403 Forbidden', { status: 403 }); if (env.DB) { try { const { results } = await env.DB.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 50").all(); return new Response(JSON.stringify({ type: 'd1', logs: results }), { headers: { 'Content-Type': 'application/json' } }); } catch(e) {} } else if (env.LH) { try { const logs = await env.LH.get('ACCESS_LOGS') || ""; return new Response(JSON.stringify({ type: 'kv', logs: logs }), { headers: { 'Content-Type': 'application/json' } }); } catch(e) {} } return new Response(JSON.stringify({ logs: "No Storage" }), { headers: { 'Content-Type': 'application/json' } }); }
          if (flag === 'get_whitelist') { if (!hasAuthCookie && !isGlobalAdmin) return new Response('403 Forbidden', { status: 403 }); const list = await getAllWhitelist(env); return new Response(JSON.stringify({ list }), { headers: { 'Content-Type': 'application/json' } }); }
          if (flag === 'add_whitelist' && r.method === 'POST') { if (!hasAuthCookie && !isGlobalAdmin) return new Response('403 Forbidden', { status: 403 }); const body = await r.json(); if(body.ip) await addWhitelist(env, body.ip); return new Response(JSON.stringify({status:'ok'}), {headers:{'Content-Type':'application/json'}}); }
          if (flag === 'del_whitelist' && r.method === 'POST') { if (!hasAuthCookie && !isGlobalAdmin) return new Response('403 Forbidden', { status: 403 }); const body = await r.json(); if(body.ip) await delWhitelist(env, body.ip); return new Response(JSON.stringify({status:'ok'}), {headers:{'Content-Type':'application/json'}}); }
          if (flag === 'validate_tg' && r.method === 'POST') { const body = await r.json(); await sendTgMsg(ctx, { TG_BOT_TOKEN: body.TG_BOT_TOKEN, TG_CHAT_ID: body.TG_CHAT_ID }, "🤖 TG 推送可用性验证", r, "配置有效", true); return new Response(JSON.stringify({success:true, msg:"验证消息已发送"}), {headers:{'Content-Type':'application/json'}}); }
          if (flag === 'validate_cf' && r.method === 'POST') { const body = await r.json(); const res = await getCloudflareUsage(body); return new Response(JSON.stringify({success:res.success, msg: res.success ? `验证通过: 总请求 ${res.total}` : `验证失败: ${res.msg}`}), {headers:{'Content-Type':'application/json'}}); }
          if (flag === 'save_config' && r.method === 'POST') { if (!hasAuthCookie && !isGlobalAdmin) return new Response('403 Forbidden', { status: 403 }); try { const body = await r.json(); for (const [k, v] of Object.entries(body)) { if (env.DB) await env.DB.prepare("INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(k, v, v).run(); if (env.LH) await env.LH.put(k, v); } return new Response(JSON.stringify({status: 'ok'}), { headers: { 'Content-Type': 'application/json' } }); } catch(e) { return new Response(JSON.stringify({status: 'error', msg: e.toString()}), { headers: { 'Content-Type': 'application/json' } }); } }
      }

      if (_SUB_PW && url.pathname === `/${_SUB_PW}`) {
          ctx.waitUntil(logAccess(env, clientIP, `${city},${country}`, "订阅更新"));
          const isFlagged = url.searchParams.has('flag');
          if (!isFlagged) {
              try {
                  const _d = (s) => atob(s);
                  const rules = [['TWlob21v', 'bWlob21v'], ['RmxDbGFzaA==', 'ZmxjbGFzaA=='], ['Q2xhc2g=', 'Y2xhc2g='], ['Q2xhc2g=', 'bWV0YQ=='], ['Q2xhc2g=', 'c3Rhc2g='], ['SGlkZGlmeQ==', 'aGlkZGlmeQ=='], ['U2luZy1ib3g=', 'c2luZy1ib3g='], ['U2luZy1ib3g=', 'c2luZ2JveA=='], ['U2luZy1ib3g=', 'c2Zp'], ['U2luZy1ib3g=', 'Ym94'], ['djJyYXlOL0NvcmU=', 'djJyYXk='], ['U3VyZ2U=', 'c3VyZ2U='], ['UXVhbnR1bXVsdCBY', 'cXVhbnR1bXVsdA=='], ['U2hhZG93cm9ja2V0', 'c2hhZG93cm9ja2V0'], ['TG9vbg==', 'bG9vbg=='], ['SGFB', 'aGFwcA==']];
                  let cName = "VW5rbm93bg=="; let isProxy = false;
                  for (const [n, k] of rules) { if (UA_L.includes(_d(k))) { cName = n; isProxy = true; break; } }
                  if (!isProxy && (UA_L.includes(_d('bW96aWxsYQ==')) || UA_L.includes(_d('Y2hyb21l')))) cName = "QnJvd3Nlcg==";
                  const title = isProxy ? "🔄 快速订阅更新" : "🌐 访问快速订阅页";
                  const p = sendTgMsg(ctx, env, title, r, `类型: ${_d(cName)}`, isGlobalAdmin);
                  if(ctx && ctx.waitUntil) ctx.waitUntil(p);
              } catch (e) {}
          }
          const requestProxyIp = url.searchParams.get('proxyip') || _PROXY_IP;
          const pathParam = requestProxyIp ? "/proxyip=" + requestProxyIp : "/";
          const subUrl = `https://${_SUB_DOMAIN}/sub?uuid=${_UUID}&encryption=none&security=tls&sni=${host}&alpn=h3&fp=random&allowInsecure=1&type=ws&host=${host}&path=${encodeURIComponent(pathParam)}`;

          if (UA_L.includes('sing-box') || UA_L.includes('singbox') || UA_L.includes('clash') || UA_L.includes('meta') || UA_L.includes('loon') || UA_L.includes('surge')) {
              const type = (UA_L.includes('clash') || UA_L.includes('meta')) ? 'clash' : 'singbox';
              const config = type === 'clash' ? CLASH_CONFIG : SINGBOX_CONFIG_V12;
              const subApi = `${_CONVERTER}/sub?target=${type}&url=${encodeURIComponent(subUrl)}&config=${encodeURIComponent(config)}&emoji=true&list=false&sort=false&fdn=false&scv=false`;
              try { const res = await fetch(subApi, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' } });
                  if (res.ok) return new Response(res.body, { status: 200, headers: res.headers });
              } catch(e) {}
          }
          try {
            if (host.toLowerCase() !== _SUB_DOMAIN.toLowerCase()) {
                const res = await fetch(subUrl, { headers: { 'User-Agent': UA } });
                if (res.ok) {
                    let body = await res.text();
                    if (_PS) { try { const decoded = atob(body); const modified = decoded.split('\n').map(line => { line = line.trim(); if (!line || !line.includes('://')) return line; if (line.includes('#')) return line + encodeURIComponent(` ${_PS}`); return line + '#' + encodeURIComponent(_PS); }).join('\n'); body = btoa(modified); } catch(e) {} }
                    return new Response(body, { status: 200, headers: res.headers });
                }
            }
          } catch(e) {}
          const allIPs = await getCustomIPs(env);
          const listText = genNodes(host, _UUID, requestProxyIp, allIPs, _PS);
          return new Response(btoa(unescape(encodeURIComponent(listText))), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      if (url.pathname === '/sub') {
          ctx.waitUntil(logAccess(env, clientIP, `${city},${country}`, "常规订阅"));
          const requestUUID = url.searchParams.get('uuid');
          if (requestUUID.toLowerCase() !== _UUID.toLowerCase()) return new Response('Invalid UUID', { status: 403 });
          let proxyIp = url.searchParams.get('proxyip') || _PROXY_IP;
          const pathParam = url.searchParams.get('path');
          if (pathParam && pathParam.includes('/proxyip=')) proxyIp = pathParam.split('/proxyip=')[1];
          const allIPs = await getCustomIPs(env);
          const listText = genNodes(host, _UUID, proxyIp, allIPs, _PS);
          return new Response(btoa(unescape(encodeURIComponent(listText))), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      if (r.headers.get('Upgrade') !== 'websocket') {
        const noCacheHeaders = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' };
        if (!hasAuthCookie) return new Response(loginPage(TG_GROUP_URL, TG_CHANNEL_URL), { status: 200, headers: noCacheHeaders });
        await sendTgMsg(ctx, env, "✅ 后台登录成功", r, "进入管理面板", true); 
        ctx.waitUntil(logAccess(env, clientIP, `${city},${country}`, "登录后台"));
        
        const sysParams = { tgToken: env.TG_BOT_TOKEN || TG_BOT_TOKEN, tgId: env.TG_CHAT_ID || TG_CHAT_ID, cfId: env.CF_ID || "", cfToken: env.CF_TOKEN || "", cfMail: env.CF_EMAIL || "", cfKey: env.CF_KEY || "" };
        const tgToken = await getSafeEnv(env, 'TG_BOT_TOKEN', TG_BOT_TOKEN);
        const tgId = await getSafeEnv(env, 'TG_CHAT_ID', TG_CHAT_ID);
        const cfId = await getSafeEnv(env, 'CF_ID', ''); const cfToken = await getSafeEnv(env, 'CF_TOKEN', '');
        const cfMail = await getSafeEnv(env, 'CF_EMAIL', ''); const cfKey = await getSafeEnv(env, 'CF_KEY', '');
        const tgState = !!(tgToken && tgId); const cfState = (!!(cfId && cfToken)) || (!!(cfMail && cfKey));
        const _ADD = await getSafeEnv(env, 'ADD', ""); const _ADDAPI = await getSafeEnv(env, 'ADDAPI', ""); const _ADDCSV = await getSafeEnv(env, 'ADDCSV', "");

        return new Response(dashPage(url.hostname, _UUID, _PROXY_IP, _SUB_PW, _SUB_DOMAIN, _CONVERTER, env, clientIP, hasAuthCookie, tgState, cfState, _ADD, _ADDAPI, _ADDCSV, tgToken, tgId, cfId, cfToken, cfMail, cfKey, sysParams), { status: 200, headers: noCacheHeaders });
      }
      
      // 🟢 代理入口 - 混淆版
      const { proxyIP, sq, enSq, gp } = parsePC(url.pathname);
      const { 0: c, 1: s } = new WebSocketPair();
      s.accept(); 
      handle(s, proxyIP, sq, enSq, gp, _UUID); 
      return new Response(null, { status: 101, webSocket: c });

  } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }
};

// =============================================================================
// 📋 UI & 节点生成
// =============================================================================

function genNodes(host, uuid, proxyIP, customIPs, psName) {
  const commonUrlPart = `?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&udp=false`;
  const separator = psName ? ` ${psName}` : '';
  const result = [];
  if (!customIPs || customIPs.length === 0) {
      const path = proxyIP ? `/proxyip=${proxyIP}` : "/";
      const nodeName = `${psName || 'Worker'} - Default`;
      const vLink = `${P_V}://${uuid}@${proxyIP || host}:443${commonUrlPart}&path=${encodeURIComponent(path)}#${encodeURIComponent(nodeName)}`;
      return vLink;
  }
  for (const ipInfo of customIPs) {
      let [addressPart, ...nameParts] = ipInfo.split('#');
      let uniqueName = nameParts.join('#').trim();
      addressPart = addressPart.trim();
      let ip = addressPart; let port = '443';
      if (addressPart.includes(':') && !addressPart.includes(']:')) { const parts = addressPart.split(':'); ip = parts[0]; port = parts[1]; }
      const path = proxyIP ? `/proxyip=${proxyIP}` : "/";
      let nodeName = uniqueName || ip; if (psName) nodeName = `${nodeName}${separator}`;
      const vLink = `${P_V}://${uuid}@${ip}:${port}${commonUrlPart}&path=${encodeURIComponent(path)}#${encodeURIComponent(nodeName)}`;
      result.push(vLink);
  }
  return result.join('\n');
}

async function getCustomIPs(env) {
    let allIPs = [];
    const addText = await getSafeEnv(env, 'ADD', "");
    if (addText) { addText.split('\n').forEach(line => { const trimmed = line.trim(); if (trimmed && !trimmed.startsWith('#')) allIPs.push(trimmed); }); }
    const addApi = await getSafeEnv(env, 'ADDAPI', "");
    if (addApi) { const urls = addApi.split('\n').filter(u => u.trim().startsWith('http')); for (const url of urls) { try { const res = await fetch(url.trim(), { headers: { 'User-Agent': 'Mozilla/5.0' } }); if (res.ok) { const text = await res.text(); text.split('\n').forEach(line => { const trimmed = line.trim(); if (trimmed && !trimmed.startsWith('#')) allIPs.push(trimmed); }); } } catch (e) {} } }
    const addCsv = await getSafeEnv(env, 'ADDCSV', "");
    if (addCsv) { const urls = addCsv.split('\n').filter(u => u.trim().startsWith('http')); for (const url of urls) { try { const res = await fetch(url.trim(), { headers: { 'User-Agent': 'Mozilla/5.0' } }); if (res.ok) { const text = await res.text(); text.split('\n').forEach(line => { const trimmed = line.trim(); const firstCol = trimmed.split(',')[0]; if (firstCol && !firstCol.startsWith('#')) allIPs.push(firstCol); }); } } catch (e) {} } }
    return allIPs;
}

function loginPage(tgGroup, tgChannel) {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Worker Login</title>
    <style>
        body { background: linear-gradient(135deg, #0f4c75 0%, #3282b8 50%, #bbe1fa 100%); color: white; font-family: 'Segoe UI', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .glass-box { background: rgba(16, 32, 60, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3); text-align: center; width: 320px; }
        h2 { margin-top: 0; margin-bottom: 20px; font-weight: 600; font-size: 1.4rem; display: flex; align-items: center; justify-content: center; gap: 8px; } h2::before { content: '🔒'; font-size: 1.2rem; }
        input { width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(30, 45, 70, 0.6); color: white; box-sizing: border-box; text-align: center; font-size: 0.95rem; outline: none; transition: 0.3s; }
        input:focus { border-color: #3282b8; background: rgba(30, 45, 70, 0.9); } input::placeholder { color: #8ba0b3; }
        .btn-group { display: flex; flex-direction: column; gap: 10px; }
        button { width: 100%; padding: 12px; border-radius: 6px; border: none; cursor: pointer; font-size: 0.95rem; transition: 0.2s; font-weight: 600; }
        .btn-primary { background: linear-gradient(90deg, #3282b8, #0f4c75); color: white; box-shadow: 0 4px 6px rgba(0,0,0,0.2); } .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-unlock { background: linear-gradient(90deg, #a29bfe, #6c5ce7); color: white; margin-top: 5px; } .btn-unlock:hover { opacity: 0.9; transform: translateY(-1px); }
        .social-links { margin-top: 25px; display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; }
        .pill { background: rgba(0, 0, 0, 0.3); padding: 6px 12px; border-radius: 20px; color: #dcdde1; text-decoration: none; font-size: 0.8rem; display: flex; align-items: center; gap: 5px; transition: 0.2s; border: 1px solid rgba(255, 255, 255, 0.1); }
        .pill:hover { background: rgba(255, 255, 255, 0.1); border-color: #3282b8; color: white; }
    </style>
</head>
<body>
    <div class="glass-box">
        <h2>禁止进入</h2>
        <input type="password" id="pwd" placeholder="请输入密码" autofocus autocomplete="new-password" onkeypress="if(event.keyCode===13)verify()">
        <div class="btn-group">
            <button class="btn-primary" onclick="alert('请直接输入密码解锁')">请输入密码</button>
            <button class="btn-unlock" onclick="verify()">解锁后台</button>
        </div>
        <div class="social-links">
            <a href="javascript:void(0)" onclick="gh()" class="pill">🔥 烈火项目直达</a>
            <a href="${tgChannel}" target="_blank" class="pill">📢 天诚频道组</a>
            <a href="${tgGroup}" target="_blank" class="pill">✈️ 天诚交流群</a>
        </div>
    </div>
    <script>
        function gh(){fetch("?flag=github&t="+Date.now(),{keepalive:!0});window.open("https://github.com/xtgm/stallTCP1.3V1","_blank")}
        function verify(){
            const p = document.getElementById("pwd").value;
            if(!p) return;
            document.cookie = "auth=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
            document.cookie = "auth=" + p + "; path=/; SameSite=Lax";
            sessionStorage.setItem("is_active", "1");
            location.reload();
        }
        window.onload = function() {
            if(!sessionStorage.getItem("is_active")) {
                document.cookie = "auth=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
            }
        }
    </script>
</body>
</html>`;
}

function dashPage(host, uuid, proxyip, subpass, subdomain, converter, env, clientIP, hasAuth, tgState, cfState, add, addApi, addCsv, tgToken, tgId, cfId, cfToken, cfMail, cfKey, sysParams) {
    const defaultSubLink = `https://${host}/${subpass}`;
    const pathParam = proxyip ? "/proxyip=" + proxyip : "/";
    const longLink = `https://${subdomain}/sub?uuid=${uuid}&encryption=none&security=tls&sni=${host}&alpn=h3&fp=random&allowInsecure=1&type=ws&host=${host}&path=${encodeURIComponent(pathParam)}`;
    const safeVal = (str) => (str || '').replace(/"/g, '&quot;');
    const getStatusLabel = (val, sysVal) => { if (!val) return ""; if (val === sysVal) return `<span class="source-tag sys">🔒 系统预设 (不可删除)</span>`; return `<span class="source-tag man">💾 后台配置 (可清除)</span>`; };
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Worker 控制台</title>
    <style>
        body { display: none; opacity: 0; transition: opacity 0.3s; }
        body.loaded { display: flex; opacity: 1; }
        :root { --bg: #121418; --card: #1e222a; --text: #e0e0e0; --border: #2a2f38; --accent: #3498db; --green: #2ecc71; --red: #e74c3c; --input-bg: #15181e; --modal-bg: #1e222a; }
        body.light { --bg: #f0f2f5; --card: #ffffff; --text: #333333; --border: #e0e0e0; --accent: #3498db; --green: #27ae60; --red: #c0392b; --input-bg: #f9f9f9; --modal-bg: #ffffff; }
        body { background-color: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; justify-content: center; }
        .container { width: 100%; max-width: 900px; display: flex; flex-direction: column; gap: 20px; }
        .card { background-color: var(--card); border-radius: 8px; padding: 20px; border: 1px solid var(--border); box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 15px; border-bottom: 1px solid var(--border); margin-bottom: 15px; }
        .header-title { display: flex; align-items: center; gap: 10px; font-size: 1.2rem; font-weight: 600; }
        .header-title span { color: #f1c40f; }
        .tools { display: flex; gap: 10px; }
        .tool-btn { width: 40px; height: 40px; background: var(--input-bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; cursor: pointer; transition: 0.2s; display: flex; align-items: center; justify-content: center; font-size: 1.1rem; position: relative; }
        .tool-btn:hover { border-color: var(--accent); background: #2b303b; }
        .tool-btn::before { content: attr(data-tooltip); position: absolute; bottom: -35px; left: 50%; transform: translateX(-50%); padding: 5px 10px; background: rgba(0,0,0,0.85); color: #fff; font-size: 12px; border-radius: 4px; white-space: nowrap; pointer-events: none; opacity: 0; visibility: hidden; transition: 0.2s; z-index: 10; }
        .tool-btn:hover::before { opacity: 1; visibility: visible; bottom: -40px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; position: absolute; top: 5px; right: 5px; }
        .status-dot.on { background-color: var(--green); box-shadow: 0 0 5px var(--green); }
        .status-dot.off { background-color: var(--red); }
        .status-grid { display: grid; grid-template-columns: 1fr 1.5fr; gap: 20px; }
        .circle-chart-box { background: var(--input-bg); border-radius: 8px; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 25px; border: 1px dashed var(--border); }
        .circle-ring { width: 100px; height: 100px; border-radius: 50%; border: 8px solid var(--border); border-top-color: var(--green); margin-bottom: 15px; flex-shrink: 0; }
        .circle-val { font-size: 2.2rem; font-weight: bold; color: var(--green); line-height: 1; margin-bottom: 5px; }
        .circle-label { font-size: 0.85rem; color: #888; white-space: nowrap; }
        .info-list { display: flex; flex-direction: column; gap: 10px; }
        .info-item { background: var(--input-bg); padding: 12px 15px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; font-size: 0.9rem; }
        .info-val { font-family: monospace; color: var(--green); }
        .section-title { font-size: 0.95rem; color: var(--accent); margin-bottom: 10px; font-weight: 600; display: flex; align-items: center; gap: 5px; }
        .input-block { margin-bottom: 12px; }
        label { display: block; font-size: 0.8rem; color: #888; margin-bottom: 6px; }
        input[type="text"], textarea { width: 100%; background: var(--input-bg); border: 1px solid var(--border); color: var(--text); padding: 12px; border-radius: 6px; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; outline: none; transition: 0.2s; box-sizing: border-box; }
        input[type="text"]:focus, textarea:focus { border-color: var(--accent); }
        textarea { min-height: 100px; resize: vertical; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; word-break: break-all; }
        .input-group-row { display: flex; gap: 10px; }
        .input-group-row input { flex: 1; }
        .btn-check { background: #1f3a52; color: #fff; border: 1px solid #2b303b; padding: 0 15px; border-radius: 6px; cursor: pointer; white-space: nowrap; font-weight: bold; }
        .btn-check:hover { background: #2a4d6e; }
        .btn-copy { background: #1f3a52; color: #fff; border: 1px solid #2b303b; padding: 0 15px; border-radius: 4px; cursor: pointer; }
        .btn-main { flex: 2; background: var(--green); color: #fff; border: none; padding: 12px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .btn-test { flex: 1; background: #1f3a52; color: #fff; border: 1px solid #1e4a75; padding: 12px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .checkbox-row { display: flex; justify-content: flex-end; align-items: center; gap: 5px; font-size: 0.85rem; color: #888; margin-bottom: 5px; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100; justify-content: center; align-items: center; }
        .modal.show { display: flex; }
        .modal-content { background: var(--modal-bg); padding: 25px; border-radius: 12px; width: 90%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); border: 1px solid var(--border); }
        .modal-head { display: flex; justify-content: space-between; margin-bottom: 20px; font-weight: bold; font-size: 1.2rem; align-items: center; }
        .modal-head span { display: flex; align-items: center; gap: 8px; }
        .close-btn { cursor: pointer; color: #888; font-size: 1.2rem; }
        .modal-btns { display: flex; gap: 10px; margin-top: 25px; }
        .modal-btns button { flex: 1; padding: 12px; border-radius: 8px; border: none; cursor: pointer; font-weight: bold; font-size: 0.95rem; color: white; transition: 0.2s; }
        .btn-valid { background: #2f80ed; } .btn-save { background: #f2994a; } .btn-cancel { background: #e0e0e0; color: #333 !important; } .btn-clear { background: #e74c3c; }
        .log-box { font-family: monospace; font-size: 0.8rem; max-height: 200px; overflow-y: auto; background: var(--input-bg); padding: 10px; border-radius: 4px; }
        .log-entry { border-bottom: 1px solid var(--border); padding: 8px 0; display: flex; align-items: center; gap: 10px; }
        .log-time { color: #888; width: 150px; flex-shrink: 0; font-size: 0.85rem; font-family: monospace; }
        .log-ip { color: var(--text); width: 260px; flex-shrink: 0; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .log-loc { color: #888; flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 0.85rem; }
        .log-tag { width: 80px; text-align: center; background: #f39c12; color: white; padding: 2px 0; border-radius: 4px; font-size: 0.75rem; flex-shrink: 0; }
        .log-tag.green { background: var(--green); }
        .wl-table { width:100%; border-collapse: collapse; font-size:0.85rem; margin-top:10px; }
        .wl-table th, .wl-table td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
        .wl-table th { color: #888; font-weight: normal; }
        .btn-del { background: var(--red); color:white; border:none; padding:4px 10px; border-radius:4px; cursor:pointer; font-size:0.75rem;}
        .sys-tag { background: #7f8c8d; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; }
        .source-tag { font-size: 0.75rem; margin-top: 4px; display: block; }
        .source-tag.sys { color: #f1c40f; } .source-tag.man { color: #2ecc71; }
        #toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: var(--green); color: white; padding: 8px 20px; border-radius: 20px; opacity: 0; transition: 0.3s; pointer-events: none; }
        .refresh-btn { width: 100%; background: #1f3a52; color: #64b5f6; border: 1px solid #1e4a75; padding: 10px; border-radius: 6px; cursor: pointer; margin-top: 10px; transition: 0.2s; font-weight:bold; }
        @media (max-width: 600px) { .status-grid { grid-template-columns: 1fr; } .input-group-row { flex-direction:column; } }
    </style>
</head>
<body id="mainBody">
    <div class="container">
        <div class="card" style="padding: 15px 20px;">
            <div class="header" style="margin-bottom:0; border-bottom:none; padding-bottom:0;">
                <div class="header-title"><span>⚡</span> Worker 控制台</div>
                <div class="tools">
                    <button class="tool-btn" onclick="toggleTheme()" data-tooltip="切换黑/白主题">🌗</button>
                    <button class="tool-btn" onclick="showModal('tgModal')" data-tooltip="添加bot机器人监控">🤖 <span class="status-dot ${tgState ? 'on' : 'off'}"></span></button>
                    <button class="tool-btn" onclick="showModal('cfModal')" data-tooltip="添加cloudflare API请求数统计">☁️ <span class="status-dot ${cfState ? 'on' : 'off'}"></span></button>
                    <button class="tool-btn logout-btn" onclick="logout()" style="background:#c0392b;color:white" data-tooltip="退出登录">⏻</button>
                </div>
            </div>
        </div>
        <div class="card status-grid">
            <div class="circle-chart-box"><div class="circle-ring"></div><div class="circle-val" id="reqCount">...</div><div class="circle-label">Cloudflare 统计 / 今日请求</div></div>
            <div style="display:flex; flex-direction:column; justify-content:center;">
                <div class="info-list">
                    <div class="info-item"><span style="color:#888">Cloudflare API</span><span class="info-val" id="apiStatus" style="color: #64b5f6;">Check...</span></div>
                    <div class="info-item"><span style="color:#888">Google (连通)</span><span class="info-val" id="googleStatus">Check...</span></div>
                    <div class="info-item"><span style="color:#888">当前 IP</span><span class="info-val" id="currentIp" style="font-size:0.8rem">...</span></div>
                    <div class="info-item"><span style="color:#888">DB/KV 状态</span><span class="info-val" id="kvStatus">...</span></div>
                </div>
                <button class="refresh-btn" onclick="updateStats()">🔄 刷新状态</button>
            </div>
        </div>
        <div class="card">
            <div class="section-title">🚀 自适应订阅 (仅上游)</div>
            <div style="display:flex; gap:10px; margin-bottom:15px;"><input type="text" id="autoSub" value="${defaultSubLink}" readonly style="flex:1"><button class="btn-copy" onclick="copyId('autoSub')">复制</button></div>
            <div class="input-block"><label>订阅源地址 (Sub Domain)</label><input type="text" id="subDom" value="${subdomain}" oninput="updateLink()"></div>
            <div class="input-block"><label>Worker 域名 (SNI/Host)</label><input type="text" id="hostDom" value="${host}" oninput="updateLink()"></div>
            <div class="input-block"><label>ProxyIP (优选)</label><div class="input-group-row"><input type="text" id="pIp" value="${proxyip}" oninput="updateLink()"><button class="btn-check" onclick="checkProxy()">检测 ProxyIP</button></div></div>
            <div class="checkbox-row"><input type="checkbox" id="clashMode" onchange="toggleClash()"><label for="clashMode">启用 Clash 模式</label></div>
            <div class="input-block"><label>手动订阅链接生成</label><textarea id="finalLink">${longLink}</textarea></div>
            <div class="action-btns"><button class="btn-main" onclick="copyId('finalLink')">复制链接</button><button class="btn-test" onclick="testSub()">测试访问</button></div>
        </div>
        <div class="card">
            <div class="section-title" style="justify-content:space-between"><span>🛡️ 白名单 IP 管理</span><button class="tool-btn" onclick="loadWhitelist()" style="width:auto;padding:6px 12px;font-size:0.8rem">刷新</button></div>
           <div class="input-group-row" style="margin-bottom:10px"><input type="text" id="newWhitelistIp" placeholder="输入 IP 地址 (IPv4/IPv6)"><button class="btn-check" onclick="addWhitelist()" style="background:var(--green);border:none;">添加白名单</button></div>
            <div style="max-height:200px; overflow-y:auto; border:1px solid var(--border); border-radius:4px;"><table class="wl-table"><thead><tr><th>IP 地址</th><th style="width:80px">操作</th></tr></thead><tbody id="whitelistBody"><tr><td colspan="2" style="text-align:center">加载中...</td></tr></tbody></table></div>
            <div style="font-size:0.75rem; color:#888; margin-top:5px">提示：🔒 系统内置 IP 需要修改代码或环境变量才能删除。</div>
        </div>
        <div class="card">
            <div class="section-title" style="justify-content:space-between"><span>🛠️ 优选 IP 与 远程配置</span><button class="tool-btn" onclick="saveNodeConfig()" style="width:auto;padding:6px 12px;font-size:0.8rem;background:var(--green);border:none;color:white;font-weight:bold;">💾 保存配置</button></div>
            <div style="font-size:0.8rem;color:#e74c3c;margin-bottom:10px;">⚠️ 注意：若要在此生效，请确保 Cloudflare 后台未设置对应环境变量 (ADD/ADDAPI/ADDCSV)</div>
            <div class="input-block"><label>ADD - 本地优选 IP (格式: IP:Port#Name，一行一个)</label><textarea id="inpAdd" placeholder="1.1.1.1:443#US">${safeVal(add)}</textarea></div>
            <div class="input-block"><label>ADDAPI - 远程优选 TXT 链接 (支持多行)</label><textarea id="inpAddApi" placeholder="https://example.com/ips.txt">${safeVal(addApi)}</textarea></div>
             <div class="input-block"><label>ADDCSV - 远程优选 CSV 链接 (支持多行)</label><textarea id="inpAddCsv" placeholder="https://example.com/ips.csv">${safeVal(addCsv)}</textarea></div>
        </div>
        <div class="card">
            <div class="section-title" style="justify-content:space-between"><span>📋 操作日志 (DB/KV 4MB)</span><button class="tool-btn" onclick="loadLogs()" style="width:auto;padding:6px 12px;font-size:0.8rem">刷新</button></div>
            <div class="log-box" id="logBox">Loading logs...</div>
        </div>
    </div>
    <div id="tgModal" class="modal">
        <div class="modal-content">
            <div class="modal-head"><span>🤖 Telegram 通知配置</span><span class="close-btn" onclick="closeModal('tgModal')">×</span></div>
            <label>Bot Token</label><input type="text" id="tgToken" placeholder="123456:ABC-DEF..." value="${safeVal(tgToken)}">${getStatusLabel(tgToken, sysParams.tgToken)}
            <label style="margin-top:10px">Chat ID</label><input type="text" id="tgId" placeholder="123456789" value="${safeVal(tgId)}">${getStatusLabel(tgId, sysParams.tgId)}
            <div class="modal-btns"><button class="btn-valid" onclick="validateApi('tg')">可用性验证</button><button class="btn-save" onclick="saveConfig({TG_BOT_TOKEN: val('tgToken'), TG_CHAT_ID: val('tgId')}, 'tgModal')">保存</button><button class="btn-clear" onclick="clearConfig('tg')">清除配置</button><button class="btn-cancel" onclick="closeModal('tgModal')">取消</button></div>
        </div>
   </div>
    <div id="cfModal" class="modal">
        <div class="modal-content">
            <div class="modal-head"><span>☁️ Cloudflare 统计配置</span><span class="close-btn" onclick="closeModal('cfModal')">×</span></div>
            <div style="margin-bottom:15px;border-bottom:1px solid var(--border);padding-bottom:10px">
                <label>方案1: Account ID + API Token</label><input type="text" id="cfAcc" placeholder="Account ID" style="margin-bottom:10px" value="${safeVal(cfId)}">${getStatusLabel(cfId, sysParams.cfId)}<input type="text" id="cfTok" placeholder="API Token (Read permission)" value="${safeVal(cfToken)}">${getStatusLabel(cfToken, sysParams.cfToken)}
            </div>
            <label>方案2: Email + Global Key</label><input type="text" id="cfMail" placeholder="Email" style="margin-bottom:10px" value="${safeVal(cfMail)}">${getStatusLabel(cfMail, sysParams.cfMail)}<input type="text" id="cfKey" placeholder="Global API Key" value="${safeVal(cfKey)}">${getStatusLabel(cfKey, sysParams.cfKey)}
            <div class="modal-btns"><button class="btn-valid" onclick="validateApi('cf')">可用性验证</button><button class="btn-save" onclick="saveConfig({CF_ID:val('cfAcc'), CF_TOKEN:val('cfTok'), CF_EMAIL:val('cfMail'), CF_KEY:val('cfKey')}, 'cfModal')">保存</button><button class="btn-clear" onclick="clearConfig('cf')">清除配置</button><button class="btn-cancel" onclick="closeModal('cfModal')">取消</button></div>
        </div>
    </div>
    <div id="toast">已复制</div>
    <script>
        const UUID = "${uuid}"; const CONVERTER = "${converter}"; const CLIENT_IP = "${clientIP}"; const HAS_AUTH = ${hasAuth};
        window.addEventListener('DOMContentLoaded', () => { if (HAS_AUTH && !sessionStorage.getItem("is_active")) { document.cookie = "auth=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"; window.location.reload(); } else { document.body.classList.add('loaded'); if(!document.getElementById('subDom').value) { updateLink(); } } });
        function val(id) { return document.getElementById(id).value; } function showModal(id) { document.getElementById(id).classList.add('show'); } function closeModal(id) { document.getElementById(id).classList.remove('show'); }
        async function updateStats() { try { const start = Date.now(); await fetch('https://www.google.com/generate_204', {mode: 'no-cors'}); document.getElementById('googleStatus').innerText = (Date.now() - start) + 'ms'; } catch (e) { document.getElementById('googleStatus').innerText = 'Timeout'; } try { const res = await fetch('?flag=stats'); const data = await res.json(); document.getElementById('reqCount').innerText = data.req; document.getElementById('apiStatus').innerText = data.cfConfigured ? 'Connected' : 'Internal'; document.getElementById('currentIp').innerText = data.ip; document.getElementById('kvStatus').innerText = data.hasKV ? 'D1/KV OK' : 'Missing'; } catch (e) { document.getElementById('reqCount').innerText = 'N/A'; } }
        async function loadLogs() { try { const res = await fetch('?flag=get_logs'); const data = await res.json(); let html = ''; if (data.type === 'd1' && Array.isArray(data.logs)) { html = data.logs.map(log => "<div class='log-entry'><span class='log-time'>" + log.time + "</span><span class='log-ip'>" + log.ip + "</span><span class='log-loc'>" + log.region + "</span><span class='log-tag " + (log.action.includes('订阅')||log.action.includes('检测')?'green':'') + "'>" + log.action + "</span></div>").join(''); } else if (data.logs && typeof data.logs === 'string') { html = data.logs.split('\\n').filter(x=>x).slice(0, 50).map(line => { const p = line.split('|'); return "<div class='log-entry'><span class='log-time'>" + p[0] + "</span><span class='log-ip'>" + p[1] + "</span><span class='log-loc'>" + p[2] + "</span><span class='log-tag " + (p[3].includes('订阅')||p[3].includes('检测')?'green':'') + "'>" + p[3] + "</span></div>"; }).join(''); } document.getElementById('logBox').innerHTML = html || '暂无日志'; } catch(e) { document.getElementById('logBox').innerText = '加载失败或未绑定 DB/KV'; } }
        async function loadWhitelist() { try { const res = await fetch('?flag=get_whitelist'); const data = await res.json(); const list = data.list || []; const html = list.length ? list.map(item => { const actionHtml = item.type === 'system' ? '<span class="sys-tag">🔒 系统内置</span>' : "<button class='btn-del' onclick='delWhitelist(\\"" + item.ip + "\\")'>🗑️ 删除</button>"; return "<tr><td>" + item.ip + "</td><td>" + actionHtml + "</td></tr>"; }).join('') : '<tr><td colspan="2" style="text-align:center">暂无白名单 IP</td></tr>'; document.getElementById('whitelistBody').innerHTML = html; } catch(e) { document.getElementById('whitelistBody').innerHTML = '<tr><td colspan="2">加载失败</td></tr>'; } }
        async function addWhitelist() { const ip = document.getElementById('newWhitelistIp').value.trim(); if(!ip) return; try { await fetch('?flag=add_whitelist', { method:'POST', body:JSON.stringify({ip}) }); document.getElementById('newWhitelistIp').value = ''; loadWhitelist(); } catch(e) { alert('添加失败'); } }
        async function delWhitelist(ip) { if(!confirm('确定移除 '+ip+'?')) return; try { await fetch('?flag=del_whitelist', { method:'POST', body:JSON.stringify({ip}) }); loadWhitelist(); } catch(e) { alert('删除失败'); } }
        async function checkProxy() { const val = document.getElementById('pIp').value; if(val) { try { await navigator.clipboard.writeText(val); alert("✅ ProxyIP 已复制成功\\n\\n点击确定跳转检测网站..."); } catch(e) { alert("跳转检测网站..."); } fetch('?flag=log_proxy_check'); window.open("${PROXY_CHECK_URL}", "_blank"); } }
        function testSub() { const url = document.getElementById('finalLink').value; if(url) { fetch('?flag=log_sub_test'); window.open(url); } }
        async function saveConfig(data, modalId) { try { await fetch('?flag=save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) }); alert('保存成功'); if(modalId) closeModal(modalId); setTimeout(() => location.reload(), 500); } catch(e) { alert('保存失败: ' + e); } }
        function saveNodeConfig() { const data = { ADD: val('inpAdd'), ADDAPI: val('inpAddApi'), ADDCSV: val('inpAddCsv') }; saveConfig(data, null); }
        async function clearConfig(type) { if(!confirm('确定清除后台配置？\\n(若存在系统环境变量，清除后将自动恢复为系统值)')) return; let data = {}; if(type === 'tg') data = { TG_BOT_TOKEN: "", TG_CHAT_ID: "" }; if(type === 'cf') data = { CF_ID: "", CF_TOKEN: "", CF_EMAIL: "", CF_KEY: "" }; saveConfig(data, type + 'Modal'); }
        async function validateApi(type) { const endpoint = type === 'tg' ? 'validate_tg' : 'validate_cf'; let payload = {}; if(type === 'tg') payload = { TG_BOT_TOKEN: val('tgToken'), TG_CHAT_ID: val('tgId') }; else payload = { CF_ID:val('cfAcc'), CF_TOKEN:val('cfTok'), CF_EMAIL:val('cfMail'), CF_KEY:val('cfKey') }; try { const res = await fetch('?flag=' + endpoint, { method:'POST', body:JSON.stringify(payload) }); const d = await res.json(); alert(d.msg || (d.success ? '验证通过' : '验证失败')); } catch(e) { alert('请求错误'); } }
        function toggleTheme() { document.body.classList.toggle('light'); }
        function updateLink() { let base = document.getElementById('subDom').value.trim() || document.getElementById('hostDom').value.trim(); let host = document.getElementById('hostDom').value.trim(); let p = document.getElementById('pIp').value.trim(); let isClash = document.getElementById('clashMode').checked; let path = p ? "/proxyip=" + p : "/"; const search = new URLSearchParams(); search.set('uuid', UUID); search.set('encryption', 'none'); search.set('security', 'tls'); search.set('sni', host); search.set('alpn', 'h3'); search.set('fp', 'random'); search.set('allowInsecure', '1'); search.set('type', 'ws'); search.set('host', host); search.set('path', path); search.set('udp', 'false'); let finalUrl = \`https://\${base}/sub?\${search.toString()}\`; if (isClash) { let subUrl = CONVERTER + "/sub?target=clash&url=" + encodeURIComponent(finalUrl) + "&emoji=true&list=false&sort=false"; document.getElementById('finalLink').value = subUrl; } else { document.getElementById('finalLink').value = finalUrl; } }
        function toggleClash() { updateLink(); }
        function copyId(id) { const el = document.getElementById(id); el.select(); navigator.clipboard.writeText(el.value).then(() => { const t = document.getElementById('toast'); t.classList.add('show'); t.style.opacity=1; setTimeout(() => t.style.opacity=0, 2000); }); }
        function logout() { document.cookie = "auth=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"; sessionStorage.removeItem("is_active"); location.reload(); }
        updateStats(); loadLogs(); loadWhitelist(); updateLink(); setInterval(loadLogs, 3000);
    </script>
</body>
</html>`;
}
