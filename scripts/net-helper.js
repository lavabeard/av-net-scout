#!/usr/bin/env node
/*
 * net-helper.js — AV Net Scout privileged network helper (Phase 1: IGMP detector)
 *
 * Runs as root (launched by the app via pkexec on Linux) and performs the
 * packet-capture / raw-socket work the unprivileged GUI cannot. It speaks a
 * line-delimited JSON protocol over stdio:
 *
 *   stdin  (commands):  {"cmd":"start","iface":"192.168.0.10"}  {"cmd":"stop"}  {"cmd":"ping"}
 *   stdout (events):    {"ev":"ready","device":"en0"}  {"ev":"querier",...}
 *                       {"ev":"membership","groups":[...]}  {"ev":"error","message":...}
 *
 * The helper exits when stdin closes (the app closing the pipe is the reliable
 * stop signal even when the helper runs as root and the parent does not).
 *
 * Phase 1 implements the IGMP snooping/querier DETECTOR via libpcap (promiscuous
 * capture, BPF filter "igmp"): it reports whether a querier is present (IP,
 * version, measured query interval) and builds a live group-membership map from
 * every device's IGMP reports — visibility a raw IGMP socket can't provide.
 *
 * Standalone testing:
 *   node scripts/net-helper.js --selftest        # parser unit checks, no root
 *   sudo node scripts/net-helper.js --iface <ip> # live capture on an interface
 */

'use strict';

// ── stdout event writer ─────────────────────────────────────────────────────
function emit(obj) {
  try { process.stdout.write(JSON.stringify(obj) + '\n'); } catch { /* pipe gone */ }
}
function log(message) { emit({ ev: 'log', message: String(message) }); }

// ── IGMP parsing (pure, unit-tested) ────────────────────────────────────────
const IGMP = {
  QUERY:     0x11,
  V1_REPORT: 0x12,
  V2_REPORT: 0x16,
  LEAVE:     0x17,
  V3_REPORT: 0x22,
};

function ip4(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

/**
 * Decode an IGMP message body into normalized records.
 * @param {string} src  source IP from the enclosing IP header
 * @param {Buffer} buf  IGMP portion only (starts at the IGMP type byte)
 * @returns {Array} records: {kind:'querier'|'report'|'leave', ...}
 */
function decodeIgmp(src, buf) {
  if (!buf || buf.length < 1) return [];
  const type = buf[0];
  const out = [];

  switch (type) {
    case IGMP.QUERY: {
      if (buf.length < 8) return [];
      const maxResp = buf[1];
      const group = ip4(buf, 4);
      // v3 queries are >= 12 bytes; v1 queries carry maxResp == 0; else v2.
      const version = buf.length >= 12 ? 3 : (maxResp === 0 ? 1 : 2);
      out.push({
        kind: 'querier',
        src,
        version,
        group,
        general: group === '0.0.0.0',
        maxRespMs: maxResp * 100, // v2 max-resp is in 1/10 s units
      });
      break;
    }

    case IGMP.V1_REPORT:
    case IGMP.V2_REPORT: {
      if (buf.length < 8) return [];
      out.push({
        kind: 'report',
        src,
        group: ip4(buf, 4),
        version: type === IGMP.V1_REPORT ? 1 : 2,
      });
      break;
    }

    case IGMP.LEAVE: {
      if (buf.length < 8) return [];
      out.push({ kind: 'leave', src, group: ip4(buf, 4), version: 2 });
      break;
    }

    case IGMP.V3_REPORT: {
      if (buf.length < 8) return [];
      const numRecords = (buf[6] << 8) | buf[7];
      let off = 8;
      for (let i = 0; i < numRecords && off + 8 <= buf.length; i++) {
        const recType = buf[off];
        const auxLen = buf[off + 1];
        const numSources = (buf[off + 2] << 8) | buf[off + 3];
        const group = ip4(buf, off + 4);
        // Record types: 1 MODE_IS_INCLUDE, 2 MODE_IS_EXCLUDE, 3 CHANGE_TO_INCLUDE,
        // 4 CHANGE_TO_EXCLUDE, 5 ALLOW_NEW_SOURCES, 6 BLOCK_OLD_SOURCES.
        // INCLUDE with no sources == leaving the group; everything else == joined.
        const isLeave = (recType === 1 || recType === 3) && numSources === 0;
        out.push({ kind: isLeave ? 'leave' : 'report', src, group, version: 3, recType });
        off += 8 + numSources * 4 + auxLen * 4;
      }
      break;
    }

    default:
      return [];
  }
  return out;
}

// ── Detector state ──────────────────────────────────────────────────────────
const REPORTER_TTL_MS = 5 * 60 * 1000; // forget a reporter after 5 min of silence
const QUERIER_TTL_MS  = 5 * 60 * 1000;

const queriers   = new Map();           // src -> { version, lastSeenMs, lastGeneralMs, intervalMs }
const membership = new Map();           // group -> Map(reporter -> lastSeenMs)
let capInstance  = null;
let captureBuf   = null;
let membershipTimer = null;
let started = false;

function now() { return Date.now(); }

function handleRecord(rec) {
  const t = now();
  if (rec.kind === 'querier') {
    const prev = queriers.get(rec.src);
    let intervalMs = prev ? prev.intervalMs : null;
    if (rec.general) {
      if (prev && prev.lastGeneralMs) {
        const delta = t - prev.lastGeneralMs;
        // Smooth a little so a single jittery gap doesn't dominate.
        intervalMs = prev.intervalMs ? Math.round(prev.intervalMs * 0.5 + delta * 0.5) : delta;
      }
    }
    queriers.set(rec.src, {
      version: rec.version,
      lastSeenMs: t,
      lastGeneralMs: rec.general ? t : (prev ? prev.lastGeneralMs : null),
      intervalMs,
    });
    emit({
      ev: 'querier',
      ip: rec.src,
      version: rec.version,
      general: rec.general,
      group: rec.general ? null : rec.group,
      intervalMs,
    });
  } else if (rec.kind === 'report') {
    if (!membership.has(rec.group)) membership.set(rec.group, new Map());
    membership.get(rec.group).set(rec.src, t);
    emit({ ev: 'report', group: rec.group, reporter: rec.src, version: rec.version });
  } else if (rec.kind === 'leave') {
    const g = membership.get(rec.group);
    if (g) { g.delete(rec.src); if (g.size === 0) membership.delete(rec.group); }
    emit({ ev: 'leave', group: rec.group, reporter: rec.src, version: rec.version });
    querierFastLeave(rec.group); // group-specific query burst if we're the querier
  }
}

function pruneAndSnapshot() {
  const t = now();
  for (const [src, q] of queriers) if (t - q.lastSeenMs > QUERIER_TTL_MS) queriers.delete(src);
  const groups = [];
  for (const [group, reporters] of membership) {
    for (const [ip, seen] of reporters) if (t - seen > REPORTER_TTL_MS) reporters.delete(ip);
    if (reporters.size === 0) { membership.delete(group); continue; }
    groups.push({
      group,
      count: reporters.size,
      reporters: [...reporters.keys()].sort(),
    });
  }
  groups.sort((a, b) => a.group.localeCompare(b.group));
  emit({
    ev: 'membership',
    groups,
    queriers: [...queriers.entries()].map(([ip, q]) => ({
      ip, version: q.version, intervalMs: q.intervalMs,
    })),
  });
}

// ── libpcap capture ─────────────────────────────────────────────────────────
function startCapture(iface) {
  if (started) { emit({ ev: 'error', code: 'already_running', message: 'capture already running' }); return; }

  let Cap, decoders;
  try {
    ({ Cap, decoders } = require('cap'));
  } catch (e) {
    emit({ ev: 'error', code: 'no_pcap', message: 'libpcap binding (cap) not installed: ' + e.message });
    return;
  }
  const PROTOCOL = decoders.PROTOCOL;

  // Resolve the capture device: accept an IP address, an explicit device name,
  // or fall back to the default device.
  let device;
  try {
    if (iface && /^\d+\.\d+\.\d+\.\d+$/.test(iface)) device = Cap.findDevice(iface);
    else if (iface) device = iface;
    else device = Cap.findDevice();
  } catch (e) {
    emit({ ev: 'error', code: 'no_device', message: 'could not resolve capture device: ' + e.message });
    return;
  }
  if (!device) {
    emit({ ev: 'error', code: 'no_device', message: 'no capture device found for ' + (iface || 'default') });
    return;
  }

  const c = new Cap();
  captureBuf = Buffer.alloc(65535);
  let linkType;
  try {
    // BPF filter: "ip proto 2" (IGMP). The "igmp" keyword does not compile
    // reliably through this libpcap binding, so we match the IP protocol number.
    linkType = c.open(device, 'ip proto 2', 10 * 1024 * 1024, captureBuf);
    if (typeof c.setMinBytes === 'function') c.setMinBytes(0);
  } catch (e) {
    const code = /permission|denied|not permitted|EACCES|EPERM|root/i.test(e.message) ? 'eaccess' : 'open_failed';
    emit({ ev: 'error', code, message: 'pcap open failed on ' + device + ': ' + e.message });
    return;
  }

  capInstance = c;
  started = true;
  emit({ ev: 'ready', device, linkType });

  c.on('packet', () => {
    try {
      let src, igmpStart, igmpEnd;
      if (linkType === 'ETHERNET') {
        const eth = decoders.Ethernet(captureBuf);
        if (eth.info.type !== PROTOCOL.ETHERNET.IPV4) return;
        const ip = decoders.IPV4(captureBuf, eth.offset);
        if (ip.info.protocol !== PROTOCOL.IP.IGMP && ip.info.protocol !== 2) return;
        src = ip.info.srcaddr;
        igmpStart = ip.offset;
        igmpEnd = ip.offset + (ip.info.totallen - ip.hdrlen);
      } else if (linkType === 'RAW' || linkType === 'NULL') {
        const off = linkType === 'NULL' ? 4 : 0; // BSD loopback has a 4-byte family header
        const ip = decoders.IPV4(captureBuf, off);
        if (ip.info.protocol !== PROTOCOL.IP.IGMP && ip.info.protocol !== 2) return;
        src = ip.info.srcaddr;
        igmpStart = ip.offset;
        igmpEnd = ip.offset + (ip.info.totallen - ip.hdrlen);
      } else {
        return; // unsupported link layer
      }
      if (igmpEnd > captureBuf.length || igmpEnd <= igmpStart) return;
      const igmp = Buffer.from(captureBuf.subarray(igmpStart, igmpEnd));
      for (const rec of decodeIgmp(src, igmp)) handleRecord(rec);
    } catch (e) {
      log('packet decode error: ' + e.message);
    }
  });

  membershipTimer = setInterval(pruneAndSnapshot, 2000);
}

// ── IGMP querier (raw-socket) ────────────────────────────────────────────────
// Phase 2. Sends IGMP General Queries (heartbeat that keeps snooping switches'
// membership alive) and group-specific queries on fast-leave. Defers to an
// existing lower-IP querier (RFC 2236 querier election) unless forced.

const ALL_HOSTS = '224.0.0.1';

function ipToBytes(ip) { return ip.split('.').map(o => parseInt(o, 10) & 0xff); }
function ipNum(ip) { return ip.split('.').reduce((a, o) => (a * 256 + (parseInt(o, 10) || 0)) >>> 0, 0); }

// Standard 16-bit one's-complement Internet checksum over big-endian words.
function checksum16(buf, start = 0, end = buf.length) {
  let sum = 0;
  let i = start;
  for (; i + 1 < end; i += 2) sum += (buf[i] << 8) | buf[i + 1];
  if (i < end) sum += buf[i] << 8; // odd trailing byte
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

// IGMPv2 query body (8 bytes). group '0.0.0.0' == general query.
function buildIgmpV2Query(group, maxRespMs = 10000) {
  const buf = Buffer.alloc(8);
  buf[0] = 0x11;
  buf[1] = Math.max(1, Math.min(255, Math.round(maxRespMs / 100))); // 1/10 s units
  const g = ipToBytes(group);
  buf[4] = g[0]; buf[5] = g[1]; buf[6] = g[2]; buf[7] = g[3];
  const ck = checksum16(buf, 0, 8);
  buf[2] = (ck >> 8) & 0xff; buf[3] = ck & 0xff;
  return buf;
}

// IPv4 header (24 bytes) with the IP Router Alert option, as IGMP requires.
function buildIpHeaderWithRA(srcIp, dstIp, payloadLen) {
  const ihlWords = 6; // 20 base + 4 option bytes
  const buf = Buffer.alloc(ihlWords * 4);
  buf[0] = (4 << 4) | ihlWords;
  buf[1] = 0xc0;                                  // DSCP CS6 (network control)
  const total = ihlWords * 4 + payloadLen;
  buf[2] = (total >> 8) & 0xff; buf[3] = total & 0xff;
  buf[8] = 1;                                     // TTL 1 (link-local)
  buf[9] = 2;                                      // protocol = IGMP
  const s = ipToBytes(srcIp), d = ipToBytes(dstIp);
  buf[12] = s[0]; buf[13] = s[1]; buf[14] = s[2]; buf[15] = s[3];
  buf[16] = d[0]; buf[17] = d[1]; buf[18] = d[2]; buf[19] = d[3];
  buf[20] = 0x94; buf[21] = 0x04; buf[22] = 0x00; buf[23] = 0x00; // Router Alert
  const ck = checksum16(buf, 0, buf.length);
  buf[10] = (ck >> 8) & 0xff; buf[11] = ck & 0xff;
  return buf;
}

// Full IP+IGMP query packet. group '0.0.0.0'/empty -> general query to 224.0.0.1.
function buildQueryPacket(srcIp, group, maxRespMs = 10000) {
  const g = group && group !== '0.0.0.0' ? group : '0.0.0.0';
  const dst = g === '0.0.0.0' ? ALL_HOSTS : g;
  const igmp = buildIgmpV2Query(g, maxRespMs);
  const ip = buildIpHeaderWithRA(srcIp, dst, igmp.length);
  return Buffer.concat([ip, igmp]);
}

// Querier election: we are active iff no *other* querier has a lower IP.
function shouldBeActiveQuerier(myIp, otherQuerierIps) {
  const me = ipNum(myIp);
  return !otherQuerierIps.some(ip => ip !== myIp && ipNum(ip) < me);
}

const querier = {
  running: false,
  active: false,
  socket: null,
  srcIp: null,
  intervalSecs: 125,
  maxRespMs: 10000,
  force: false,
  sendTimer: null,
  electionTimer: null,
  count: 0,
};

function otherQuerierIps() {
  return [...queriers.keys()].filter(ip => ip !== querier.srcIp);
}

function emitQuerierState(reason) {
  emit({
    ev: 'querier-state',
    running: querier.running,
    active: querier.active,
    srcIp: querier.srcIp,
    intervalSecs: querier.intervalSecs,
    count: querier.count,
    others: otherQuerierIps(),
    reason: reason || null,
  });
}

function sendQuery(group) {
  if (!querier.socket || !querier.active) return;
  let pkt;
  try { pkt = buildQueryPacket(querier.srcIp, group, querier.maxRespMs); }
  catch (e) { emit({ ev: 'error', code: 'querier_build', message: e.message }); return; }
  const dst = group && group !== '0.0.0.0' ? group : ALL_HOSTS;
  try {
    querier.socket.send(pkt, 0, pkt.length, dst, () => {}, (err) => {
      if (err) emit({ ev: 'error', code: 'querier_send', message: 'IGMP send failed: ' + err.message });
    });
    querier.count++;
    emit({ ev: 'query-sent', group: group && group !== '0.0.0.0' ? group : null, dst, count: querier.count });
  } catch (e) {
    emit({ ev: 'error', code: 'querier_send', message: 'IGMP send failed: ' + e.message });
  }
}

// Fast-leave: when the detector observes a Leave for a group and we are the
// active querier, burst group-specific queries to confirm any remaining member.
function querierFastLeave(group) {
  if (!querier.running || !querier.active) return;
  let n = 0;
  const burst = setInterval(() => {
    if (!querier.active || n >= 2) { clearInterval(burst); return; }
    sendQuery(group);
    n++;
  }, 1000);
  sendQuery(group);
}

function evaluateElection() {
  const wantActive = querier.force || shouldBeActiveQuerier(querier.srcIp, otherQuerierIps());
  if (wantActive !== querier.active) {
    querier.active = wantActive;
    emitQuerierState(wantActive
      ? (querier.force ? 'forced-active' : 'won-election')
      : 'deferring-to-lower-ip');
  }
}

function startQuerier(opts) {
  if (querier.running) { emit({ ev: 'error', code: 'querier_running', message: 'querier already running' }); return; }
  const srcIp = opts.iface;
  if (!srcIp || !/^\d+\.\d+\.\d+\.\d+$/.test(srcIp)) {
    emit({ ev: 'error', code: 'querier_no_iface', message: 'querier needs an interface IP (got ' + srcIp + ')' });
    return;
  }

  let raw;
  try { raw = require('raw-socket'); }
  catch (e) { emit({ ev: 'error', code: 'no_raw_socket', message: 'raw-socket not installed: ' + e.message }); return; }

  // The querier needs the detector's capture for election + fast-leave.
  if (!started) startCapture(srcIp);

  let socket;
  try {
    socket = raw.createSocket({ protocol: 2 }); // IPPROTO_IGMP
    // We build the full IP header (Router Alert + TTL 1), so enable HDRINCL.
    socket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL, 1);
    socket.on('error', e => emit({ ev: 'error', code: 'querier_socket', message: e.message }));
  } catch (e) {
    const code = /permission|denied|not permitted|EACCES|EPERM|root/i.test(e.message) ? 'eaccess' : 'querier_open';
    emit({ ev: 'error', code, message: 'raw socket setup failed: ' + e.message });
    return;
  }

  // Best-effort: pin multicast egress to the chosen NIC. raw-socket doesn't expose
  // IP_MULTICAST_IF, so use the platform's raw setsockopt option number. Non-fatal —
  // without it the OS default multicast route is used.
  try {
    const IP_MULTICAST_IF = process.platform === 'linux' ? 32 : 9; // Linux vs BSD/macOS
    socket.setOption(raw.SocketLevel.IPPROTO_IP, IP_MULTICAST_IF, Buffer.from(ipToBytes(srcIp)), 4);
  } catch (e) {
    emit({ ev: 'log', message: 'could not bind querier to NIC ' + srcIp + ': ' + e.message });
  }

  Object.assign(querier, {
    running: true,
    active: false,
    socket,
    srcIp,
    intervalSecs: Math.max(5, parseInt(opts.intervalSecs, 10) || 125),
    maxRespMs: Math.max(1000, parseInt(opts.maxRespMs, 10) || 10000),
    force: !!opts.force,
    count: 0,
  });

  evaluateElection();           // decide active vs standby immediately
  if (querier.active) sendQuery('0.0.0.0'); // startup general query
  querier.sendTimer = setInterval(() => { if (querier.active) sendQuery('0.0.0.0'); },
                                  querier.intervalSecs * 1000);
  querier.electionTimer = setInterval(evaluateElection, 5000);
  emit({ ev: 'querier-ready', srcIp, intervalSecs: querier.intervalSecs, force: querier.force });
  emitQuerierState('started');
}

function stopQuerier() {
  if (!querier.running) return;
  if (querier.sendTimer) clearInterval(querier.sendTimer);
  if (querier.electionTimer) clearInterval(querier.electionTimer);
  querier.sendTimer = querier.electionTimer = null;
  if (querier.socket) { try { querier.socket.close(); } catch {} }
  querier.socket = null;
  querier.running = false;
  querier.active = false;
  emit({ ev: 'querier-stopped' });
}

function shutdown(code = 0) {
  stopQuerier();
  if (membershipTimer) { clearInterval(membershipTimer); membershipTimer = null; }
  if (capInstance) { try { capInstance.close(); } catch {} capInstance = null; }
  started = false;
  emit({ ev: 'stopped' });
  process.exit(code);
}

// ── stdin command loop ──────────────────────────────────────────────────────
function handleCommand(line) {
  line = line.trim();
  if (!line) return;
  let cmd;
  try { cmd = JSON.parse(line); } catch { return; }
  switch (cmd.cmd) {
    case 'start':         if (!started) startCapture(cmd.iface); break;
    case 'stop':          shutdown(0); break;
    case 'querier-start': startQuerier(cmd); break;
    case 'querier-stop':  stopQuerier(); break;
    case 'ping':          emit({ ev: 'pong' }); break;
    default: break;
  }
}

function runStdinLoop() {
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      handleCommand(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
    }
  });
  process.stdin.on('end', () => shutdown(0));
  process.stdin.on('close', () => shutdown(0));
  process.stdin.resume();
}

// ── Self-test (no root, no pcap) ────────────────────────────────────────────
function selftest() {
  let pass = 0, fail = 0;
  const check = (name, cond) => { if (cond) { pass++; } else { fail++; console.error('FAIL: ' + name); } };

  const u16 = n => [(n >> 8) & 0xff, n & 0xff];
  const ip = s => s.split('.').map(Number);

  // v2 general query
  let r = decodeIgmp('192.168.0.1', Buffer.from([0x11, 0x64, 0, 0, ...ip('0.0.0.0')]));
  check('v2 general query', r.length === 1 && r[0].kind === 'querier' && r[0].version === 2 && r[0].general === true);

  // v2 group-specific query
  r = decodeIgmp('192.168.0.1', Buffer.from([0x11, 0x64, 0, 0, ...ip('239.1.1.1')]));
  check('v2 group query', r[0].general === false && r[0].group === '239.1.1.1');

  // v1 query (maxResp 0)
  r = decodeIgmp('192.168.0.1', Buffer.from([0x11, 0x00, 0, 0, ...ip('0.0.0.0')]));
  check('v1 query', r[0].version === 1);

  // v3 query (12 bytes)
  r = decodeIgmp('192.168.0.1', Buffer.from([0x11, 0x64, 0, 0, ...ip('0.0.0.0'), 0x02, 0x64, 0, 0]));
  check('v3 query', r[0].version === 3 && r[0].general === true);

  // v2 report
  r = decodeIgmp('192.168.0.50', Buffer.from([0x16, 0, 0, 0, ...ip('239.5.5.5')]));
  check('v2 report', r[0].kind === 'report' && r[0].group === '239.5.5.5' && r[0].version === 2);

  // leave
  r = decodeIgmp('192.168.0.50', Buffer.from([0x17, 0, 0, 0, ...ip('239.5.5.5')]));
  check('leave', r[0].kind === 'leave' && r[0].group === '239.5.5.5');

  // v3 report, 1 EXCLUDE record (join)
  r = decodeIgmp('192.168.0.60', Buffer.from([
    0x22, 0, 0, 0, 0, 0, ...u16(1),       // header: type, resv, csum, resv, numRecords=1
    0x02, 0x00, ...u16(0), ...ip('239.2.2.2'), // record: EXCLUDE, auxLen 0, 0 sources, group
  ]));
  check('v3 report exclude', r.length === 1 && r[0].kind === 'report' && r[0].group === '239.2.2.2' && r[0].version === 3);

  // v3 report, INCLUDE with 0 sources == leave
  r = decodeIgmp('192.168.0.60', Buffer.from([
    0x22, 0, 0, 0, 0, 0, ...u16(1),
    0x01, 0x00, ...u16(0), ...ip('239.3.3.3'),
  ]));
  check('v3 include-empty == leave', r[0].kind === 'leave' && r[0].group === '239.3.3.3');

  // garbage / too short
  check('short buffer', decodeIgmp('1.2.3.4', Buffer.from([0x11])).length === 0);
  check('unknown type', decodeIgmp('1.2.3.4', Buffer.from([0x99, 0, 0, 0, 0, 0, 0, 0])).length === 0);

  // ── Querier: packet construction & checksums ──
  // IGMP body checksum must verify to 0 over the message.
  const body = buildIgmpV2Query('0.0.0.0', 10000);
  check('igmp body type/len', body[0] === 0x11 && body.length === 8);
  check('igmp checksum valid', checksum16(body, 0, 8) === 0);

  // IP header: IHL=6, Router Alert option present, header checksum verifies.
  const general = buildQueryPacket('192.168.0.5', '0.0.0.0', 10000);
  check('packet length 24+8', general.length === 32);
  check('ihl=6 (router alert)', (general[0] & 0x0f) === 6);
  check('ttl=1', general[8] === 1);
  check('proto=igmp', general[9] === 2);
  check('router alert option', general[20] === 0x94 && general[21] === 0x04);
  check('ip checksum valid', checksum16(general, 0, 24) === 0);
  check('dst = all-hosts', ip4(general, 16) === '224.0.0.1');

  // Group-specific query targets the group, not all-hosts.
  const gs = buildQueryPacket('192.168.0.5', '239.1.2.3', 10000);
  check('group query dst', ip4(gs, 16) === '239.1.2.3');

  // Round-trip: our own parser must decode the query we build.
  const rt = decodeIgmp('192.168.0.5', general.subarray(24));
  check('round-trip decode', rt.length === 1 && rt[0].kind === 'querier' && rt[0].general === true);
  const rtg = decodeIgmp('192.168.0.5', gs.subarray(24));
  check('round-trip group query', rtg[0].general === false && rtg[0].group === '239.1.2.3');

  // ── Querier election ──
  check('election: alone -> active', shouldBeActiveQuerier('192.168.0.50', []) === true);
  check('election: lower other -> standby', shouldBeActiveQuerier('192.168.0.50', ['192.168.0.10']) === false);
  check('election: higher other -> active', shouldBeActiveQuerier('192.168.0.50', ['192.168.0.90']) === true);
  check('election: ignore self', shouldBeActiveQuerier('192.168.0.50', ['192.168.0.50']) === true);

  console.log(`\nself-test: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

// ── Entry point ─────────────────────────────────────────────────────────────
function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--selftest')) { selftest(); return; }

  process.on('SIGTERM', () => shutdown(0));
  process.on('SIGINT', () => shutdown(0));
  process.on('uncaughtException', e => { emit({ ev: 'error', code: 'crash', message: e.message }); shutdown(1); });

  runStdinLoop();

  // Optional auto-start for standalone/manual testing and for the app, which
  // passes the interface on the command line so capture begins immediately.
  const i = argv.indexOf('--iface');
  if (i >= 0) startCapture(argv[i + 1] || '');
}

main();

module.exports = { // for external tests
  decodeIgmp, checksum16, buildIgmpV2Query, buildIpHeaderWithRA,
  buildQueryPacket, shouldBeActiveQuerier,
};
