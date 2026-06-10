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
    const code = /permission|denied|EACCES|root/i.test(e.message) ? 'eaccess' : 'open_failed';
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

function shutdown(code = 0) {
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
    case 'start': if (!started) startCapture(cmd.iface); break;
    case 'stop':  shutdown(0); break;
    case 'ping':  emit({ ev: 'pong' }); break;
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

module.exports = { decodeIgmp }; // for external tests
