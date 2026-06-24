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

const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');

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
    // Capture IGMP (IP proto 2) AND PTP (UDP 319/320) in one handle. The "igmp"
    // keyword doesn't compile reliably through this binding, so match proto 2.
    linkType = c.open(device, '(ip proto 2) or (udp port 319 or udp port 320) or (ether proto 0x88cc)', 10 * 1024 * 1024, captureBuf);
    if (typeof c.setMinBytes === 'function') c.setMinBytes(0);
  } catch (e) {
    const code = /permission|denied|not permitted|EACCES|EPERM|root/i.test(e.message) ? 'eaccess' : 'open_failed';
    emit({ ev: 'error', code, message: 'pcap open failed on ' + device + ': ' + e.message });
    return;
  }

  capInstance = c;
  started = true;
  ptpClocks.clear();
  ptpGmHistory.clear();
  lldpNeighbors.clear();
  emit({ ev: 'ready', device, linkType });

  c.on('packet', () => {
    try {
      let ipOff;
      if (linkType === 'ETHERNET') {
        const eth = decoders.Ethernet(captureBuf);
        if (eth.info.type === 0x88cc) { handleLldp(eth.info.srcmac, captureBuf, eth.offset); return; }
        if (eth.info.type !== PROTOCOL.ETHERNET.IPV4) return;
        ipOff = eth.offset;
      } else if (linkType === 'RAW') { ipOff = 0; }
      else if (linkType === 'NULL') { ipOff = 4; } // BSD loopback family header
      else { return; }

      const ip = decoders.IPV4(captureBuf, ipOff);
      const src = ip.info.srcaddr;
      const end = ip.offset + (ip.info.totallen - ip.hdrlen);
      if (end > captureBuf.length || end <= ip.offset) return;

      if (ip.info.protocol === 2) {                      // IGMP
        const igmp = Buffer.from(captureBuf.subarray(ip.offset, end));
        for (const rec of decodeIgmp(src, igmp)) handleRecord(rec);
      } else if (ip.info.protocol === 17) {              // UDP → PTP?
        const udp = decoders.UDP(captureBuf, ip.offset);
        if (udp.info.dstport !== 319 && udp.info.dstport !== 320) return;
        const pEnd = Math.min(end, udp.offset + (udp.info.length - 8));
        if (pEnd <= udp.offset) return;
        const rec = parsePtp(src, Buffer.from(captureBuf.subarray(udp.offset, pEnd)));
        if (rec) handlePtp(rec);
      }
    } catch (e) {
      log('packet decode error: ' + e.message);
    }
  });

  membershipTimer = setInterval(() => { pruneAndSnapshot(); ptpSnapshot(); lldpSnapshot(); }, 2000);
}

// ── PTP clock discovery (passive Announce sniff; v2 full, v1 best-effort) ─────
const PTP_TTL_MS = 30 * 1000;
const ptpClocks = new Map();   // "domain|clockId" -> { ...announce, lastSeenMs }
const ptpGmHistory = new Map(); // domain -> last grandmaster id (for failover alarm)
const lldpNeighbors = new Map(); // srcMac -> { ...tlvs, lastSeenMs }

function hexId(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(':');
}

function parsePtp(src, buf) {
  if (buf.length < 34) return null;
  // PTPv1 (IEEE 1588-2002): versionPTP is a UInt16 at bytes 0-1 == 0x0001.
  if (buf[0] === 0x00 && buf[1] === 0x01) {
    const control = buf[32];
    const srcUuid = buf.length >= 28 ? hexId(buf.subarray(22, 28)) : null;
    let gmUuid = null, stepsRemoved = null;
    if (control === 0 && buf.length >= 124) {            // v1 Sync carries GM fields
      gmUuid = hexId(buf.subarray(106, 112));            // grandmasterClockUuid (typical offset)
      stepsRemoved = (buf[122] << 8) | buf[123];
    }
    return { kind: 'announce', version: 1, domain: 0, srcClock: srcUuid || src,
             gmIdentity: gmUuid, stepsRemoved, gmPriority1: null, gmPriority2: null,
             gmClass: null, gmAccuracy: null, bestEffort: true };
  }
  // PTPv2 (IEEE 1588-2008): low nibble of byte 1 == 2.
  if ((buf[1] & 0x0f) !== 2) return null;
  const msgType = buf[0] & 0x0f;
  const domain = buf[4];
  const srcClock = hexId(buf.subarray(20, 28));
  if (msgType !== 0x0B) return { kind: 'seen', version: 2, domain, srcClock };   // non-Announce talker
  if (buf.length < 64) return null;
  return {
    kind: 'announce', version: 2, domain, srcClock,
    gmPriority1: buf[47], gmClass: buf[48], gmAccuracy: buf[49],
    gmVariance: (buf[50] << 8) | buf[51], gmPriority2: buf[52],
    gmIdentity: hexId(buf.subarray(53, 61)),
    stepsRemoved: (buf[61] << 8) | buf[62],
    timeSource: buf[63],
    logInterval: (buf[33] << 24) >> 24,   // logMessageInterval, sign-extended
  };
}

function handlePtp(rec) {
  if (!rec) return;
  const key = rec.domain + '|' + rec.srcClock;
  const prev = ptpClocks.get(key) || {};
  ptpClocks.set(key, { ...prev, ...rec, lastSeenMs: now() });
}

function ptpSnapshot() {
  const t = now();
  for (const [k, c] of ptpClocks) if (t - c.lastSeenMs > PTP_TTL_MS) ptpClocks.delete(k);
  if (!ptpClocks.size) return;

  const byDomain = new Map();
  for (const c of ptpClocks.values()) {
    if (!byDomain.has(c.domain)) byDomain.set(c.domain, []);
    byDomain.get(c.domain).push(c);
  }

  const domains = [];
  const alarms = [];
  for (const [domain, clocks] of byDomain) {
    const announcers = clocks.filter(c => c.kind === 'announce' && c.gmIdentity);
    // The grandmaster is the announcer whose own clock id == grandmasterIdentity
    // at stepsRemoved 0; otherwise the GM id that downstream announcers reference.
    let gmId = null;
    const selfGm = announcers.find(c => c.srcClock === c.gmIdentity);
    if (selfGm) gmId = selfGm.gmIdentity;
    else if (announcers.length) gmId = announcers.slice().sort((a, b) => (a.stepsRemoved || 0) - (b.stepsRemoved || 0))[0].gmIdentity;
    const gmRec = announcers.find(c => c.srcClock === gmId) || announcers.find(c => c.gmIdentity === gmId);

    // Alarm: more than one clock claiming grandmaster (steps 0, self==GM) in a domain.
    const selfGms = [...new Set(announcers.filter(c => c.srcClock === c.gmIdentity && (c.stepsRemoved || 0) === 0).map(c => c.srcClock))];
    if (selfGms.length > 1) {
      alarms.push({ domain, severity: 'error', type: 'dual-gm',
        message: 'Multiple grandmasters in domain ' + domain + ': ' + selfGms.join(', ') });
    }
    // Alarm: grandmaster changed since last snapshot (failover).
    if (gmId) {
      const prev = ptpGmHistory.get(domain);
      if (prev && prev !== gmId) {
        alarms.push({ domain, severity: 'warn', type: 'gm-change',
          message: 'Grandmaster changed in domain ' + domain + ': ' + prev + ' → ' + gmId });
      }
      ptpGmHistory.set(domain, gmId);
    }

    domains.push({
      domain,
      version: clocks[0].version,
      grandmaster: gmId ? {
        clock: gmId,
        priority1: gmRec ? gmRec.gmPriority1 : null,
        priority2: gmRec ? gmRec.gmPriority2 : null,
        clockClass: gmRec ? gmRec.gmClass : null,
        accuracy: gmRec ? gmRec.gmAccuracy : null,
        timeSource: gmRec ? gmRec.timeSource : null,
        announceIntervalS: gmRec && gmRec.logInterval != null ? +Math.pow(2, gmRec.logInterval).toFixed(3) : null,
        bestEffort: gmRec ? !!gmRec.bestEffort : false,
      } : null,
      clocks: clocks.map(c => ({
        clock: c.srcClock,
        version: c.version,
        stepsRemoved: c.stepsRemoved != null ? c.stepsRemoved : null,
        role: (c.kind === 'announce' && c.srcClock === gmId && (c.stepsRemoved || 0) === 0) ? 'grandmaster'
            : (c.kind === 'announce') ? 'boundary/master'
            : 'clock',
      })).sort((a, b) => (a.stepsRemoved || 0) - (b.stepsRemoved || 0)),
    });
  }
  emit({ ev: 'ptp', domains, alarms });
}

// ── LLDP neighbor discovery (Layer 2, EtherType 0x88cc) ──────────────────────
// Shows the directly-connected switch + port ("where am I plugged in"). LLDP is
// link-local (not forwarded), so this reflects our own uplink neighbor.
function lldpId(val) {
  if (!val || !val.length) return null;
  const subtype = val[0];
  const rest = val.subarray(1);
  if (subtype === 4 && rest.length === 6) return hexId(rest);   // MAC address
  const s = ascii(rest);
  return s || hexId(rest);
}
function ascii(b) {
  let out = '';
  for (let i = 0; i < b.length; i++) { const c = b[i]; if (c >= 0x20 && c < 0x7f) out += String.fromCharCode(c); }
  return out.trim() || null;
}

function parseLldp(buf, off) {
  const tlv = {};
  let i = off;
  while (i + 2 <= buf.length) {
    const type = (buf[i] >> 1) & 0x7f;
    const len = ((buf[i] & 0x01) << 8) | buf[i + 1];
    i += 2;
    if (type === 0) break;                       // end of LLDPDU
    if (i + len > buf.length) break;
    const val = buf.subarray(i, i + len);
    if (type === 1) tlv.chassisId = lldpId(val);
    else if (type === 2) tlv.portId = lldpId(val);
    else if (type === 4) tlv.portDesc = ascii(val);
    else if (type === 5) tlv.sysName = ascii(val);
    else if (type === 6) tlv.sysDesc = (ascii(val) || '').slice(0, 140) || null;
    i += len;
  }
  return tlv;
}

function handleLldp(srcMac, buf, off) {
  const tlv = parseLldp(buf, off);
  lldpNeighbors.set(srcMac || (tlv.chassisId || 'unknown'), { mac: srcMac, ...tlv, lastSeenMs: now() });
}

function lldpSnapshot() {
  const t = now();
  for (const [k, n] of lldpNeighbors) if (t - n.lastSeenMs > 120000) lldpNeighbors.delete(k);
  if (!lldpNeighbors.size) return;
  emit({ ev: 'lldp', neighbors: [...lldpNeighbors.values()].map(n => ({
    mac: n.mac, chassisId: n.chassisId, portId: n.portId,
    portDesc: n.portDesc, sysName: n.sysName, sysDesc: n.sysDesc,
  })) });
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

// ── DHCP detector (dgram, root for port 68) ──────────────────────────────────
// Read-only probe: broadcasts a few DHCPDISCOVERs (with distinct locally-
// administered MACs to sample the pool) and reports every DHCPOFFER — server IP,
// offered address, mask, gateway, DNS, lease, and a pool-range hint. Never sends
// a REQUEST, so it does not take a lease. Multiple responders == rogue DHCP.

const DHCP_MAGIC = [0x63, 0x82, 0x53, 0x63];

function buildDhcpDiscover(mac, xid) {
  const b = Buffer.alloc(244 + 16);
  b[0] = 1; b[1] = 1; b[2] = 6; b[3] = 0;        // op, htype, hlen, hops
  xid.copy(b, 4);                                 // xid
  b.writeUInt16BE(0x8000, 10);                    // flags: broadcast reply
  mac.copy(b, 28, 0, 6);                          // chaddr
  let o = 236;
  b[o++] = DHCP_MAGIC[0]; b[o++] = DHCP_MAGIC[1]; b[o++] = DHCP_MAGIC[2]; b[o++] = DHCP_MAGIC[3];
  b[o++] = 53; b[o++] = 1; b[o++] = 1;            // option 53 = DISCOVER
  const params = [1, 3, 6, 15, 28, 51, 54];       // mask, router, dns, domain, bcast, lease, server-id
  b[o++] = 55; b[o++] = params.length; for (const p of params) b[o++] = p;
  b[o++] = 255;                                   // end
  return b.subarray(0, o);
}

function parseDhcpReply(buf) {
  if (buf.length < 240 || buf[0] !== 2) return null;                       // BOOTREPLY
  if (!(buf[236] === 0x63 && buf[237] === 0x82 && buf[238] === 0x53 && buf[239] === 0x63)) return null;
  const yiaddr = ip4(buf, 16);
  const siaddr = ip4(buf, 20);
  const opt = {};
  let o = 240;
  while (o < buf.length) {
    const code = buf[o++];
    if (code === 255) break;
    if (code === 0) continue;
    const len = buf[o++]; if (o + len > buf.length) break;
    opt[code] = buf.subarray(o, o + len); o += len;
  }
  const ipOpt  = c => (opt[c] && opt[c].length >= 4) ? ip4(opt[c], 0) : null;
  const ipList = c => { const r = []; if (opt[c]) for (let i = 0; i + 4 <= opt[c].length; i += 4) r.push(ip4(opt[c], i)); return r; };
  const u32    = c => (opt[c] && opt[c].length >= 4) ? opt[c].readUInt32BE(0) : null;
  const str    = c => opt[c] ? opt[c].toString('utf8').replace(/\0+$/, '') : null;
  return {
    type: opt[53] ? opt[53][0] : null,            // 2 == OFFER
    yiaddr, siaddr,
    server: ipOpt(54) || (siaddr !== '0.0.0.0' ? siaddr : null),
    mask: ipOpt(1), router: ipOpt(3), dns: ipList(6),
    domain: str(15), broadcast: ipOpt(28), leaseSecs: u32(51),
  };
}

const dhcp = { sock: null, timer: null, servers: new Map(), offered: [] };

function ifaceMac(iface) {
  try {
    for (const addrs of Object.values(os.networkInterfaces())) {
      for (const a of addrs) {
        if (a.address === iface && a.mac) return Buffer.from(a.mac.split(':').map(h => parseInt(h, 16)));
      }
    }
  } catch {}
  return crypto.randomBytes(6);
}

function startDhcpDetect(iface, oneShot) {
  if (dhcp.sock) { emit({ ev: 'error', code: 'dhcp_running', message: 'DHCP detect already running' }); return; }
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  dhcp.sock = sock; dhcp.servers = new Map(); dhcp.offered = []; dhcp.oneShot = !!oneShot;

  sock.on('error', e => {
    const busy = /EADDRINUSE|EACCES/.test(e.message);
    emit({ ev: 'error', code: busy ? 'dhcp_port_busy' : 'dhcp_socket',
      message: busy ? 'Cannot bind UDP port 68 — a system DHCP client is using it. ' + e.message : e.message });
    stopDhcpDetect();
  });

  sock.on('message', msg => {
    const r = parseDhcpReply(msg);
    if (!r || r.type !== 2) return;               // OFFERs only
    if (!dhcp.servers.has(r.server || '?')) dhcp.servers.set(r.server || '?', r);
    dhcp.offered.push(r.yiaddr);
    emit({ ev: 'dhcp-offer', ...r });
  });

  sock.bind(68, () => {
    try { sock.setBroadcast(true); } catch {}
    emit({ ev: 'dhcp-ready', iface: iface || null });
    const baseMac = ifaceMac(iface);
    let n = 0;
    const sendOne = () => {
      if (!dhcp.sock || n >= 5) return;
      const mac = Buffer.from(baseMac); mac[0] = 0x02; mac[5] = (mac[5] + n) & 0xff;
      const pkt = buildDhcpDiscover(mac, crypto.randomBytes(4));
      sock.send(pkt, 0, pkt.length, 67, '255.255.255.255',
        err => { if (err) emit({ ev: 'error', code: 'dhcp_send', message: err.message }); });
      n++;
    };
    sendOne();
    const burst = setInterval(() => { if (n >= 5) { clearInterval(burst); return; } sendOne(); }, 300);
  });

  dhcp.timer = setTimeout(finishDhcp, 4500);
}

function finishDhcp() {
  let poolMin = null, poolMax = null;
  for (const ip of dhcp.offered) {
    if (poolMin === null || ipNum(ip) < ipNum(poolMin)) poolMin = ip;
    if (poolMax === null || ipNum(ip) > ipNum(poolMax)) poolMax = ip;
  }
  emit({
    ev: 'dhcp-done',
    servers: [...dhcp.servers.values()],
    count: dhcp.servers.size,
    offered: [...new Set(dhcp.offered)],
    poolMin, poolMax,
  });
  const oneShot = dhcp.oneShot;
  stopDhcpDetect();
  if (oneShot) shutdown(0);   // launched via --dhcp: this is a one-shot probe
}

function stopDhcpDetect() {
  if (dhcp.timer) { clearTimeout(dhcp.timer); dhcp.timer = null; }
  if (dhcp.sock) { try { dhcp.sock.close(); } catch {} dhcp.sock = null; }
}

function shutdown(code = 0) {
  stopDhcpDetect();
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
    case 'dhcp-detect':   startDhcpDetect(cmd.iface); break;
    case 'dhcp-stop':     stopDhcpDetect(); break;
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

  // ── DHCP: discover build + offer parse round-trip ──
  const xid = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const disc = buildDhcpDiscover(Buffer.from([2, 0, 0, 0, 0, 1]), xid);
  check('discover op/htype', disc[0] === 1 && disc[1] === 1 && disc[2] === 6);
  check('discover xid', disc[4] === 0xde && disc[7] === 0xef);
  check('discover broadcast flag', disc[10] === 0x80);
  check('discover magic', disc[236] === 0x63 && disc[239] === 0x63);
  check('discover msgtype DISCOVER', disc[240] === 53 && disc[242] === 1);

  // Synthetic OFFER: BOOTREPLY, yiaddr 10.0.0.55, opts: type=OFFER, mask, router, lease, server-id.
  const off = Buffer.alloc(300);
  off[0] = 2;                                     // BOOTREPLY
  [10, 0, 0, 55].forEach((b, k) => off[16 + k] = b);   // yiaddr
  off[236] = 0x63; off[237] = 0x82; off[238] = 0x53; off[239] = 0x63;
  let p = 240;
  off[p++] = 53; off[p++] = 1; off[p++] = 2;            // OFFER
  off[p++] = 1;  off[p++] = 4; [255,255,255,0].forEach(b => off[p++] = b);   // mask
  off[p++] = 3;  off[p++] = 4; [10,0,0,1].forEach(b => off[p++] = b);        // router
  off[p++] = 54; off[p++] = 4; [10,0,0,1].forEach(b => off[p++] = b);        // server id
  off[p++] = 51; off[p++] = 4; off.writeUInt32BE(86400, p); p += 4;          // lease
  off[p++] = 255;
  const parsed = parseDhcpReply(off);
  check('offer parsed', !!parsed && parsed.type === 2);
  check('offer yiaddr', parsed.yiaddr === '10.0.0.55');
  check('offer server', parsed.server === '10.0.0.1');
  check('offer mask', parsed.mask === '255.255.255.0');
  check('offer router', parsed.router === '10.0.0.1');
  check('offer lease', parsed.leaseSecs === 86400);
  check('non-reply rejected', parseDhcpReply(Buffer.from([1, 1, 6, 0])) === null);

  // ── PTP v2 Announce parse ──
  const ann = Buffer.alloc(64);
  ann[0] = 0x0B;                 // messageType = Announce
  ann[1] = 0x02;                 // versionPTP = 2
  ann[4] = 3;                    // domainNumber
  [0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11].forEach((b,k)=>ann[20+k]=b);  // sourcePortIdentity clock
  ann[47] = 128;                 // grandmasterPriority1
  ann[48] = 6;                   // clockClass (6 = locked to primary ref)
  ann[49] = 0x21;               // clockAccuracy
  ann[52] = 128;                 // grandmasterPriority2
  [0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11].forEach((b,k)=>ann[53+k]=b);  // grandmasterIdentity (== source → this IS the GM)
  ann[61] = 0x00; ann[62] = 0x00; // stepsRemoved = 0
  ann[63] = 0x20;               // timeSource (GPS)
  const p2 = parsePtp('10.0.0.9', ann);
  check('ptp v2 announce', !!p2 && p2.kind === 'announce' && p2.version === 2);
  check('ptp domain', p2.domain === 3);
  check('ptp gm identity', p2.gmIdentity === 'aa:bb:cc:dd:ee:ff:00:11');
  check('ptp self==gm (grandmaster)', p2.srcClock === p2.gmIdentity && p2.stepsRemoved === 0);
  check('ptp priority1', p2.gmPriority1 === 128 && p2.gmClass === 6);
  // Non-Announce PTP message still identifies a talker
  const sync = Buffer.alloc(34); sync[0] = 0x00; sync[1] = 0x02; sync[4] = 3;
  check('ptp non-announce seen', parsePtp('10.0.0.9', sync).kind === 'seen');
  check('ptp too short', parsePtp('1.2.3.4', Buffer.from([0])) === null);

  // ── LLDP neighbor parse ──
  const tlv = (type, valBytes) => {
    const len = valBytes.length;
    return [((type << 1) | (len >> 8)) & 0xff, len & 0xff, ...valBytes];
  };
  const mac = [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33];
  const name = [...'SW-CORE'].map(c => c.charCodeAt(0));
  const portName = [...'Gi1/0/12'].map(c => c.charCodeAt(0));
  const lldpBuf = Buffer.from([
    ...tlv(1, [0x04, ...mac]),          // Chassis ID (subtype 4 = MAC)
    ...tlv(2, [0x05, ...portName]),     // Port ID (subtype 5 = interface name)
    ...tlv(5, name),                    // System Name
    ...tlv(0, []),                      // End
  ]);
  const ll = parseLldp(lldpBuf, 0);
  check('lldp chassis (MAC)', ll.chassisId === 'aa:bb:cc:11:22:33');
  check('lldp port id', ll.portId === 'Gi1/0/12');
  check('lldp system name', ll.sysName === 'SW-CORE');

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

  const d = argv.indexOf('--dhcp');
  if (d >= 0) startDhcpDetect(argv[d + 1] || '', true);
}

main();

module.exports = { // for external tests
  decodeIgmp, checksum16, buildIgmpV2Query, buildIpHeaderWithRA,
  buildQueryPacket, shouldBeActiveQuerier,
  buildDhcpDiscover, parseDhcpReply,
  parsePtp, parseLldp,
};
