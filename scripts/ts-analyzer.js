'use strict';
/*
 * ts-analyzer.js — MPEG-TS health (TR 101 290 subset) + service/PID/PCR metadata.
 *
 * Pure JS, no dependencies. Feed it raw 188-byte TS bytes as they stream; call
 * snapshot() for rolling stats. Used by the embedded player (the same ffmpeg
 * remux that feeds mpegts.js is teed into this analyzer).
 *
 * Implements the most useful TR 101 290 checks:
 *   P1.1/1.2 sync loss / sync-byte error   P1.4 continuity-counter error
 *   P1.3 PAT error   P1.5 PMT error        P2.3 PCR repetition (>40ms)
 *   + transport-error (TEI), bitrate, PID table with stream types, service name.
 *
 * Self-test:  node scripts/ts-analyzer.js --selftest
 */

const PKT = 188;
const NULL_PID = 0x1fff;

function streamTypeName(t) {
  const m = {
    0x01: 'MPEG-1 video', 0x02: 'MPEG-2 video', 0x1b: 'H.264', 0x24: 'HEVC',
    0x03: 'MPEG-1 audio', 0x04: 'MPEG-2 audio', 0x0f: 'AAC (ADTS)', 0x11: 'AAC (LATM)',
    0x81: 'AC-3', 0x87: 'E-AC-3', 0x06: 'PES private (AC-3/subtitle/CC)', 0x05: 'private sections',
    0x15: 'metadata', 0x1c: 'MPEG-4 audio',
  };
  return m[t] || ('0x' + t.toString(16));
}

function createTsAnalyzer() {
  let pending = Buffer.alloc(0);
  let s = freshStats();

  function freshStats() {
    return {
      startMs: Date.now(), bytes: 0, packets: 0,
      syncErrors: 0, teiErrors: 0,
      ccErrors: 0, ccByPid: {}, lastCc: {}, countByPid: {},
      patSeenMs: 0, patCount: 0,
      pmtPids: new Set(), pmtSeenMs: {},
      pcrPid: null, lastPcr: null, pcrMaxIntervalMs: 0, pcrErrors: 0,
      streamTypes: {}, serviceName: null, provider: null,
    };
  }

  function feed(chunk) {
    s.bytes += chunk.length;
    pending = pending.length ? Buffer.concat([pending, chunk]) : Buffer.from(chunk);
    let i = 0;
    while (pending.length - i >= PKT) {
      if (pending[i] !== 0x47) {
        // Lost alignment — hunt for a 0x47 that has another 0x47 one packet later.
        const limit = Math.min(pending.length - PKT - 1, i + PKT * 8);
        let found = -1;
        for (let j = i + 1; j <= limit; j++) {
          if (pending[j] === 0x47 && pending[j + PKT] === 0x47) { found = j; break; }
        }
        s.syncErrors++;
        if (found < 0) { i = pending.length - (pending.length % PKT); break; }
        i = found;
        continue;
      }
      parsePacket(pending.subarray(i, i + PKT));
      i += PKT;
    }
    pending = pending.subarray(i);
    if (pending.length > PKT * 16) pending = Buffer.from(pending.subarray(pending.length - PKT * 16));
  }

  function parsePacket(p) {
    s.packets++;
    if (p[1] & 0x80) s.teiErrors++;                 // transport_error_indicator
    const pid = ((p[1] & 0x1f) << 8) | p[2];
    const afc = (p[3] >> 4) & 0x03;
    const cc = p[3] & 0x0f;
    s.countByPid[pid] = (s.countByPid[pid] || 0) + 1;

    let payloadOffset = 4;
    let discontinuity = false;
    if (afc === 2 || afc === 3) {
      const afLen = p[4];
      if (afLen > 0) {
        const flags = p[5];
        discontinuity = (flags & 0x80) !== 0;
        if ((flags & 0x10) && pid === s.pcrPid) {     // PCR present on the PCR PID
          const base = p[6] * 33554432 + (p[7] << 17) + (p[8] << 9) + (p[9] << 1) + (p[10] >> 7);
          const ext = ((p[10] & 0x01) << 8) | p[11];
          const pcr = base * 300 + ext;               // 27 MHz units
          if (s.lastPcr != null) {
            let d = pcr - s.lastPcr;
            if (d < 0) d += 8589934592 * 300;          // 33-bit base wrap
            const ms = d / 27000;
            if (ms > s.pcrMaxIntervalMs) s.pcrMaxIntervalMs = ms;
            if (ms > 40) s.pcrErrors++;                // P2.3 PCR repetition
          }
          s.lastPcr = pcr;
        }
      }
      payloadOffset = 5 + afLen;
    }
    const hasPayload = afc === 1 || afc === 3;

    // P1.4 continuity-counter error (per PID, payload packets only, dup allowed)
    if (hasPayload && pid !== NULL_PID) {
      const prev = s.lastCc[pid];
      if (prev != null && !discontinuity) {
        const expected = (prev + 1) & 0x0f;
        if (cc !== expected && cc !== prev) { s.ccErrors++; s.ccByPid[pid] = (s.ccByPid[pid] || 0) + 1; }
      }
      s.lastCc[pid] = cc;
    }

    if (!hasPayload || payloadOffset >= PKT) return;
    const pusi = (p[1] & 0x40) !== 0;

    if (pid === 0x0000) {                              // PAT
      s.patSeenMs = Date.now(); s.patCount++;
      psi(p, payloadOffset, pusi, (tableId, body) => {
        if (tableId !== 0x00) return;
        const end = sectionEnd(body);
        for (let k = 8; k + 4 <= end; k += 4) {
          const prog = (body[k] << 8) | body[k + 1];
          const pmtPid = ((body[k + 2] & 0x1f) << 8) | body[k + 3];
          if (prog !== 0) s.pmtPids.add(pmtPid);
        }
      });
    } else if (s.pmtPids.has(pid)) {                   // PMT
      s.pmtSeenMs[pid] = Date.now();
      psi(p, payloadOffset, pusi, (tableId, body) => {
        if (tableId !== 0x02) return;
        const pcrPid = ((body[8] & 0x1f) << 8) | body[9];
        if (pcrPid !== 0x1fff) s.pcrPid = pcrPid;
        const piLen = ((body[10] & 0x0f) << 8) | body[11];
        const end = sectionEnd(body);
        let k = 12 + piLen;
        while (k + 5 <= end) {
          const streamType = body[k];
          const ePid = ((body[k + 1] & 0x1f) << 8) | body[k + 2];
          const esLen = ((body[k + 3] & 0x0f) << 8) | body[k + 4];
          s.streamTypes[ePid] = streamType;
          k += 5 + esLen;
        }
      });
    } else if (pid === 0x0011) {                        // SDT (service name)
      psi(p, payloadOffset, pusi, (tableId, body) => {
        if (tableId !== 0x42) return;
        const info = sdtService(body);
        if (info) { s.serviceName = info.service || s.serviceName; s.provider = info.provider || s.provider; }
      });
    }
  }

  // body[] starts at table_id; section ends section_length-4 (before CRC32).
  function sectionEnd(body) {
    const sectionLen = ((body[1] & 0x0f) << 8) | body[2];
    return Math.min(body.length, 3 + sectionLen) - 4;
  }

  function psi(p, off, pusi, cb) {
    let i = off;
    if (pusi) { i += 1 + p[i]; }                       // skip pointer_field
    if (i + 3 >= PKT) return;
    const tableId = p[i];
    if (tableId === 0xff) return;
    const sectionLen = ((p[i + 1] & 0x0f) << 8) | p[i + 2];
    const end = Math.min(PKT, i + 3 + sectionLen);
    cb(tableId, p.subarray(i, end));
  }

  // Best-effort DVB SDT service descriptor (0x48) → provider + service name.
  function sdtService(body) {
    for (let i = 11; i + 2 < body.length; i++) {
      if (body[i] !== 0x48) continue;
      let k = i + 2;                                    // skip tag + descriptor_length
      k += 1;                                           // service_type
      if (k >= body.length) return null;
      const provLen = body[k++]; const provider = ascii(body, k, provLen); k += provLen;
      if (k >= body.length) return { provider, service: null };
      const svcLen = body[k++]; const service = ascii(body, k, svcLen);
      return { provider, service };
    }
    return null;
  }
  function ascii(b, off, len) {
    let out = '';
    for (let i = off; i < off + len && i < b.length; i++) { const c = b[i]; if (c >= 0x20 && c < 0x7f) out += String.fromCharCode(c); }
    return out.trim() || null;
  }

  function snapshot() {
    const elapsedMs = Math.max(1, Date.now() - s.startMs);
    const now = Date.now();
    const patOk = s.patSeenMs > 0 && (now - s.patSeenMs) < 1000;
    const pmtOk = s.pmtPids.size > 0 && [...s.pmtPids].every(pid => s.pmtSeenMs[pid] && (now - s.pmtSeenMs[pid]) < 1000);
    const pids = Object.keys(s.countByPid).map(Number).sort((a, b) => a - b).map(pid => ({
      pid, count: s.countByPid[pid],
      type: s.streamTypes[pid] != null ? streamTypeName(s.streamTypes[pid])
          : pid === 0 ? 'PAT' : s.pmtPids.has(pid) ? 'PMT' : pid === 0x11 ? 'SDT' : pid === NULL_PID ? 'null' : null,
    }));
    return {
      bitrateMbps: +((s.bytes * 8) / (elapsedMs / 1000) / 1e6).toFixed(2),
      packets: s.packets,
      service: s.serviceName, provider: s.provider,
      pcrPid: s.pcrPid,
      checks: {
        sync: { ok: s.syncErrors === 0, errors: s.syncErrors },
        tei:  { ok: s.teiErrors === 0, errors: s.teiErrors },
        cc:   { ok: s.ccErrors === 0, errors: s.ccErrors, byPid: s.ccByPid },
        pat:  { ok: patOk },
        pmt:  { ok: pmtOk, na: s.pmtPids.size === 0 },
        pcr:  { ok: s.pcrPid == null ? null : s.pcrErrors === 0, errors: s.pcrErrors,
                maxIntervalMs: +s.pcrMaxIntervalMs.toFixed(1), na: s.pcrPid == null },
      },
      pids,
    };
  }

  function reset() { s = freshStats(); pending = Buffer.alloc(0); }

  return { feed, snapshot, reset };
}

// ── Self-test ────────────────────────────────────────────────────────────────
function selftest() {
  let pass = 0, fail = 0;
  const check = (n, c) => { if (c) pass++; else { fail++; console.error('FAIL: ' + n); } };

  // Build a TS packet: pid, cc, payloadUnitStart, payload bytes.
  function pkt(pid, cc, pusi, payload = []) {
    const b = Buffer.alloc(PKT, 0xff);
    b[0] = 0x47;
    b[1] = ((pusi ? 0x40 : 0) | ((pid >> 8) & 0x1f));
    b[2] = pid & 0xff;
    b[3] = 0x10 | (cc & 0x0f);                          // afc=1 (payload only)
    let o = 4;
    if (pusi) b[o++] = 0x00;                            // pointer_field
    for (const x of payload) b[o++] = x;
    return b;
  }
  // PAT: program 1 → PMT pid 0x100
  function patSection() {
    return [0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00,
            0x00, 0x01, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00]; // prog=1 pmtpid=0x100 + dummy CRC
  }
  // PMT: pcr pid 0x100, one H.264 ES on 0x100
  function pmtSection() {
    return [0x02, 0xb0, 0x12, 0x00, 0x01, 0xc1, 0x00, 0x00,
            0xe1, 0x00,             // PCR_PID = 0x100
            0xf0, 0x00,             // program_info_length = 0
            0x1b, 0xe1, 0x00, 0xf0, 0x00, // stream_type 0x1b (H.264) ePid 0x100
            0x00, 0x00, 0x00, 0x00];      // dummy CRC
  }

  const a = createTsAnalyzer();
  a.feed(Buffer.concat([
    pkt(0x0000, 0, true, patSection()),
    pkt(0x0100, 0, true, pmtSection()),
    pkt(0x0100, 1, false, [0,0,1]),
    pkt(0x0100, 2, false, [0,0,1]),
  ]));
  let snap = a.snapshot();
  check('parsed packets', snap.packets === 4);
  check('PAT ok', snap.checks.pat.ok === true);
  check('PMT ok', snap.checks.pmt.ok === true);
  check('found PMT pid 0x100', snap.pids.some(p => p.pid === 0x100));
  check('H.264 stream type', snap.pids.some(p => p.type === 'H.264'));
  check('no CC errors yet', snap.checks.cc.errors === 0);

  // Induce a continuity-counter error on pid 0x100 (jump 2 → 5)
  const b = createTsAnalyzer();
  b.feed(Buffer.concat([
    pkt(0x0100, 0, false, [1]), pkt(0x0100, 1, false, [1]), pkt(0x0100, 5, false, [1]),
  ]));
  check('CC error detected', b.snapshot().checks.cc.errors === 1);

  // Sync-byte loss: prepend junk so the first packet isn't aligned
  const c = createTsAnalyzer();
  c.feed(Buffer.concat([Buffer.from([0x11, 0x22, 0x33]), pkt(0x0100, 0, false), pkt(0x0100, 1, false)]));
  check('sync error counted', c.snapshot().checks.sync.errors >= 1);

  console.log(`\nts-analyzer self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

if (require.main === module && process.argv.includes('--selftest')) selftest();

module.exports = { createTsAnalyzer, streamTypeName };
