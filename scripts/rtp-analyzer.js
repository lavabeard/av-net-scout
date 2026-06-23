'use strict';
/*
 * rtp-analyzer.js — RTP / AES67 stream health (RFC 3550).
 *
 * Pure JS, no dependencies. Feed it RTP packets (the UDP payload) with their
 * arrival time; call snapshot() for rolling per-SSRC stats:
 *   packet loss %, lost count, reordered/duplicate, interarrival jitter (ms),
 *   payload type, packet rate. Used for AES67/Ravenna multicast audio.
 *
 * Self-test:  node scripts/rtp-analyzer.js --selftest
 */

const RTP_SEQ_MOD = 0x10000;
const MAX_DROPOUT = 3000;
const MAX_MISORDER = 100;

function createRtpAnalyzer(clockRate = 48000) {
  const ssrcs = new Map();
  let startMs = Date.now();

  function feed(buf, arrivalMs) {
    if (!buf || buf.length < 12) return;
    if ((buf[0] >> 6) !== 2) return;                       // RTP version 2
    const pt = buf[1] & 0x7f;
    const seq = (buf[2] << 8) | buf[3];
    const ts = (buf[4] * 16777216) + (buf[5] << 16) + (buf[6] << 8) + buf[7];
    const ssrc = ((buf[8] * 16777216) + (buf[9] << 16) + (buf[10] << 8) + buf[11]) >>> 0;
    const now = arrivalMs != null ? arrivalMs : Date.now();

    let st = ssrcs.get(ssrc);
    if (!st) {
      st = { pt, baseSeq: seq, maxSeq: seq, cycles: 0, received: 0,
             reordered: 0, dup: 0, lastSeqExt: seq, jitter: 0, transit: null,
             firstMs: now, lastMs: now, lastSeq: seq };
      ssrcs.set(ssrc, st);
    }
    st.pt = pt;
    st.received++;
    st.lastMs = now;

    // RFC 3550 sequence tracking
    const udelta = (seq - st.maxSeq) & 0xffff;
    if (udelta === 0 && st.received > 1) {
      st.dup++;                                             // duplicate of current highest seq
    } else if (udelta < MAX_DROPOUT) {
      if (seq < st.maxSeq) st.cycles += RTP_SEQ_MOD;        // wrapped
      st.maxSeq = seq;
    } else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
      st.reordered++;                                       // large jump (restart/misorder)
    } else {
      if (seq === st.lastSeq) st.dup++; else st.reordered++;
    }
    st.lastSeq = seq;

    // RFC 3550 interarrival jitter
    const arrivalTs = now * (clockRate / 1000);
    const transit = arrivalTs - ts;
    if (st.transit != null) {
      let d = transit - st.transit;
      if (d < 0) d = -d;
      st.jitter += (d - st.jitter) / 16;
    }
    st.transit = transit;
  }

  function snapshot() {
    const streams = [];
    for (const [ssrc, st] of ssrcs) {
      const extMax = st.cycles + st.maxSeq;
      const expected = extMax - st.baseSeq + 1;
      const lost = Math.max(0, expected - st.received);
      const lossPct = expected > 0 ? (lost / expected) * 100 : 0;
      const durS = Math.max(0.001, (st.lastMs - st.firstMs) / 1000);
      streams.push({
        ssrc: '0x' + ssrc.toString(16).padStart(8, '0'),
        pt: st.pt,
        received: st.received,
        expected,
        lost,
        lossPct: +lossPct.toFixed(3),
        reordered: st.reordered,
        dup: st.dup,
        jitterMs: +(st.jitter * 1000 / clockRate).toFixed(3),
        pps: Math.round(st.received / durS),
      });
    }
    return { clockRate, streams };
  }

  function reset() { ssrcs.clear(); startMs = Date.now(); }
  return { feed, snapshot, reset };
}

// ── Self-test ────────────────────────────────────────────────────────────────
function selftest() {
  let pass = 0, fail = 0;
  const check = (n, c) => { if (c) pass++; else { fail++; console.error('FAIL: ' + n); } };

  function rtp(seq, ts, ssrc, pt = 97) {
    const b = Buffer.alloc(16);
    b[0] = 0x80; b[1] = pt & 0x7f;
    b[2] = (seq >> 8) & 0xff; b[3] = seq & 0xff;
    b[4] = (ts >>> 24) & 0xff; b[5] = (ts >> 16) & 0xff; b[6] = (ts >> 8) & 0xff; b[7] = ts & 0xff;
    b[8] = (ssrc >>> 24) & 0xff; b[9] = (ssrc >> 16) & 0xff; b[10] = (ssrc >> 8) & 0xff; b[11] = ssrc & 0xff;
    return b;
  }

  // Clean run: seq 0..4, 48 ts units apart, 1ms apart → no loss
  const a = createRtpAnalyzer(48000);
  for (let i = 0; i < 5; i++) a.feed(rtp(i, i * 48, 0x11223344), i);
  let snap = a.snapshot();
  check('one ssrc', snap.streams.length === 1);
  check('5 received', snap.streams[0].received === 5);
  check('no loss', snap.streams[0].lost === 0 && snap.streams[0].lossPct === 0);
  check('pt parsed', snap.streams[0].pt === 97);

  // Loss: skip seq 3 (0,1,2,4) → expected 5, received 4, lost 1
  const b = createRtpAnalyzer(48000);
  [0, 1, 2, 4].forEach((s, i) => b.feed(rtp(s, s * 48, 0x55), i));
  snap = b.snapshot();
  check('loss detected', snap.streams[0].lost === 1);
  check('loss pct ~20%', Math.abs(snap.streams[0].lossPct - 20) < 0.01);

  // Duplicate
  const c = createRtpAnalyzer();
  [0, 1, 1, 2].forEach((s, i) => c.feed(rtp(s, s * 48, 0x77), i));
  check('dup detected', c.snapshot().streams[0].dup === 1);

  // Two SSRCs tracked independently
  const d = createRtpAnalyzer();
  d.feed(rtp(0, 0, 0xaa), 0); d.feed(rtp(0, 0, 0xbb), 0);
  check('two ssrcs', d.snapshot().streams.length === 2);

  // Non-RTP / short rejected
  const e = createRtpAnalyzer();
  e.feed(Buffer.from([0, 1, 2]), 0); e.feed(Buffer.alloc(16), 0); // v=0 rejected
  check('garbage rejected', e.snapshot().streams.length === 0);

  console.log(`\nrtp-analyzer self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

if (require.main === module && process.argv.includes('--selftest')) selftest();

module.exports = { createRtpAnalyzer };
