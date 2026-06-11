const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path  = require('path');
const fs    = require('fs');
const os    = require('os');
const dgram = require('dgram');
const net   = require('net');

function findFfprobe() {
  if (process.platform === 'win32') {
    const c = ['C:\\ffmpeg\\bin\\ffprobe.exe','C:\\Program Files\\ffmpeg\\bin\\ffprobe.exe','C:\\ProgramData\\chocolatey\\bin\\ffprobe.exe','C:\\tools\\ffmpeg\\bin\\ffprobe.exe'];
    for (const p of c) if (fs.existsSync(p)) return p;
    return 'ffprobe.exe';
  }
  if (process.platform === 'darwin') {
    for (const p of ['/opt/homebrew/bin/ffprobe','/usr/local/bin/ffprobe','/usr/bin/ffprobe']) if (fs.existsSync(p)) return p;
  }
  return 'ffprobe';
}

function findFfmpeg() {
  if (process.platform === 'win32') {
    const c = ['C:\\ffmpeg\\bin\\ffmpeg.exe','C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe','C:\\ProgramData\\chocolatey\\bin\\ffmpeg.exe','C:\\tools\\ffmpeg\\bin\\ffmpeg.exe'];
    for (const p of c) if (fs.existsSync(p)) return p;
    return 'ffmpeg.exe';
  }
  if (process.platform === 'darwin') {
    for (const p of ['/opt/homebrew/bin/ffmpeg','/usr/local/bin/ffmpeg','/usr/bin/ffmpeg']) if (fs.existsSync(p)) return p;
  }
  return 'ffmpeg';
}

function findVlc() {
  if (process.platform === 'win32') {
    for (const p of ['C:\\Program Files\\VideoLAN\\VLC\\vlc.exe','C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe']) if (fs.existsSync(p)) return p;
    return 'vlc.exe';
  }
  if (process.platform === 'darwin') return '/Applications/VLC.app/Contents/MacOS/VLC';
  return 'vlc';
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1400, height: 920, minWidth: 1000, minHeight: 680,
    backgroundColor: '#0d0f0e',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
    title: 'Multicast Ring Tester', show: false,
  });
  win.loadFile('index.html');
  win.once('ready-to-show', () => win.show());
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('before-quit', () => { stopIgmpHelper(); stopDhcpHelper(); stopPlayerFfmpeg(); });

// ── ffprobe ───────────────────────────────────────────────────────────────────
function probeUrl(url, timeoutMs) {
  return new Promise(resolve => {
    const ffprobe = findFfprobe();
    const µs = Math.max(1000000, (timeoutMs - 1500) * 1000);
    const args = ['-v','quiet','-print_format','json','-show_streams','-show_format','-show_programs','-timeout',String(µs),'-fflags','nobuffer',url];
    let stdout = '';
    let proc;
    const kill = setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} resolve({ error: 'timeout' }); }, timeoutMs);
    try { proc = spawn(ffprobe, args); }
    catch (e) { clearTimeout(kill); resolve({ error: 'not_found', message: e.message }); return; }
    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.on('close', () => {
      clearTimeout(kill);
      if (!stdout) { resolve({ error: 'no_signal' }); return; }
      try { resolve({ ok: true, raw: JSON.parse(stdout) }); }
      catch { resolve({ error: 'parse_error' }); }
    });
    proc.on('error', err => { clearTimeout(kill); resolve({ error: 'not_found', message: err.message }); });
  });
}

ipcMain.handle('probe-stream', (_e, url) => probeUrl(url, 9000));

// A probe is a real A/V hit only if ffprobe actually found a video or audio
// stream. ffprobe will sometimes "open" a plain web server or empty endpoint and
// return ok with zero decodable streams — those are the Network Discovery false
// positives. This gate filters them and reports what was actually detected, so a
// hit is labeled by its true format/codec (e.g. "mjpeg") rather than the bucket
// it was probed under (e.g. "hls").
function avSummary(result) {
  if (!result || !result.ok || !result.raw) return null;
  const streams = result.raw.streams || [];
  const v = streams.find(s => s.codec_type === 'video');
  const a = streams.find(s => s.codec_type === 'audio');
  if (!v && !a) return null;
  return {
    format: (result.raw.format && result.raw.format.format_name) || '',
    vcodec: v ? (v.codec_name || '') : '',
    acodec: a ? (a.codec_name || '') : '',
    res: (v && v.width && v.height) ? v.width + 'x' + v.height : '',
  };
}

// ── Range scan ────────────────────────────────────────────────────────────────
let scanCtx = { running: false, cancel: false };

async function runScan(event, { prefix, start, end, port, iface, concurrency, probeSecs }) {
  const total = end - start + 1;
  const timeoutMs = Math.max(3000, ((parseInt(probeSecs)||5) * 1000) + 1000);
  const concurrent = Math.min(Math.max(1, parseInt(concurrency)||10), 24);
  const addrs = [];
  for (let i = start; i <= end; i++) addrs.push(prefix + '.' + i);
  let idx = 0, completed = 0, found = 0;
  const send = (ch, data) => { if (!event.sender.isDestroyed()) event.sender.send(ch, data); };
  async function worker() {
    while (idx < addrs.length && !scanCtx.cancel) {
      const ip = addrs[idx++];
      const base = 'udp://@' + ip + ':' + port;
      const url = iface ? base + '?localaddr=' + iface : base;
      const res = await probeUrl(url, timeoutMs);
      completed++;
      if (res.ok) found++;
      send('scan-result', { ip, port, url, result: res, progress: { completed, total, found } });
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrent, addrs.length) }, worker));
  scanCtx.running = false;
  send('scan-done', { total, completed, found, cancelled: scanCtx.cancel });
}

ipcMain.handle('start-scan', (event, params) => {
  if (scanCtx.running) return { error: 'already_running' };
  scanCtx = { running: true, cancel: false };
  runScan(event, params);
  return { ok: true };
});
ipcMain.handle('stop-scan', () => { scanCtx.cancel = true; return { ok: true }; });

// ── SAP ───────────────────────────────────────────────────────────────────────
let sapSock = null;
ipcMain.handle('start-sap', (event, { iface }) => {
  if (sapSock) return { error: 'already_running' };
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  const send = (ch, d) => { if (!event.sender.isDestroyed()) event.sender.send(ch, d); };
  sock.on('error', err => { send('sap-error', { message: err.message }); sock.close(); sapSock = null; });
  sock.on('message', (msg, rinfo) => { const p = parseSap(msg); if (p) send('sap-announce', { ...p, from: rinfo.address }); });
  sock.bind(9875, () => {
    try { sock.addMembership('224.2.127.254', iface || undefined); sock.setMulticastLoopback(false); send('sap-ready', {}); }
    catch (e) { send('sap-error', { message: 'Could not join SAP group: ' + e.message }); }
  });
  sapSock = sock;
  return { ok: true };
});
ipcMain.handle('stop-sap', () => { if (sapSock) { try { sapSock.close(); } catch {} sapSock = null; } return { ok: true }; });

function parseSap(buf) {
  if (buf.length < 8) return null;
  const flags = buf[0];
  if (((flags >> 5) & 0x07) !== 1) return null;
  if (flags & 0x04) return null;
  const authLen = buf[1];
  let offset = 8 + authLen * 4;
  if (offset >= buf.length) return null;
  let text = buf.slice(offset).toString('utf8');
  const nul = text.indexOf('\0');
  if (nul >= 0 && nul < 40) text = text.slice(nul + 1);
  return parseSdp(text);
}

function parseSdp(sdp) {
  const r = { name: null, address: null, port: null, mediaType: null };
  for (const raw of sdp.split(/\r?\n/)) {
    if (raw.length < 2 || raw[1] !== '=') continue;
    const k = raw[0], v = raw.slice(2).trim();
    if (k === 's') r.name = v || null;
    if (k === 'c') { const p = v.split(' '); if (p[2]) r.address = p[2].split('/')[0]; }
    if (k === 'm') { const p = v.split(' '); r.mediaType = p[0]; r.port = parseInt(p[1]) || null; }
  }
  return (r.address && r.port) ? r : null;
}

// ── TCP port check ────────────────────────────────────────────────────────────
function checkPort(host, port, timeoutMs) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let done = false;
    const finish = (val) => { if (!done) { done = true; sock.destroy(); resolve(val); } };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => finish(true));
    sock.on('timeout', () => finish(false));
    sock.on('error', () => finish(false));
    try { sock.connect(port, host); } catch { finish(false); }
  });
}

// ── Local subnet helper ───────────────────────────────────────────────────────
function getLocalSubnets() {
  const results = [];
  for (const [iface, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs) {
      if ((a.family === 'IPv4' || a.family === 4) && !a.internal) {
        // Derive network prefix (first 3 octets for /24-ish)
        const parts = a.address.split('.');
        const network = parts.slice(0, 3).join('.');
        results.push({ iface, address: a.address, network });
      }
    }
  }
  return results;
}

// ── Network Discovery Scan ────────────────────────────────────────────────────
let netScanCtx = { running: false, cancel: false };

async function runNetScan(event, params) {
  const { subnet, protocols = [], concurrency = 20, probeSecs = 3, udpPort = 4444 } = params;
  const timeoutMs = Math.max(3000, (parseInt(probeSecs) || 3) * 1000 + 1000);
  const concurrent = Math.min(Math.max(1, parseInt(concurrency) || 20), 50);
  const send = (ch, d) => { if (!event.sender.isDestroyed()) event.sender.send(ch, d); };

  const ips = [];
  for (let i = 1; i <= 254; i++) ips.push(subnet + '.' + i);
  const total = ips.length;
  let idx = 0, completed = 0, found = 0;

  async function worker() {
    while (idx < ips.length && !netScanCtx.cancel) {
      const ip = ips[idx++];
      const results = [];

      if (protocols.includes('rtsp')) {
        for (const port of [554, 8554]) {
          if (netScanCtx.cancel) break;
          const open = await checkPort(ip, port, 800);
          if (open) {
            const url = `rtsp://${ip}:${port}/`;
            const result = await probeUrl(url, timeoutMs);
            const av = avSummary(result);
            if (av) { results.push({ ip, port, url, protocol: 'rtsp', result, detected: av }); found++; }
          }
        }
      }

      if (protocols.includes('rtmp')) {
        if (!netScanCtx.cancel) {
          const port = 1935;
          const open = await checkPort(ip, port, 800);
          if (open) {
            const url = `rtmp://${ip}:${port}/live`;
            const result = await probeUrl(url, timeoutMs);
            const av = avSummary(result);
            if (av) { results.push({ ip, port, url, protocol: 'rtmp', result, detected: av }); found++; }
          }
        }
      }

      if (protocols.includes('hls')) {
        for (const port of [80, 8080, 8888]) {
          if (netScanCtx.cancel) break;
          const open = await checkPort(ip, port, 800);
          if (open) {
            const paths = ['/index.m3u8', '/hls', '/live', '/stream', '/'];
            for (const p of paths) {
              const url = `http://${ip}:${port}${p}`;
              const result = await probeUrl(url, timeoutMs);
              const av = avSummary(result);
              if (av) { results.push({ ip, port, url, protocol: 'hls', result, detected: av }); found++; break; }
            }
          }
        }
      }

      // NOTE: RTP is intentionally NOT scanned by IP here. `rtp://@ip:port`
      // makes ffmpeg bind LOCALLY and listen for inbound packets — it never
      // contacts the target IP, so a "hit" is just ambient RTP traffic stamped
      // with a meaningless address. Unicast RTP is discovered via SAP/SDP only.

      if (protocols.includes('udp')) {
        if (!netScanCtx.cancel) {
          const port = parseInt(udpPort) || 4444;
          const url = `udp://@${ip}:${port}`;
          const result = await probeUrl(url, timeoutMs);
          const av = avSummary(result);
          if (av) { results.push({ ip, port, url, protocol: 'udp', result, detected: av }); found++; }
        }
      }

      completed++;
      for (const r of results) {
        send('net-scan-result', { ...r, progress: { completed, total, found } });
      }
      send('net-scan-progress', { completed, total, found });
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrent, ips.length) }, worker));
  netScanCtx.running = false;
  send('net-scan-done', { total, completed, found, cancelled: netScanCtx.cancel });
}

ipcMain.handle('start-net-scan', (event, params) => {
  if (netScanCtx.running) return { error: 'already_running' };
  netScanCtx = { running: true, cancel: false };
  runNetScan(event, params);
  return { ok: true };
});
ipcMain.handle('stop-net-scan', () => { netScanCtx.cancel = true; return { ok: true }; });

// ── mDNS Listener ─────────────────────────────────────────────────────────────
let mdnsSock = null;

// kind:'device' means these are discovered endpoints, NOT directly probeable/playable
// URL streams. NDI needs the NDI SDK / a monitor; Dante/AES67/Ravenna need an AoIP receiver.
const MDNS_SERVICE_MAP = {
  '_ndi._tcp.local':      { protocol: 'ndi',     kind: 'device', urlFn: (ip, port, inst) => `ndi://${inst || ip}` },
  '_netaudio._tcp.local': { protocol: 'dante',   kind: 'device', urlFn: (ip, port) => `aes67://${ip}:${port}` },
  '_aes67._udp.local':    { protocol: 'aes67',   kind: 'device', urlFn: (ip, port) => `aes67://${ip}:${port}` },
  '_ravenna._tcp.local':  { protocol: 'ravenna', kind: 'device', urlFn: (ip, port) => `aes67://${ip}:${port}` },
};

function parseDnsName(buf, offset) {
  const parts = [];
  let jumped = false;
  let origOffset = offset;
  let safetyLimit = 128;

  while (offset < buf.length && safetyLimit-- > 0) {
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    if ((len & 0xC0) === 0xC0) {
      // Pointer
      if (offset + 1 >= buf.length) break;
      const ptr = ((len & 0x3F) << 8) | buf[offset + 1];
      if (!jumped) origOffset = offset + 2;
      offset = ptr;
      jumped = true;
    } else {
      offset++;
      if (offset + len > buf.length) break;
      parts.push(buf.slice(offset, offset + len).toString('utf8'));
      offset += len;
    }
  }
  if (!jumped) origOffset = offset;
  return { name: parts.join('.'), end: origOffset };
}

function parseDnsMessage(buf) {
  if (buf.length < 12) return null;
  const qdCount = (buf[4] << 8) | buf[5];
  const anCount = (buf[6] << 8) | buf[7];
  const nsCount = (buf[8] << 8) | buf[9];
  const arCount = (buf[10] << 8) | buf[11];

  let offset = 12;

  // Skip questions
  for (let i = 0; i < qdCount && offset < buf.length; i++) {
    const r = parseDnsName(buf, offset);
    offset = r.end;
    offset += 4; // qtype + qclass
  }

  const records = [];
  const totalRR = anCount + nsCount + arCount;

  for (let i = 0; i < totalRR && offset < buf.length; i++) {
    if (offset >= buf.length) break;
    const nameR = parseDnsName(buf, offset);
    offset = nameR.end;
    if (offset + 10 > buf.length) break;

    const type = (buf[offset] << 8) | buf[offset + 1];
    // const cls = (buf[offset+2] << 8) | buf[offset+3];
    const ttl = (buf[offset + 4] << 24) | (buf[offset + 5] << 16) | (buf[offset + 6] << 8) | buf[offset + 7];
    const rdlen = (buf[offset + 8] << 8) | buf[offset + 9];
    offset += 10;

    const rdStart = offset;
    const rdEnd = offset + rdlen;
    if (rdEnd > buf.length) break;

    let rdata = null;
    if (type === 12) {
      // PTR
      const r = parseDnsName(buf, offset);
      rdata = { type: 'PTR', name: nameR.name, target: r.name };
    } else if (type === 33) {
      // SRV
      if (rdlen >= 6) {
        const priority = (buf[offset] << 8) | buf[offset + 1];
        const weight   = (buf[offset + 2] << 8) | buf[offset + 3];
        const port     = (buf[offset + 4] << 8) | buf[offset + 5];
        const r = parseDnsName(buf, offset + 6);
        rdata = { type: 'SRV', name: nameR.name, priority, weight, port, target: r.name };
      }
    } else if (type === 1) {
      // A
      if (rdlen === 4) {
        const ip = `${buf[offset]}.${buf[offset+1]}.${buf[offset+2]}.${buf[offset+3]}`;
        rdata = { type: 'A', name: nameR.name, ip };
      }
    } else if (type === 16) {
      // TXT
      const txts = [];
      let p = offset;
      while (p < rdEnd) { const l = buf[p++]; if (p + l <= rdEnd) txts.push(buf.slice(p, p + l).toString('utf8')); p += l; }
      rdata = { type: 'TXT', name: nameR.name, txts };
    }
    if (rdata) records.push(rdata);
    offset = rdEnd;
  }
  return records;
}

function buildMdnsQuery(serviceType) {
  // Build minimal DNS query for PTR record
  const labels = serviceType.split('.');
  const nameBuf = [];
  for (const label of labels) {
    if (!label) continue;
    nameBuf.push(label.length);
    for (let i = 0; i < label.length; i++) nameBuf.push(label.charCodeAt(i));
  }
  nameBuf.push(0); // root

  const header = Buffer.from([
    0x00, 0x00, // ID
    0x00, 0x00, // flags: standard query
    0x00, 0x01, // QDCOUNT: 1
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
  ]);
  const question = Buffer.concat([
    Buffer.from(nameBuf),
    Buffer.from([0x00, 0x0C, 0x00, 0x01]) // QTYPE=PTR, QCLASS=IN
  ]);
  return Buffer.concat([header, question]);
}

ipcMain.handle('start-mdns', (event) => {
  if (mdnsSock) return { error: 'already_running' };
  const send = (ch, d) => { if (!event.sender.isDestroyed()) event.sender.send(ch, d); };

  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  sock.on('error', err => { send('mdns-error', { message: err.message }); sock.close(); mdnsSock = null; });

  // Track SRV/A records to correlate with PTR
  const srvMap = new Map(); // service instance name → port
  const aMap = new Map();   // hostname → ip

  sock.on('message', (msg, rinfo) => {
    let records;
    try { records = parseDnsMessage(msg); } catch { return; }
    if (!records) return;

    // Update SRV and A caches
    for (const r of records) {
      if (r.type === 'SRV') srvMap.set(r.name, { port: r.port, target: r.target });
      if (r.type === 'A') aMap.set(r.name, r.ip);
    }

    for (const r of records) {
      if (r.type !== 'PTR') continue;
      for (const [svcType, info] of Object.entries(MDNS_SERVICE_MAP)) {
        if (r.name.toLowerCase() !== svcType.toLowerCase()) continue;
        // r.target is the service instance name
        const instanceName = r.target;
        const srv = srvMap.get(instanceName);
        // Require a correlated SRV record so we have a real host+port, not a
        // guess based on whichever device happened to send the mDNS packet.
        // Without it we'd attribute the source to the wrong host with a fake port.
        if (!srv || !srv.port) continue;
        const target = srv.target;
        const ip = (target && aMap.get(target)) || rinfo.address;
        const instLabel = instanceName.split('.')[0];
        const url = info.urlFn(ip, srv.port, instLabel);
        send('mdns-announce', {
          ip, port: srv.port, protocol: info.protocol,
          kind: info.kind || 'device',
          host: target || null,
          name: instLabel,
          url,
        });
      }
    }
  });

  sock.bind(5353, () => {
    try {
      sock.addMembership('224.0.0.251');
      sock.setMulticastLoopback(false);
      // Send PTR queries for each service type
      for (const svcType of Object.keys(MDNS_SERVICE_MAP)) {
        const qbuf = buildMdnsQuery(svcType);
        sock.send(qbuf, 0, qbuf.length, 5353, '224.0.0.251');
      }
      send('mdns-ready', {});
    } catch (e) {
      send('mdns-error', { message: 'Could not join mDNS group: ' + e.message });
    }
  });

  mdnsSock = sock;
  return { ok: true };
});

ipcMain.handle('stop-mdns', () => {
  if (mdnsSock) { try { mdnsSock.close(); } catch {} mdnsSock = null; }
  return { ok: true };
});

// ── IGMP Detector (privileged helper) ───────────────────────────────────────
// Phase 1 of the Network Tools suite. The capture/raw work runs in a separate
// root process (scripts/net-helper.js) launched via pkexec on Linux; the GUI
// stays unprivileged. We relay the helper's line-delimited JSON events to the
// renderer. See docs/network-tools-design.md.
let igmpHelper = null;
let dhcpHelper = null;

// Resolve where the helper's Node binary + script live, returning real paths the
// root (pkexec'd) process can actually read.
//
// AppImage gotcha: an AppImage runs from a *private* FUSE mount (/tmp/.mount_*)
// that only the invoking user can read — so a root helper launched from there
// fails with "Permission denied" (exit 127). When we detect an AppImage, we
// copy Node + the helper script + the native modules into a normal directory
// under userData (which root can read) and launch from there. For .deb/dev the
// in-place paths are already real, so we use them directly.
function resolveHelper() {
  if (!app.isPackaged) {
    return { nodeBin: process.env.AVNS_NODE || 'node',
             helperPath: path.join(__dirname, 'scripts', 'net-helper.js') };
  }

  const srcNode = path.join(process.resourcesPath, 'node');
  const inPlace = { nodeBin: srcNode, helperPath: path.join(__dirname, 'scripts', 'net-helper.js') };
  const isAppImage = !!process.env.APPIMAGE || /\/\.mount_/.test(process.resourcesPath || '');

  if (!isAppImage) {
    try { fs.chmodSync(srcNode, 0o755); } catch {}
    return inPlace;
  }

  // AppImage: stage out of the FUSE mount (once per version).
  const stageDir = path.join(app.getPath('userData'), 'helper-' + app.getVersion());
  const dstNode = path.join(stageDir, 'node');
  const dstHelper = path.join(stageDir, 'net-helper.js');
  fs.mkdirSync(path.join(stageDir, 'node_modules'), { recursive: true });
  if (!fs.existsSync(dstNode)) fs.copyFileSync(srcNode, dstNode);
  fs.chmodSync(dstNode, 0o755);
  fs.copyFileSync(path.join(__dirname, 'scripts', 'net-helper.js'), dstHelper);
  for (const m of ['cap', 'raw-socket']) {
    const dstM = path.join(stageDir, 'node_modules', m);
    if (!fs.existsSync(dstM)) fs.cpSync(path.join(__dirname, 'node_modules', m), dstM, { recursive: true });
  }
  return { nodeBin: dstNode, helperPath: dstHelper };
}

// Build the (command, args) to launch the helper, choosing an elevation wrapper
// by platform. AVNS_NO_ELEVATE=1 runs it unprivileged (dev/CI only — pcap will
// fail with eaccess, which the UI surfaces).
function buildHelperSpawn(nodeBin, helperPath, extraArgs = []) {
  const helperArgs = [helperPath, ...extraArgs];
  if (process.env.AVNS_NO_ELEVATE === '1') return { cmd: nodeBin, args: helperArgs };
  if (process.platform === 'linux')  return { cmd: 'pkexec', args: [nodeBin, ...helperArgs] };
  if (process.platform === 'darwin') return { cmd: 'sudo',   args: ['-n', nodeBin, ...helperArgs] };
  return { cmd: nodeBin, args: helperArgs };
}

// Spawn the privileged helper with auto-start args, relaying its JSON events to
// the renderer. Shared by the IGMP detector and the DHCP detector.
function spawnHelper(extraArgs, send, opts) {
  let resolved;
  try { resolved = resolveHelper(); }
  catch (e) { return { error: 'stage_failed', message: 'could not prepare privileged helper: ' + e.message }; }
  const { cmd, args } = buildHelperSpawn(resolved.nodeBin, resolved.helperPath, extraArgs);

  let proc;
  try { proc = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (e) { return { error: 'spawn_failed', message: e.message }; }

  let buf = '';
  proc.stdout.on('data', d => {
    buf += d.toString();
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      let ev; try { ev = JSON.parse(line); } catch { continue; }
      relayHelperEvent(send, ev);
    }
  });
  proc.stderr.on('data', d => {
    const msg = d.toString().trim();
    if (msg) send(opts.errCh, { message: msg, source: 'stderr' });
  });
  proc.on('error', e => {
    let message = e.message;
    if (/ENOENT/.test(e.message)) {
      message = process.platform === 'linux'
        ? `${cmd} not found — install it (e.g. "sudo apt install pkexec" or "policykit-1"), then retry`
        : `${cmd} not found on PATH`;
    }
    send(opts.errCh, { code: 'elevation_failed', message });
    if (opts.onExit) opts.onExit(proc);
  });
  proc.on('exit', (code, sig) => {
    send(opts.stoppedCh, { code, signal: sig });
    if (opts.onExit) opts.onExit(proc);
  });
  return { proc };
}

function killHelper(p) {
  if (!p) return;
  // Closing stdin is the reliable stop signal even when the child is root and
  // we (unprivileged) can't signal it; SIGTERM is a backstop.
  try { p.stdin.end(); } catch {}
  try { p.kill('SIGTERM'); } catch {}
}
function stopIgmpHelper() { const p = igmpHelper; igmpHelper = null; killHelper(p); }
function stopDhcpHelper() { const p = dhcpHelper; dhcpHelper = null; killHelper(p); }

// ── IGMP detector ────────────────────────────────────────────────────────────
ipcMain.handle('igmp-detect-start', (event, { iface } = {}) => {
  if (igmpHelper) return { error: 'already_running' };
  const send = (ch, d) => { if (!event.sender.isDestroyed()) event.sender.send(ch, d); };
  const res = spawnHelper(['--iface', iface].filter(Boolean), send, {
    errCh: 'igmp-error', stoppedCh: 'igmp-stopped',
    onExit: proc => { if (igmpHelper === proc) igmpHelper = null; },
  });
  if (res.error) return res;
  igmpHelper = res.proc;
  return { ok: true };
});
ipcMain.handle('igmp-detect-stop', () => { stopIgmpHelper(); return { ok: true }; });

// Querier reuses the detector's helper process (it needs the capture for
// election + fast-leave), driven over that helper's stdin.
ipcMain.handle('igmp-querier-start', (_e, opts = {}) => {
  if (!igmpHelper) return { error: 'detector_not_running' };
  try { igmpHelper.stdin.write(JSON.stringify({ cmd: 'querier-start', ...opts }) + '\n'); }
  catch (e) { return { error: 'write_failed', message: e.message }; }
  return { ok: true };
});
ipcMain.handle('igmp-querier-stop', () => {
  if (igmpHelper) { try { igmpHelper.stdin.write(JSON.stringify({ cmd: 'querier-stop' }) + '\n'); } catch {} }
  return { ok: true };
});

// ── DHCP detector (its own short-lived helper; exits itself after the probe) ──
ipcMain.handle('dhcp-detect-start', (event, { iface } = {}) => {
  if (dhcpHelper) return { error: 'already_running' };
  const send = (ch, d) => { if (!event.sender.isDestroyed()) event.sender.send(ch, d); };
  const res = spawnHelper(['--dhcp', iface].filter(Boolean), send, {
    errCh: 'dhcp-error', stoppedCh: 'dhcp-stopped',
    onExit: proc => { if (dhcpHelper === proc) dhcpHelper = null; },
  });
  if (res.error) return res;
  dhcpHelper = res.proc;
  return { ok: true };
});
ipcMain.handle('dhcp-detect-stop', () => { stopDhcpHelper(); return { ok: true }; });

function relayHelperEvent(send, ev) {
  switch (ev.ev) {
    case 'ready':            send('igmp-ready', ev); break;
    case 'querier':          send('igmp-querier', ev); break;
    case 'membership':       send('igmp-membership', ev); break;
    case 'report':           send('igmp-report', ev); break;
    case 'leave':            send('igmp-leave', ev); break;
    case 'querier-ready':    send('igmp-querier-ready', ev); break;
    case 'querier-state':    send('igmp-querier-state', ev); break;
    case 'query-sent':       send('igmp-query-sent', ev); break;
    case 'querier-stopped':  send('igmp-querier-stopped', ev); break;
    case 'dhcp-ready':       send('dhcp-ready', ev); break;
    case 'dhcp-offer':       send('dhcp-offer', ev); break;
    case 'dhcp-done':        send('dhcp-done', ev); break;
    case 'error':            send(/^dhcp/.test(ev.code || '') ? 'dhcp-error' : 'igmp-error', ev); break;
    case 'log':              break; // helper diagnostics — ignored in the UI for now
    default:                 break;
  }
}

// ── Embedded player bridge (ffmpeg remux → localhost WebSocket → mpegts.js) ───
// Chromium cannot open udp/rtp/rtsp/MPEG-TS, so we remux the selected stream to
// MPEG-TS with ffmpeg (-c copy, no re-encode → original quality) and pipe it over
// a 127.0.0.1 WebSocket that mpegts.js plays in the renderer.
let playerWss = null, playerWsPort = 0, playerFfmpeg = null;
const playerClients = new Set();

function ensurePlayerWss() {
  if (playerWss) return Promise.resolve(playerWsPort);
  return new Promise((resolve, reject) => {
    let WebSocketServer;
    try { ({ WebSocketServer } = require('ws')); }
    catch (e) { reject(new Error('ws module missing: ' + e.message)); return; }
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    wss.on('connection', ws => {
      playerClients.add(ws);
      ws.on('close',  () => playerClients.delete(ws));
      ws.on('error',  () => playerClients.delete(ws));
    });
    wss.on('listening', () => { playerWss = wss; playerWsPort = wss.address().port; resolve(playerWsPort); });
    wss.on('error', reject);
  });
}

function stopPlayerFfmpeg() {
  if (!playerFfmpeg) return;
  const p = playerFfmpeg; playerFfmpeg = null;
  try { p.kill('SIGKILL'); } catch {}
}

function startPlayerFfmpeg(url, send) {
  stopPlayerFfmpeg();
  const ff = findFfmpeg();
  const pre = /^rtsp:/i.test(url) ? ['-rtsp_transport', 'tcp'] : [];
  // Remux (copy) the incoming TS/H.264 to clean MPEG-TS on stdout.
  const args = [...pre, '-fflags', 'nobuffer', '-flags', 'low_delay',
    '-i', url, '-c', 'copy', '-f', 'mpegts', '-muxdelay', '0', 'pipe:1'];
  let proc;
  try { proc = spawn(ff, args, { stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { send('player-error', { message: 'ffmpeg spawn failed: ' + e.message }); return; }
  playerFfmpeg = proc;
  proc.stdout.on('data', chunk => {
    for (const ws of playerClients) if (ws.readyState === 1) { try { ws.send(chunk); } catch {} }
  });
  let errTail = '';
  proc.stderr.on('data', d => { errTail = (errTail + d.toString()).slice(-500); });
  proc.on('error', e => send('player-error', { message: e.message }));
  proc.on('exit', (code, sig) => {
    if (playerFfmpeg === proc) playerFfmpeg = null;
    if (code && !sig) send('player-error', { message: 'ffmpeg exited (' + code + '): ' + (errTail.trim().split('\n').pop() || '') });
  });
}

ipcMain.handle('player-start', async (event, { url } = {}) => {
  if (!url) return { error: 'no_url' };
  const send = (ch, d) => { if (!event.sender.isDestroyed()) event.sender.send(ch, d); };
  let port;
  try { port = await ensurePlayerWss(); }
  catch (e) { return { error: 'ws_failed', message: e.message }; }
  startPlayerFfmpeg(url, send);
  return { ok: true, port };
});
ipcMain.handle('player-stop', () => { stopPlayerFfmpeg(); return { ok: true }; });

// ── Misc IPC ──────────────────────────────────────────────────────────────────
// Accepts either a bare url string (legacy) or { url, miface } where miface is
// the network interface NAME (e.g. "eth0"). For multicast we bind VLC's join to
// that NIC via --miface, and strip the ffmpeg-only ?localaddr= param VLC can't parse.
ipcMain.handle('launch-vlc', (_e, arg) => {
  let url = typeof arg === 'string' ? arg : (arg && arg.url) || '';
  const miface = (arg && typeof arg === 'object') ? arg.miface : null;
  if (!url) return { error: 'no_url' };

  // Remove ffmpeg-specific query params VLC doesn't understand (localaddr, etc.)
  url = url.replace(/[?&](localaddr|fifo_size|overrun_nonfatal|pkt_size)=[^&]*/gi, '')
           .replace(/\?&/, '?').replace(/[?&]$/, '');

  const isMulticast = /^(udp|rtp):\/\/@/i.test(url);
  const args = [];
  // --miface (VLC 3.x) selects the multicast interface by name. Only meaningful
  // for multicast joins; harmless to omit otherwise.
  if (miface && isMulticast) args.push('--miface=' + miface);
  args.push(url);

  try { const p = spawn(findVlc(), args, { detached: true, stdio: 'ignore' }); p.unref(); return { ok: true, args }; }
  catch (e) { return { error: e.message }; }
});

ipcMain.handle('save-m3u', async (_e, { content, defaultName }) => {
  const { filePath, canceled } = await dialog.showSaveDialog({
    defaultPath: defaultName,
    filters: [{ name: 'M3U Playlist', extensions: ['m3u'] }],
  });
  if (canceled || !filePath) return { cancelled: true };
  fs.writeFileSync(filePath, content, 'utf8');
  return { ok: true, filePath };
});

ipcMain.handle('get-env', () => {
  const fp = findFfprobe(), vl = findVlc();
  const nics = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs) {
      if ((a.family === 'IPv4' || a.family === 4) && !a.internal)
        nics.push({ name, address: a.address, netmask: a.netmask });
    }
  }
  return {
    platform: process.platform, ffprobe: fp,
    ffprobeFound: path.isAbsolute(fp) ? fs.existsSync(fp) : null,
    vlc: vl, vlcFound: path.isAbsolute(vl) ? fs.existsSync(vl) : null,
    nics,
    localSubnets: getLocalSubnets(),
    version: app.getVersion(),
  };
});
