const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
  // Basic
  getEnv:        ()        => ipcRenderer.invoke('get-env'),
  probeStream:   (url)     => ipcRenderer.invoke('probe-stream', url),
  launchVlc:     (arg)     => ipcRenderer.invoke('launch-vlc', arg),
  saveM3u:       (c, n)    => ipcRenderer.invoke('save-m3u', { content: c, defaultName: n }),

  // Range scan
  startScan:     (params)  => ipcRenderer.invoke('start-scan', params),
  stopScan:      ()        => ipcRenderer.invoke('stop-scan'),
  onScanResult:  cb => ipcRenderer.on('scan-result',  (_, d) => cb(d)),
  onScanDone:    cb => ipcRenderer.on('scan-done',    (_, d) => cb(d)),

  // SAP
  startSap:      (iface)   => ipcRenderer.invoke('start-sap', { iface }),
  stopSap:       ()        => ipcRenderer.invoke('stop-sap'),
  onSapAnnounce: cb => ipcRenderer.on('sap-announce', (_, d) => cb(d)),
  onSapReady:    cb => ipcRenderer.on('sap-ready',    (_, d) => cb(d)),
  onSapError:    cb => ipcRenderer.on('sap-error',    (_, d) => cb(d)),

  // Network discovery scan
  startNetScan:  (params)  => ipcRenderer.invoke('start-net-scan', params),
  stopNetScan:   ()        => ipcRenderer.invoke('stop-net-scan'),
  onNetScanResult:   cb => ipcRenderer.on('net-scan-result',   (_, d) => cb(d)),
  onNetScanProgress: cb => ipcRenderer.on('net-scan-progress', (_, d) => cb(d)),
  onNetScanDone:     cb => ipcRenderer.on('net-scan-done',     (_, d) => cb(d)),

  // mDNS
  startMdns:     ()        => ipcRenderer.invoke('start-mdns'),
  stopMdns:      ()        => ipcRenderer.invoke('stop-mdns'),
  onMdnsAnnounce: cb => ipcRenderer.on('mdns-announce', (_, d) => cb(d)),
  onMdnsReady:    cb => ipcRenderer.on('mdns-ready',    (_, d) => cb(d)),
  onMdnsError:    cb => ipcRenderer.on('mdns-error',    (_, d) => cb(d)),

  // Network Tools — IGMP detector (privileged helper)
  igmp: {
    start: (iface)  => ipcRenderer.invoke('igmp-detect-start', { iface }),
    stop:  ()       => ipcRenderer.invoke('igmp-detect-stop'),
    onReady:      cb => ipcRenderer.on('igmp-ready',      (_, d) => cb(d)),
    onQuerier:    cb => ipcRenderer.on('igmp-querier',    (_, d) => cb(d)),
    onMembership: cb => ipcRenderer.on('igmp-membership', (_, d) => cb(d)),
    onReport:     cb => ipcRenderer.on('igmp-report',     (_, d) => cb(d)),
    onLeave:      cb => ipcRenderer.on('igmp-leave',      (_, d) => cb(d)),
    onError:      cb => ipcRenderer.on('igmp-error',      (_, d) => cb(d)),
    onStopped:    cb => ipcRenderer.on('igmp-stopped',    (_, d) => cb(d)),
    // Querier (active tool, same helper)
    querierStart: (opts) => ipcRenderer.invoke('igmp-querier-start', opts),
    querierStop:  ()     => ipcRenderer.invoke('igmp-querier-stop'),
    onQuerierReady:   cb => ipcRenderer.on('igmp-querier-ready',   (_, d) => cb(d)),
    onQuerierState:   cb => ipcRenderer.on('igmp-querier-state',   (_, d) => cb(d)),
    onQuerySent:      cb => ipcRenderer.on('igmp-query-sent',      (_, d) => cb(d)),
    onQuerierStopped: cb => ipcRenderer.on('igmp-querier-stopped', (_, d) => cb(d)),
  },

  removeListeners: ch => ipcRenderer.removeAllListeners(ch),
});
