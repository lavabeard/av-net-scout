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

  removeListeners: ch => ipcRenderer.removeAllListeners(ch),
});
