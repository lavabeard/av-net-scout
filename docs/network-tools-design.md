# Network Tools — Design Spec (DHCP server · IGMP querier · Snooping detector)

Status: **draft / scoping**  ·  Target: **Linux-first**, macOS/Windows documented as future
Date: 2026-06-09

---

## 1. Why

AV-over-IP commissioning often happens on **isolated or unmanaged networks**: a
dumb switch, a single VLAN, no router. Two infrastructure roles are missing in
that scenario and are the most common cause of "the streams won't flow":

- **No DHCP server** → devices can't get addresses; engineers hand-set static IPs
  one at a time.
- **No IGMP querier** → snooping switches have nobody to query group membership,
  so they either flood all multicast (saturating the network) or prune it (streams
  die after the initial join expires).

Today the app is a multicast **client/analyzer** only — it *joins* groups (SAP on
`224.2.127.254`, mDNS on `224.0.0.251`) and probes streams. It does not provide
either infrastructure role. This spec adds three tools that let the app stand in
for that missing infrastructure on a lab/commissioning network:

| Tool | Role | Risk |
|---|---|---|
| **DHCP server** | Hand out IPs from a pool on a chosen NIC | High — must never run on a network that already has DHCP |
| **IGMP querier** | Periodically query group membership so snooping switches keep multicast alive | Medium — must defer to an existing querier (querier election) |
| **Querier / snooping detector** | Read-only: report whether a querier exists, its IP/version/interval, and observed memberships | Low — passive |

> ⚠️ **These are network-altering tools.** A second DHCP server or a competing
> querier on a production network is disruptive. The detector should be the
> default first action, and the active tools must require explicit acknowledgement.

---

## 2. UX — a new "Network Tools" tab

Add a fourth discovery-mode tab alongside the existing ones in `index.html`
(currently `tabRange`, `tabSap`, `tabNet` driven by `setMode()`):

```
⊞ Range Scan   ◎ SAP Listen   ⊕ Network Discovery   🛠 Network Tools
```

`setMode('tools')` reveals a panel with three sub-cards. Each card has:

- A NIC selector (reuse the existing interface picker fed by `getLocalSubnets()`).
- A **status pill** (stopped / running / elevation-required / error).
- Start/Stop, live status, and a results area.

### 2.1 DHCP server card
- Inputs: NIC, pool start/end, subnet mask, gateway (optional), DNS (optional),
  lease time. Sensible defaults pre-filled from the selected NIC's subnet.
- A **"This is an isolated/lab network"** checkbox that must be ticked to start.
- Live **lease table**: MAC · assigned IP · hostname · expiry. Persisted to
  `userData/dhcp-leases.json`.
- Pre-flight: passively listen ~3 s for an existing DHCP server; refuse to start
  (or hard-warn) if one is detected.

### 2.2 IGMP querier card
- Inputs: NIC, IGMP version (v2/v3), query interval (default 125 s per RFC),
  robustness/response time (advanced).
- Pre-flight: run the **detector** first. If another querier with a lower IP is
  present, show "deferring to existing querier (x.x.x.x)" and stay passive
  (standard IGMP querier election). Offer a "force" override for labs.
- Live: last-query-sent timestamp, query count, detected other queriers.

### 2.3 Detector card (read-only)
- Listens for IGMP general/group queries and membership reports.
- Reports: querier present? · querier IP · version · measured query interval ·
  per-group membership reporters seen. No elevation to *send*, but capture still
  needs rights (see §4).

---

## 3. IPC surface (follows existing conventions)

Mirror the current `ipcMain.handle` + `event.sender.send(...)` streaming pattern
and expose through `window.api` in `preload.js`.

```js
// preload.js additions
dhcp:   { start, stop, onLease, onReady, onError, onConflict },
querier:{ start, stop, onTick, onReady, onError, onOtherQuerier },
igmpDetect: { start, stop, onQuerier, onReport, onError },
```

| Channel | Direction | Payload |
|---|---|---|
| `dhcp-start` / `dhcp-stop` | invoke | `{ iface, poolStart, poolEnd, mask, gateway, dns, leaseSecs }` |
| `dhcp-lease` | main→renderer | `{ mac, ip, hostname, expiresAt }` |
| `dhcp-conflict` | main→renderer | `{ serverIp }` (existing DHCP detected) |
| `querier-start` / `querier-stop` | invoke | `{ iface, version, intervalSecs }` |
| `querier-tick` | main→renderer | `{ sentAt, count }` |
| `querier-other` | main→renderer | `{ ip, version }` |
| `igmp-detect-start` / `-stop` | invoke | `{ iface }` |
| `igmp-querier` | main→renderer | `{ ip, version, intervalSecs }` |
| `igmp-report` | main→renderer | `{ group, reporter }` |

All channels gain `*-ready` / `*-error` events like the SAP/mDNS handlers, so the
UI can show elevation-required and bind-failure states cleanly.

---

## 4. Privilege model (Linux-first)

All three tools need elevation:

- **DHCP server** binds UDP **port 67** (privileged) and sends broadcast.
- **IGMP querier** needs a **raw socket** (`AF_INET`, `IPPROTO_IGMP`) to craft
  queries with the IP **Router Alert** option and TTL 1. Node `dgram` cannot do
  this; requires the native **`raw-socket`** addon (or a helper binary).
- **Detector** must **receive** IGMP — either a raw `IPPROTO_IGMP` socket (recv
  only) or libpcap. Raw recv also needs root.

### Chosen approach: a privileged Node helper launched via `pkexec`

```
Electron (unprivileged)  ──spawn pkexec──▶  net-helper.js (root)
        │                                        │
        └────── line-delimited JSON over stdio ◀─┘   (or a unix socket in /run)
```

- `scripts/net-helper.js` implements the DHCP server, querier, and detector using
  `dgram` + `raw-socket`. It runs as root, started on demand via
  `pkexec node net-helper.js` (falling back to `sudo` if `pkexec` is absent).
- The Electron main process talks to the helper over **stdio JSON lines**, and
  relays to the renderer via the IPC channels above. Helper is killed on Stop /
  app quit.
- Rationale vs. alternatives:
  - *Run the whole app as root* — rejected (Electron-as-root is unsafe).
  - *`setcap` on the binary* — doesn't work inside an **AppImage** (read-only
    SquashFS, caps don't survive the FUSE mount). Helper-via-pkexec sidesteps this.
  - *Per-tool sudo prompts* — `pkexec` gives a graphical auth prompt and a clean
    one-shot elevation; preferred for desktop UX.

### AppImage specifics
- The bundled Node isn't on `PATH` as root. The helper is extracted/located via
  `process.resourcesPath`; we invoke `pkexec <bundled-node> <helper>` with an
  absolute path to the **bundled** Node (no reliance on a system `node`).
- `raw-socket` is a native addon built **once against the bundled Node's ABI**
  (not Electron's). The GUI process never loads `raw-socket` — only the helper
  does — so no `electron-rebuild` of it is required. (See §6.)

---

## 5. Per-tool technical detail

### 5.1 DHCP server (`dgram`, no raw sockets)
- Bind `0.0.0.0:67`, `setBroadcast(true)`, bind to NIC via `socket.bind(67, ifAddr)`
  and `SO_BINDTODEVICE` semantics where available.
- Parse BOOTP/DHCP: opcode, `xid`, `chaddr`, option 53 (msg type), 50 (requested
  IP), 12 (hostname), 55 (param req list).
- State machine: DISCOVER→OFFER, REQUEST→ACK/NAK, RELEASE/DECLINE handling.
- Allocation: first free address in pool; **ARP/ping conflict check** before
  offering; sticky leases keyed by MAC; persist to `userData/dhcp-leases.json`.
- Options served: 1 (mask), 3 (router), 6 (DNS), 51 (lease), 54 (server id), 28
  (broadcast). Keep minimal/AV-focused.
- Pre-flight conflict probe: send a DISCOVER as a client and listen ~3 s; if any
  OFFER returns, emit `dhcp-conflict` and refuse unless forced.

### 5.2 IGMP querier (`raw-socket`)
- Raw socket, `IPPROTO_IGMP`; set `IP_HDRINCL` or use the addon's header builder.
- Build **IGMPv2 General Query** (type `0x11`, max-resp-time, checksum, group
  `0.0.0.0`) to dest `224.0.0.1`, **TTL 1**, with **IP Router Alert** option
  (`0x94 0x04 0x00 0x00`). v3 query variant behind the version selector.
- Send every `intervalSecs` (default 125 s; startup burst per robustness var).
- **Querier election:** before sending, run the detector. If another querier is
  seen with a numerically lower source IP, stay silent (it wins). Re-arm if it
  disappears (no queries for ~2× interval). Lab "force" override available.

### 5.3 Detector (libpcap, promiscuous)
**Decision: libpcap-based promiscuous capture** (not raw IGMP recv) — so the
detector sees not just queries but **every device's membership reports**, giving
full "who is subscribing to what group" visibility (a raw `IPPROTO_IGMP` socket
only sees traffic addressed to the host, i.e. queries but not other hosts'
reports).
- Open a pcap handle on the selected NIC in promiscuous mode with BPF filter
  `igmp` (protocol 2). Needs root / `CAP_NET_RAW` → runs inside the same
  privileged helper.
- Parse the captured Ethernet→IP→IGMP frames. Classify by IGMP type: `0x11`
  query (→ querier present; src IP, max-resp-time ⇒ version), `0x16`/`0x22`
  reports (→ membership: reporter IP + group), `0x17` leave.
- Measure interval between successive queries to report the querier's cadence.
- Build a live **membership map**: group → list of reporter IPs (with last-seen).
- Emit `igmp-querier` / `igmp-report`. This card runs standalone as a pure
  diagnostic and is the recommended default before enabling the active tools.

---

## 6. Build / packaging implications

- Two native dependencies, both built against the **bundled Node** ABI:
  - **`raw-socket`** (node-gyp) — IGMP querier *send* (Phase 2).
  - a **libpcap binding** (e.g. `cap`/`pcap`, node-gyp) — detector capture
    (Phase 1). Build needs `libpcap-dev`; runtime libpcap ships on Linux/macOS.
  DHCP needs neither (pure `dgram`).
- The privileged helper runs under **Node**, not Electron, to keep elevation off
  the GUI process — so `raw-socket` must be built for the **Node ABI** that runs
  the helper. **Decision: bundle a known Node runtime in the AppImage** for the
  helper (not system Node). `raw-socket` is therefore built once against that
  bundled Node's ABI — self-contained, no user prerequisite, predictable. Cost:
  ~30–50 MB larger AppImage; we own bundled-Node updates.
- CI (`.github/workflows/build.yml`): add a native-build step (`python3`,
  build-essential, **`libpcap-dev`**) for `raw-socket` and the pcap binding;
  verify the helper loads both under the bundled Node in the Linux smoke test.
- **Decision: ship a polkit `.policy` file** (installed to
  `/usr/share/polkit-1/actions/com.avnetscout.helper.policy`) defining a single
  action for launching the helper. Gives a branded, clear prompt ("AV Net Scout
  needs administrator access to capture IGMP traffic and run network services"),
  a custom icon, and `auth_admin_keep` so the user isn't re-prompted every launch
  within the cache window. The `install.sh` one-liner drops this file (one-time
  elevated step); document a no-policy fallback to the default `pkexec` dialog if
  the file isn't installed.

---

## 7. Per-platform notes (future)

| | DHCP (UDP 67) | IGMP querier (raw) | Detector (capture) | Elevation |
|---|---|---|---|---|
| **Linux** (target) | `dgram`, root | `raw-socket`, root | raw recv / libpcap | `pkexec`/`sudo` |
| **macOS** | `dgram`, root | BSD raw socket, root | raw recv (root) | `osascript` auth or `sudo` |
| **Windows** | admin for :67 | raw sockets restricted → likely need **Npcap** | **Npcap** required | UAC / manifest |

Windows is the weakest fit: Winsock raw sockets can't send arbitrary IGMP easily,
so the querier/detector would depend on **Npcap**. Defer until Linux is solid.

---

## 8. Safety & guardrails (hard requirements)

1. **Detector-first default.** Active tools are gated behind a detector pass.
2. **Isolated-network acknowledgement** checkbox required to start DHCP/querier.
3. **DHCP conflict refusal** — never offer leases if another server answers.
4. **Querier election** — never fight an existing lower-IP querier unless forced.
5. **Clean teardown** — helper killed and sockets closed on Stop and app quit;
   no orphaned root process.
6. **Audit log** — every lease/query/elevation written to the in-app log panel.

---

## 9. Phasing

- **Phase 1 — Detector** (lowest risk, highest diagnostic value). Helper + raw
  recv + UI card. Proves the pkexec helper plumbing.
- **Phase 2 — IGMP querier** (reuses helper + raw socket; adds send + election).
- **Phase 3 — DHCP server** (pure `dgram`; lease store + conflict probe + UI).
- **Phase 4 — packaging hardening** (AppImage helper path, CI native build,
  polkit policy) and macOS port.

---

## 10. Open questions

- ~~Bundle a Node runtime for the helper, or require system Node ≥ 18 on Linux?~~
  **Resolved: bundle a known Node runtime in the AppImage** (self-contained;
  `raw-socket` built once against its ABI). See §4, §6.
- ~~Ship a polkit policy (smoother prompt) or accept the default `pkexec` dialog?~~
  **Resolved: ship a polkit `.policy`** (branded prompt, `auth_admin_keep` caching;
  installed by `install.sh`, with a default-dialog fallback). See §6.
- DHCP: how much option coverage do AV devices actually need beyond mask/router/DNS?
- Should the querier also send group-specific queries, or general-only (simpler)?
- ~~Detector via raw `IPPROTO_IGMP` recv (no extra dep) vs libpcap (richer, heavier)?~~
  **Resolved: libpcap promiscuous capture** for full membership visibility (queries
  + every device's reports). See §5.3, §6. Windows will require Npcap (§7).
