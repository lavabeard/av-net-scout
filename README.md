# Multicast Ring Tester

Desktop app for discovering, verifying, and labelling UDP multicast streams in professional AV/IT environments. Built with Electron — runs on macOS, Windows, and Linux.

---

## Features

- **Range Scan** — parallel ffprobe probe of an entire IP range (configurable concurrency and timeout). Live streams populate in real-time as they respond.
- **SAP Listen** — joins `224.2.127.254:9875` and captures SAP/SDP announcements. Encoders that broadcast SAP (Extron, Haivision, vMix, OBS with SAP plugin) appear automatically.
- **ffprobe Metadata** — every live stream shows video codec, resolution, fps, bitrate and audio codec, sample rate, channels pulled directly from the stream.
- **Editable Channel Names** — click any channel name field to label it. Names persist across app restarts via localStorage.
- **AI Name Import** — paste any format (channel list, spreadsheet, encoder config, free-form notes) and AI maps names to streams by IP address.
- **NIC Selector** — bind ffprobe and SAP to a specific network interface. Useful for multi-NIC machines with multicast on a dedicated VLAN.
- **Open All in VLC** — saves one M3U playlist with all live streams (including names and metadata in track titles).
- **Export M3U** — native save dialog, CRLF line endings, names as track titles.
- **Auto-Rotate** — cycles through live streams one at a time with a configurable dwell timer. Shows channel name in the status bar.
- **Sort** — by discovery order, IP address, bitrate, or name.

---

## Download

Pre-built installers are attached to each [GitHub Release](../../releases/latest):

| Platform | File |
|---|---|
| macOS (Apple Silicon + Intel) | `Multicast Ring Tester-x.x.x.dmg` |
| Windows | `Multicast Ring Tester Setup x.x.x.exe` |
| Linux | `Multicast Ring Tester-x.x.x.AppImage` or `.deb` |

---

## Prerequisites

The app itself requires no install beyond the package above. However:

### ffmpeg / ffprobe (required for stream probing)

**macOS:**
```bash
brew install ffmpeg
```

**Windows:**
```
winget install Gyan.FFmpeg
```
Or download from https://ffmpeg.org/download.html and add `bin/` to PATH.

**Linux (Ubuntu/Debian):**
```bash
sudo apt install ffmpeg
```

### VLC (required for stream playback)

Download from https://www.videolan.org — the app detects VLC in its default install location automatically.

---

## Build from Source

Requires Node.js 18+.

```bash
git clone https://github.com/lavabeard/Multicast-ring-analyzer.git
cd multicast-ring-tester
npm install
```

### Run in development
```bash
npm start
```

### Build installers

```bash
npm run dist:mac     # macOS DMG (must run on macOS)
npm run dist:win     # Windows NSIS installer (must run on Windows, or use CI)
npm run dist:linux   # Linux AppImage + deb
```

Output goes to `dist/`.

---

## CI/CD — GitHub Actions

Every push to `main` automatically builds all three platforms in parallel. Installers are uploaded as workflow artifacts.

**To create a release with downloadable installers:**

```bash
git tag v2.2.0
git push origin v2.2.0
```

This triggers the release job which attaches all three platform builds to a GitHub Release.

### Required secrets (for signed builds — optional)

Unsigned builds work fine for internal/single-machine use. For distribution add:

| Secret | Description |
|---|---|
| `CSC_LINK` | macOS: base64-encoded .p12 certificate |
| `CSC_KEY_PASSWORD` | macOS: certificate password |
| `WIN_CSC_LINK` | Windows: base64-encoded .pfx certificate |
| `WIN_CSC_KEY_PASSWORD` | Windows: certificate password |

Add these under **Settings → Secrets → Actions** in your GitHub repo.

---

## Network Notes

- The machine running this app must be on the same VLAN as the multicast traffic.
- Stream URLs use `udp://@IP:PORT` — the `@` is mandatory for multicast group join.
- For a specific VLAN interface, enter that interface's IP in the **NIC / Interface** field. This appends `?localaddr=X.X.X.X` to ffprobe and VLC calls.
- SAP listener joins `224.2.127.254:9875` — ensure UDP port 9875 is reachable on the selected interface.
- ffprobe probe timeout defaults to 5s. Increase if streams are slow to announce.

---

## AI Name Import

The **Import Names** feature uses the Anthropic API (Claude Haiku) to parse pasted data and map names to channel IPs. You need an Anthropic API key:

1. Get a key at https://console.anthropic.com
2. Open **Import Names** in the app
3. Enter your key — it is saved locally and never sent anywhere except Anthropic's API

The AI can parse any format: channel spreadsheets, encoder configs, free-form notes, mixed data.

---

## Stack

- [Electron](https://www.electronjs.org/) — cross-platform desktop shell
- [electron-builder](https://www.electron.build/) — packaging and installers
- [ffprobe](https://ffmpeg.org/ffprobe.html) — stream metadata (spawned as subprocess)
- [VLC](https://www.videolan.org/) — stream playback (spawned as subprocess)
- Node.js `dgram` — SAP/SDP UDP listener
- Anthropic Claude Haiku — AI name parsing

---

## License

MIT — Alpha AV/IT

---

## Upgrading

Upgrade scripts back up your existing installation **and** your Electron user data (localStorage, window state) before installing the new version.

### Linux / macOS

```bash
git clone https://github.com/lavabeard/Multicast-ring-analyzer.git
cd Multicast-ring-analyzer
./scripts/upgrade.sh
```

Flags:

| Flag | Meaning |
|---|---|
| _(none)_ | Pull latest git, build, back up old install, install new |
| `--from-dist` | Skip git pull and build — install from an existing `dist/` folder |
| `--dry-run` | Print every action without making any changes |

Backups are saved to `~/.local/share/multicast-ring-tester-backups/<timestamp>/` (Linux) or `~/Library/Application Support/` equivalent (macOS).

### Windows (PowerShell)

```powershell
git clone https://github.com/lavabeard/Multicast-ring-analyzer.git
cd Multicast-ring-analyzer
.\scripts\upgrade.ps1
```

Same flags: `-FromDist`, `-DryRun`.  
Backups land in `%LOCALAPPDATA%\multicast-ring-tester-backups\<timestamp>\`.

---

## Linux Testing (Docker)

A self-contained Docker build runs a clean Ubuntu 22.04 environment, installs all Electron dependencies, builds the Linux AppImage + deb, and smoke-tests that the artifacts are valid and ffprobe is reachable.

**Build and test:**
```bash
docker build -f Dockerfile.linux-test -t mcast-linux-test .
docker run --rm mcast-linux-test
```

**Copy artifacts out:**
```bash
docker create --name mcast-artifacts mcast-linux-test
docker cp mcast-artifacts:/artifacts ./docker-dist
docker rm mcast-artifacts
ls docker-dist/
# Multicast Ring Tester-x.x.x.AppImage
# multicast-ring-tester_x.x.x_amd64.deb
```

This is also what CI runs on every push to `main` — see `.github/workflows/build.yml`.
