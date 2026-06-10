#!/usr/bin/env bash
# install.sh — Multicast Ring Analyzer installer for Linux
#
# Run directly:
#   bash install.sh
#
# Or one-liner from GitHub:
#   curl -fsSL https://raw.githubusercontent.com/lavabeard/multicast-ring-analyzer/main/install.sh | bash
#
# Flags:
#   --dry-run        show every action without making changes
#   --uninstall      remove the app (keeps user data)
#   --purge          remove the app AND user data
#   --no-deps        skip dependency checks/installs

set -euo pipefail

# ── config ─────────────────────────────────────────────────────────────────────
APP_NAME="Multicast Ring Analyzer"
APP_ID="multicast-ring-analyzer"
REPO="lavabeard/multicast-ring-analyzer"
INSTALL_DIR="$HOME/Applications"
APPIMAGE_PATH="$INSTALL_DIR/$APP_NAME.AppImage"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/$APP_ID.desktop"
USER_DATA="${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME"
BACKUP_BASE="$HOME/.local/share/$APP_ID-backups"
STAMP="$(date +%Y%m%d_%H%M%S)"

DRY_RUN=false
UNINSTALL=false
PURGE=false
SKIP_DEPS=false

# ── parse args ─────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=true ;;
    --uninstall) UNINSTALL=true ;;
    --purge)     PURGE=true; UNINSTALL=true ;;
    --no-deps)   SKIP_DEPS=true ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--uninstall] [--purge] [--no-deps]"
      echo ""
      echo "  (no flags)   Install or upgrade $APP_NAME"
      echo "  --dry-run    Show what would happen without making changes"
      echo "  --uninstall  Remove the app (keeps your channel names and settings)"
      echo "  --purge      Remove the app and all user data"
      echo "  --no-deps    Skip dependency checks"
      exit 0
      ;;
  esac
done

# ── colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
step()    { echo -e "${BOLD}${CYAN}[→]${RESET} $*"; }
error()   { echo -e "${RED}[✘]${RESET} $*" >&2; exit 1; }
dry()     { echo -e "${CYAN}[dry-run]${RESET} $*"; }
run()     { if $DRY_RUN; then dry "$*"; else "$@"; fi; }
run_cmd() { if $DRY_RUN; then dry "$*"; else eval "$*"; fi; }

# ── root check ─────────────────────────────────────────────────────────────────
SUDO=""
if [[ $EUID -ne 0 ]]; then
  if command -v sudo &>/dev/null; then
    SUDO="sudo"
  fi
fi

# ── detect architecture ────────────────────────────────────────────────────────
detect_arch() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64)          echo "x64" ;;
    aarch64|arm64)   echo "arm64" ;;
    armv7l|armhf)    echo "armv7l" ;;
    *)               echo "unknown:$machine" ;;
  esac
}

# ── detect distro ──────────────────────────────────────────────────────────────
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

detect_distro_name() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${PRETTY_NAME:-${NAME:-Unknown Linux}}"
  else
    echo "Unknown Linux"
  fi
}

# ── detect package manager ─────────────────────────────────────────────────────
detect_pm() {
  if   command -v apt-get &>/dev/null; then echo "apt"
  elif command -v dnf     &>/dev/null; then echo "dnf"
  elif command -v yum     &>/dev/null; then echo "yum"
  elif command -v pacman  &>/dev/null; then echo "pacman"
  elif command -v zypper  &>/dev/null; then echo "zypper"
  else echo "unknown"
  fi
}

pm_install() {
  local pkg="$1"
  local pm
  pm="$(detect_pm)"
  case "$pm" in
    apt)    run $SUDO apt-get install -y "$pkg" ;;
    dnf)    run $SUDO dnf install -y "$pkg" ;;
    yum)    run $SUDO yum install -y "$pkg" ;;
    pacman) run $SUDO pacman -S --noconfirm "$pkg" ;;
    zypper) run $SUDO zypper install -y "$pkg" ;;
    *)      warn "Unknown package manager — install $pkg manually"; return 1 ;;
  esac
}

# ── system detection ───────────────────────────────────────────────────────────
SYS_ARCH="$(detect_arch)"
SYS_DISTRO="$(detect_distro)"
SYS_DISTRO_NAME="$(detect_distro_name)"
SYS_PM="$(detect_pm)"

# ── header ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Multicast Ring Analyzer — Linux Installer${RESET}"
echo    "  ─────────────────────────────────────────────"
echo -e "  Distro : $SYS_DISTRO_NAME"
echo -e "  Arch   : $(uname -m) → $SYS_ARCH"
echo -e "  Pkg Mgr: $SYS_PM"
echo    "  ─────────────────────────────────────────────"
$DRY_RUN && warn "Dry-run mode — no changes will be made"
echo ""

# ── compatibility check ────────────────────────────────────────────────────────
step "Checking system compatibility…"

# Block unsupported architectures
case "$SYS_ARCH" in
  x64|arm64)
    info "Architecture $SYS_ARCH is supported" ;;
  armv7l)
    warn "armv7l (32-bit ARM) detected — no pre-built binary available"
    warn "You can build from source: git clone https://github.com/$REPO && npm install && npm start"
    exit 1 ;;
  unknown:*)
    warn "Unrecognised architecture: $(uname -m)"
    warn "Only x86_64 and aarch64/arm64 are supported"
    exit 1 ;;
esac

# Warn on untested distros (AppImage should still work, just flag it)
case "$SYS_DISTRO" in
  ubuntu|debian|linuxmint|pop|elementary|kali|raspbian)
    info "Distro $SYS_DISTRO_NAME — fully supported" ;;
  fedora|rhel|centos|rocky|almalinux)
    info "Distro $SYS_DISTRO_NAME — supported (RPM-based)" ;;
  arch|manjaro|endeavouros)
    info "Distro $SYS_DISTRO_NAME — supported (Arch-based)" ;;
  opensuse*|sles)
    info "Distro $SYS_DISTRO_NAME — supported (openSUSE-based)" ;;
  *)
    warn "Distro '$SYS_DISTRO_NAME' is untested but should work via AppImage"
    warn "If you hit issues, report them at: https://github.com/$REPO/issues" ;;
esac

# AppImage requires FUSE — check kernel version as a proxy
KERNEL_VER="$(uname -r | cut -d. -f1)"
if [[ "$KERNEL_VER" -lt 4 ]]; then
  warn "Kernel $(uname -r) is very old — AppImage requires kernel 4.0+"
  warn "Consider upgrading your OS"
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
if $UNINSTALL; then
  step "Uninstalling $APP_NAME…"

  if [[ -f "$APPIMAGE_PATH" ]]; then
    info "Removing AppImage: $APPIMAGE_PATH"
    run rm -f "$APPIMAGE_PATH"
  else
    warn "AppImage not found at $APPIMAGE_PATH"
  fi

  if [[ -f "$DESKTOP_FILE" ]]; then
    info "Removing desktop entry"
    run rm -f "$DESKTOP_FILE"
    run_cmd "update-desktop-database '$DESKTOP_DIR' 2>/dev/null || true"
  fi

  # deb removal
  if command -v dpkg &>/dev/null && dpkg -l "$APP_ID" 2>/dev/null | grep -q '^ii'; then
    info "Removing deb package"
    run $SUDO apt-get remove -y "$APP_ID" 2>/dev/null || run $SUDO dpkg -r "$APP_ID"
  fi

  if $PURGE && [[ -d "$USER_DATA" ]]; then
    warn "Removing user data: $USER_DATA"
    run rm -rf "$USER_DATA"
  else
    info "User data kept at: $USER_DATA"
  fi

  echo ""
  info "Uninstall complete."
  exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECK
# ══════════════════════════════════════════════════════════════════════════════
if ! $SKIP_DEPS; then
  step "Checking dependencies…"
  echo ""

  # ── curl (needed for download) ──────────────────────────────────────────────
  if command -v curl &>/dev/null; then
    info "curl        $(curl --version | head -1 | awk '{print $2}')"
  else
    warn "curl not found — installing…"
    pm_install curl
  fi

  # ── ffmpeg / ffprobe (required — used to probe streams) ────────────────────
  if command -v ffprobe &>/dev/null; then
    info "ffprobe     $(ffprobe -version 2>&1 | head -1 | awk '{print $3}')"
  else
    warn "ffprobe not found — installing ffmpeg…"
    pm="$(detect_pm)"
    case "$pm" in
      apt)    run $SUDO apt-get update -qq && pm_install ffmpeg ;;
      dnf|yum) pm_install ffmpeg || {
                 warn "ffmpeg not in default repos — trying RPM Fusion"
                 run $SUDO dnf install -y "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm" 2>/dev/null || true
                 pm_install ffmpeg
               } ;;
      pacman) pm_install ffmpeg ;;
      *)      warn "Install ffmpeg manually: https://ffmpeg.org/download.html" ;;
    esac
    command -v ffprobe &>/dev/null && info "ffprobe     installed" || warn "ffprobe still not found — stream probing will not work"
  fi

  # ── VLC (required — used for stream playback) ───────────────────────────────
  if command -v vlc &>/dev/null; then
    info "vlc         $(vlc --version 2>/dev/null | head -1 | awk '{print $3}' || echo 'found')"
  else
    warn "VLC not found — installing…"
    pm_install vlc || warn "VLC install failed — install manually from https://www.videolan.org"
    command -v vlc &>/dev/null && info "vlc         installed" || warn "VLC still not found — stream playback will not work"
  fi

  # ── libfuse2 (required to run AppImage) ────────────────────────────────────
  # AppImages need libfuse.so.2 specifically. libfuse3 / fusermount3 — which
  # ships by default on Ubuntu 22.04+ — does NOT satisfy this, so we check for
  # the actual v2 library rather than the presence of any fusermount binary.
  if ldconfig -p 2>/dev/null | grep -q 'libfuse\.so\.2'; then
    info "libfuse2    found"
  else
    warn "libfuse2 not found — AppImages need it (libfuse3 alone won't work). Installing…"
    pm="$(detect_pm)"
    case "$pm" in
      apt)    run $SUDO apt-get update -qq; pm_install libfuse2 || pm_install libfuse2t64 || pm_install fuse ;;
      dnf|yum) pm_install fuse-libs || pm_install fuse ;;
      pacman) pm_install fuse2 ;;
      zypper) pm_install libfuse2 || pm_install fuse ;;
      *)      warn "Install libfuse2 manually for AppImage support" ;;
    esac
    if ldconfig -p 2>/dev/null | grep -q 'libfuse\.so\.2'; then
      info "libfuse2    installed"
    else
      warn "libfuse2 still missing — the app can still run with: <AppImage> --appimage-extract-and-run"
    fi
  fi

  echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
# FETCH LATEST RELEASE
# ══════════════════════════════════════════════════════════════════════════════
step "Fetching latest release from GitHub…"

RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || echo '{}')"
VERSION="$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

# Pick download URLs that match this machine's architecture
# x64:   AppImage (no suffix or x64), deb amd64
# arm64: AppImage arm64, deb arm64
if [[ "$SYS_ARCH" == "arm64" ]]; then
  APPIMAGE_URL="$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | grep '\.AppImage' | grep -i 'arm64\|aarch64' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')"
  DEB_URL="$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | grep '\.deb' | grep -i 'arm64\|aarch64' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')"
else
  # x64 — exclude arm64 files
  APPIMAGE_URL="$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | grep '\.AppImage' | grep -iv 'arm64\|aarch64\|armv7' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')"
  DEB_URL="$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | grep '\.deb' | grep -iv 'arm64\|aarch64\|armv7' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')"
fi

if [[ -z "$VERSION" ]]; then
  echo ""
  echo -e "${RED}  ✘ No release found on GitHub yet.${RESET}"
  echo ""
  echo "  This usually means one of:"
  echo "    • The build is still running  (takes ~5 minutes after a tag is pushed)"
  echo "    • The build failed            (check Actions tab on GitHub)"
  echo ""
  echo "  Check build status : https://github.com/$REPO/actions"
  echo "  Releases page      : https://github.com/$REPO/releases"
  echo ""
  echo "  ── Install from source instead ──────────────────────────────────"
  echo "  git clone git@github.com:$REPO.git"
  echo "  cd $(basename $REPO)"
  echo "  npm install && npm start"
  echo ""
  exit 1
fi

if [[ -z "$APPIMAGE_URL" && -z "$DEB_URL" ]]; then
  echo ""
  echo -e "${RED}  ✘ No $SYS_ARCH download found in release $VERSION.${RESET}"
  echo ""
  echo "  This means either:"
  echo "    • The build for $SYS_ARCH is still in progress (~5 min)"
  echo "    • The $SYS_ARCH build failed"
  echo ""
  echo "  Check build status : https://github.com/$REPO/actions"
  echo "  Releases page      : https://github.com/$REPO/releases"
  echo ""
  echo "  Try again in a few minutes, or install from source:"
  echo "    git clone git@github.com:$REPO.git"
  echo "    cd $(basename $REPO) && npm install && npm start"
  echo ""
  exit 1
fi

info "Latest version : $VERSION"
info "Architecture   : $SYS_ARCH"

# Check currently installed version
CURRENT_VERSION=""
if [[ -f "$APPIMAGE_PATH" ]]; then
  # Try to extract version from filename
  CURRENT_VERSION="$(basename "$APPIMAGE_PATH" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo '')"
fi

if [[ -n "$CURRENT_VERSION" && "$CURRENT_VERSION" == "${VERSION#v}" ]]; then
  info "Already on latest version ($VERSION)"
  echo ""
  read -rp "  Reinstall anyway? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "  Nothing to do."; exit 0; }
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# BACKUP EXISTING INSTALL
# ══════════════════════════════════════════════════════════════════════════════
BACKUP_DIR=""
if [[ -f "$APPIMAGE_PATH" || -d "$USER_DATA" ]]; then
  step "Backing up existing installation…"
  BACKUP_DIR="$BACKUP_BASE/$STAMP"

  if [[ -f "$APPIMAGE_PATH" ]]; then
    info "  App   → $BACKUP_DIR/app/"
    run mkdir -p "$BACKUP_DIR/app"
    run cp "$APPIMAGE_PATH" "$BACKUP_DIR/app/"
  fi

  if [[ -d "$USER_DATA" ]]; then
    info "  Data  → $BACKUP_DIR/userdata/"
    run cp -a "$USER_DATA" "$BACKUP_DIR/userdata/"
  fi

  echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
# DOWNLOAD + INSTALL
# ══════════════════════════════════════════════════════════════════════════════
step "Installing $APP_NAME $VERSION…"
echo ""

if [[ -n "$APPIMAGE_URL" ]]; then
  FILENAME="$(basename "$APPIMAGE_URL")"
  TMP_FILE="/tmp/$FILENAME"

  info "Downloading AppImage…"
  run curl -fL --progress-bar "$APPIMAGE_URL" -o "$TMP_FILE"

  run mkdir -p "$INSTALL_DIR"

  # Remove old AppImage
  if [[ -f "$APPIMAGE_PATH" ]]; then
    run rm -f "$APPIMAGE_PATH"
  fi

  run cp "$TMP_FILE" "$APPIMAGE_PATH"
  run chmod +x "$APPIMAGE_PATH"
  run rm -f "$TMP_FILE"
  info "AppImage installed → $APPIMAGE_PATH"

elif [[ -n "$DEB_URL" ]] && command -v dpkg &>/dev/null; then
  FILENAME="$(basename "$DEB_URL")"
  TMP_FILE="/tmp/$FILENAME"

  info "Downloading .deb package…"
  run curl -fL --progress-bar "$DEB_URL" -o "$TMP_FILE"

  # Remove old deb install
  dpkg -l "$APP_ID" 2>/dev/null | grep -q '^ii' && run $SUDO dpkg -r "$APP_ID" 2>/dev/null || true

  run $SUDO dpkg -i "$TMP_FILE"
  run $SUDO apt-get install -f -y 2>/dev/null || true
  run rm -f "$TMP_FILE"
  info ".deb installed"

fi

# ── desktop entry ──────────────────────────────────────────────────────────────
if [[ -f "$APPIMAGE_PATH" ]]; then
  run mkdir -p "$DESKTOP_DIR"
  if ! $DRY_RUN; then
    cat > "$DESKTOP_FILE" << DESKTOP
[Desktop Entry]
Name=$APP_NAME
Exec=$APPIMAGE_PATH %U
Icon=$APP_ID
Type=Application
Categories=Network;AudioVideo;
Comment=Discover and probe UDP multicast streams
StartupNotify=true
DESKTOP
  else
    dry "Write $DESKTOP_FILE"
  fi
  run_cmd "update-desktop-database '$DESKTOP_DIR' 2>/dev/null || true"
  info "Desktop entry created"
fi

# ── create app folder and README ───────────────────────────────────────────────
APP_FOLDER="$HOME/$APP_ID"
README_PATH="$APP_FOLDER/README.txt"

run mkdir -p "$APP_FOLDER"

if ! $DRY_RUN; then
  cat > "$README_PATH" << README
╔══════════════════════════════════════════════════════════════════╗
║           Multicast Ring Analyzer — Quick Start Guide           ║
╚══════════════════════════════════════════════════════════════════╝

Installed version : $VERSION
Install location  : $APPIMAGE_PATH
App folder        : $APP_FOLDER
User data         : $USER_DATA

──────────────────────────────────────────────────────────────────
 LAUNCHING THE APP
──────────────────────────────────────────────────────────────────

  From terminal:
    $APPIMAGE_PATH

  From your applications menu:
    Search for "Multicast Ring Analyzer"

──────────────────────────────────────────────────────────────────
 FIRST TIME SETUP
──────────────────────────────────────────────────────────────────

  1. Make sure your machine is on the same VLAN as the multicast
     traffic you want to monitor.

  2. The app needs ffprobe (ffmpeg) to probe streams and VLC for
     playback. Both are checked and installed by the install script.
     If either badge shows a warning in the top-right corner of the
     app, install them manually:

       sudo apt install ffmpeg vlc

  3. On first launch you may need to allow the AppImage to run:

       chmod +x "$APPIMAGE_PATH"

──────────────────────────────────────────────────────────────────
 USING THE APP
──────────────────────────────────────────────────────────────────

  RANGE SCAN TAB
  • Set IP Prefix to the first three octets of your multicast range
    e.g.  239 . 252 . 10 . x
  • Set Start / End for the last octet range  (e.g. 1 – 50)
  • Set Port to your stream port  (default 4444)
  • Choose your NIC if you have multiple network interfaces
  • Click Scan Network — live streams appear in real time
  • Each card shows codec, resolution, fps, and bitrate from ffprobe

  SAP LISTEN TAB
  • Click Start Listening to join 224.2.127.254:9875
  • Encoders that broadcast SAP (Haivision, Extron, vMix, OBS)
    appear automatically and are probed

  CHANNEL NAMES
  • Click any channel name field on a card to label it
  • Names are saved automatically and survive restarts
  • Use Import Names to paste a spreadsheet or list and let
    AI (Claude) match names to IPs automatically

  PLAYBACK
  • Click Launch VLC on any card to open that stream in VLC
  • Click Open All in VLC to load all live streams as a playlist
    (use arrow keys in VLC to step through channels)
  • Click Export M3U to save a playlist file

  AUTO-ROTATE
  • Click Auto-Rotate to cycle through all live streams in VLC
  • Set Dwell time (seconds per channel) in the rotate bar

──────────────────────────────────────────────────────────────────
 UPGRADING
──────────────────────────────────────────────────────────────────

  Re-run the install script at any time — it backs up your current
  install and user data before installing the new version:

    curl -fsSL https://raw.githubusercontent.com/lavabeard/Multicast-ring-analyzer/main/install.sh | bash

──────────────────────────────────────────────────────────────────
 UNINSTALLING
──────────────────────────────────────────────────────────────────

  Keep your channel names and settings:
    bash install.sh --uninstall

  Remove everything including user data:
    bash install.sh --purge

──────────────────────────────────────────────────────────────────
 NETWORK NOTES
──────────────────────────────────────────────────────────────────

  • Machine must be on the same VLAN as multicast traffic
  • Stream URLs use udp://@IP:PORT  (the @ is required)
  • Use the NIC selector if multicast is on a specific interface
  • SAP listener needs UDP port 9875 open on the selected interface
  • Increase probe timeout for slow or intermittent streams

──────────────────────────────────────────────────────────────────
 SUPPORT / SOURCE
──────────────────────────────────────────────────────────────────

  GitHub : https://github.com/lavabeard/Multicast-ring-analyzer
  Issues : https://github.com/lavabeard/Multicast-ring-analyzer/issues

README
  info "README written → $README_PATH"
else
  dry "Write $README_PATH"
fi

# ══════════════════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}  ✔ $APP_NAME $VERSION installed successfully${RESET}"
echo ""
echo -e "  ${BOLD}Launch:${RESET}    $APPIMAGE_PATH"
echo -e "  ${BOLD}App menu:${RESET}  Search 'Multicast Ring Analyzer'"
echo -e "  ${BOLD}README:${RESET}    $README_PATH"
[[ -n "$BACKUP_DIR" ]] && echo -e "  ${BOLD}Backup:${RESET}    $BACKUP_DIR"
echo ""
echo -e "  ${CYAN}Quick start guide saved to $README_PATH${RESET}"
echo -e "  ${CYAN}Run:  cat \"$README_PATH\"${RESET}"
echo ""
