#!/usr/bin/env bash
# upgrade.sh — Multicast Ring Analyzer upgrade script (Linux + macOS)
#
# Usage:
#   ./scripts/upgrade.sh                  # pull latest git, build, install
#   ./scripts/upgrade.sh --from-dist      # skip git/build, install from existing dist/
#   ./scripts/upgrade.sh --dry-run        # show what would happen, change nothing
#
# What it does:
#   1. Pulls latest source from git (unless --from-dist)
#   2. npm install + builds for the current platform
#   3. Backs up the existing installation to a timestamped archive
#   4. Preserves Electron user-data (localStorage, window state, etc.)
#   5. Installs the new build

set -euo pipefail

APP_NAME="Multicast Ring Tester"
APP_ID="multicast-ring-tester"
REPO_URL="https://github.com/lavabeard/av-net-scout.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
STAMP="$(date +%Y%m%d_%H%M%S)"
DRY_RUN=false
FROM_DIST=false

# ── arg parse ──────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=true ;;
    --from-dist) FROM_DIST=true ;;
    --help|-h)
      echo "Usage: $0 [--from-dist] [--dry-run]"
      echo "  --from-dist   skip git pull and build; install from existing dist/"
      echo "  --dry-run     show what would happen without making changes"
      exit 0
      ;;
  esac
done

# ── helpers ────────────────────────────────────────────────────────────────────
info()  { echo -e "\033[0;32m[upgrade]\033[0m $*"; }
warn()  { echo -e "\033[0;33m[upgrade]\033[0m $*"; }
error() { echo -e "\033[0;31m[upgrade]\033[0m $*" >&2; exit 1; }
run()   { if $DRY_RUN; then echo -e "\033[0;36m[dry-run]\033[0m $*"; else "$@"; fi; }

PLATFORM="$(uname -s)"
case "$PLATFORM" in
  Darwin) OS=mac ;;
  Linux)  OS=linux ;;
  *)      error "Unsupported platform: $PLATFORM" ;;
esac

# ── locate user data ───────────────────────────────────────────────────────────
if [[ "$OS" == "mac" ]]; then
  USER_DATA="$HOME/Library/Application Support/$APP_NAME"
else
  USER_DATA="${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME"
fi

# ── locate existing installation ──────────────────────────────────────────────
INSTALL_PATH=""
if [[ "$OS" == "mac" ]]; then
  INSTALL_PATH="/Applications/$APP_NAME.app"
elif [[ "$OS" == "linux" ]]; then
  # Check for AppImage in common locations
  for candidate in \
    "$HOME/Applications/$APP_NAME"*.AppImage \
    "/opt/$APP_ID/$APP_NAME"*.AppImage \
    "/usr/local/bin/$APP_ID" \
    "/opt/$APP_ID"; do
    if [[ -e "$candidate" ]]; then INSTALL_PATH="$candidate"; break; fi
  done
  # Check if installed via deb (dpkg)
  if [[ -z "$INSTALL_PATH" ]] && command -v dpkg &>/dev/null; then
    if dpkg -l "$APP_ID" 2>/dev/null | grep -q '^ii'; then
      INSTALL_PATH="deb:$APP_ID"
    fi
  fi
fi

info "Platform  : $OS"
info "User data : $USER_DATA"
info "Install   : ${INSTALL_PATH:-<not found — fresh install>}"
[[ "$DRY_RUN" == "true" ]] && warn "Dry-run mode — no changes will be made"
echo ""

# ── step 1: pull latest source ─────────────────────────────────────────────────
if ! $FROM_DIST; then
  info "Pulling latest source…"
  if [[ -d "$REPO_DIR/.git" ]]; then
    run git -C "$REPO_DIR" pull --ff-only origin main
  else
    warn "Not inside a git repo — cloning fresh to /tmp/mcast-build-$STAMP"
    REPO_DIR="/tmp/mcast-build-$STAMP"
    run git clone "$REPO_URL" "$REPO_DIR"
  fi
fi

# ── step 2: build ──────────────────────────────────────────────────────────────
if ! $FROM_DIST; then
  info "Installing Node dependencies…"
  run npm --prefix "$REPO_DIR" install
  info "Building for $OS…"
  if [[ "$OS" == "mac" ]]; then
    run npm --prefix "$REPO_DIR" run dist:mac
  else
    run npm --prefix "$REPO_DIR" run dist:linux
  fi
fi

# Locate the build artifact
if [[ "$OS" == "mac" ]]; then
  NEW_DMG="$(ls "$REPO_DIR"/dist/*.dmg 2>/dev/null | head -1)"
  [[ -z "$NEW_DMG" ]] && error "No .dmg found in dist/ — build may have failed"
  info "New build : $NEW_DMG"
elif [[ "$OS" == "linux" ]]; then
  NEW_APPIMAGE="$(ls "$REPO_DIR"/dist/*.AppImage 2>/dev/null | head -1)"
  NEW_DEB="$(ls "$REPO_DIR"/dist/*.deb 2>/dev/null | head -1)"
  [[ -z "$NEW_APPIMAGE" && -z "$NEW_DEB" ]] && error "No AppImage or .deb found in dist/"
fi

# ── step 3: back up existing installation ─────────────────────────────────────
BACKUP_DIR="$HOME/.local/share/$APP_ID-backups/$STAMP"
if [[ -n "$INSTALL_PATH" && "$INSTALL_PATH" != deb:* && -e "$INSTALL_PATH" ]]; then
  info "Backing up existing installation → $BACKUP_DIR/app/"
  run mkdir -p "$BACKUP_DIR/app"
  run cp -a "$INSTALL_PATH" "$BACKUP_DIR/app/"
fi

# Back up user data (localStorage, settings)
if [[ -d "$USER_DATA" ]]; then
  info "Backing up user data → $BACKUP_DIR/userdata/"
  run cp -a "$USER_DATA" "$BACKUP_DIR/userdata/"
fi

# ── step 4: install new build ──────────────────────────────────────────────────
if [[ "$OS" == "mac" ]]; then
  info "Mounting DMG…"
  if ! $DRY_RUN; then
    MOUNT_POINT="$(hdiutil attach "$NEW_DMG" -nobrowse -noautoopen | grep /Volumes | awk '{print $NF}')"
    trap "hdiutil detach '$MOUNT_POINT' -quiet 2>/dev/null || true" EXIT
    if [[ -e "/Applications/$APP_NAME.app" ]]; then
      info "Removing old .app…"
      rm -rf "/Applications/$APP_NAME.app"
    fi
    info "Copying new .app to /Applications…"
    cp -a "$MOUNT_POINT/$APP_NAME.app" /Applications/
    hdiutil detach "$MOUNT_POINT" -quiet
    trap - EXIT
  else
    echo -e "\033[0;36m[dry-run]\033[0m hdiutil attach → copy .app → hdiutil detach"
  fi

elif [[ "$OS" == "linux" ]]; then
  # Prefer deb if available and dpkg exists
  if [[ -n "$NEW_DEB" ]] && command -v dpkg &>/dev/null; then
    info "Installing .deb package…"
    if [[ "$INSTALL_PATH" == deb:* ]]; then
      run sudo dpkg -r "$APP_ID" 2>/dev/null || true
    fi
    run sudo dpkg -i "$NEW_DEB"
    run sudo apt-get install -f -y 2>/dev/null || true

  elif [[ -n "$NEW_APPIMAGE" ]]; then
    DEST_DIR="$HOME/Applications"
    DEST="$DEST_DIR/$APP_NAME.AppImage"
    run mkdir -p "$DEST_DIR"
    # Remove old AppImage if found
    if [[ -n "$INSTALL_PATH" && -f "$INSTALL_PATH" ]]; then
      info "Removing old AppImage: $INSTALL_PATH"
      run rm -f "$INSTALL_PATH"
    fi
    info "Installing AppImage → $DEST"
    run cp "$NEW_APPIMAGE" "$DEST"
    run chmod +x "$DEST"

    # Create desktop entry
    DESKTOP_FILE="$HOME/.local/share/applications/$APP_ID.desktop"
    run mkdir -p "$(dirname "$DESKTOP_FILE")"
    if ! $DRY_RUN; then
      cat > "$DESKTOP_FILE" << DESKTOP
[Desktop Entry]
Name=$APP_NAME
Exec=$DEST %U
Icon=$APP_ID
Type=Application
Categories=Network;AudioVideo;
Comment=Discover and probe UDP multicast streams
DESKTOP
      update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
    else
      echo -e "\033[0;36m[dry-run]\033[0m write $DESKTOP_FILE"
    fi
  fi
fi

# ── done ───────────────────────────────────────────────────────────────────────
echo ""
info "Upgrade complete."
[[ -d "$BACKUP_DIR" ]] && info "Backup saved to: $BACKUP_DIR"
if [[ "$OS" == "linux" && -n "$NEW_APPIMAGE" ]]; then
  info "Launch with: $HOME/Applications/$APP_NAME.AppImage"
elif [[ "$OS" == "mac" ]]; then
  info "Launch with: open -a '$APP_NAME'"
fi
