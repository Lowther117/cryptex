#!/bin/bash
# ---------------------------------------------------------------------------
#  Cryptex - macOS build. Double-click this file.
#  Installs Homebrew and Python if they are missing, installs every
#  dependency, and produces dist/Cryptex.app.
# ---------------------------------------------------------------------------
cd "$(dirname "$0")" || exit 1
HERE="$(pwd)"
LOG="$HERE/build-mac-log.txt"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

# A double-clicked .command starts with a bare PATH that has no Homebrew in it.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

echo "==============================================="
echo "  Building Cryptex for macOS"
echo "  Full log: build-mac-log.txt"
echo "==============================================="
echo

die() {
  echo
  echo "==============================================="
  echo "  BUILD FAILED: $*"
  echo "==============================================="
  echo
  echo "Press return to close."
  read -r
  exit 1
}

ensure_brew() {
  if command -v brew >/dev/null 2>&1; then return 0; fi
  echo "Homebrew is not installed. Installing it now - it will ask for your password once."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/tty \
    || die "Homebrew would not install."
  export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
  command -v brew >/dev/null 2>&1 || die "Homebrew installed but brew is still not on the PATH."
}

brew_install() {
  ensure_brew
  echo "  brew install $*"
  brew install "$@" < /dev/null || die "brew install $* failed."
}

# macOS has no built-in way to capture "what a device is playing", so the live
# loopback option needs a virtual audio driver. BlackHole is the free standard.
# This is OPTIONAL and never fatal: file decoding and real inputs work without
# it, so the build always carries on. Set CRYPTEX_SKIP_BLACKHOLE=1 to skip.
ensure_blackhole() {
  if ls /Library/Audio/Plug-Ins/HAL 2>/dev/null | grep -qi blackhole; then
    echo "      BlackHole is already installed - nothing to do."
    return 0
  fi
  if [ -n "$CRYPTEX_SKIP_BLACKHOLE" ]; then
    echo "      CRYPTEX_SKIP_BLACKHOLE is set - skipping the loopback driver."
    return 0
  fi
  if ! command -v brew >/dev/null 2>&1; then
    echo "      Homebrew is not present, so BlackHole is being skipped (it is only"
    echo "      needed for live loopback). Install it any time with:"
    echo "         brew install --cask blackhole-2ch"
    return 0
  fi
  echo "      Installing BlackHole - a virtual audio device used for loopback."
  echo "      macOS will ask for your password: it installs a system audio driver."
  if brew install --cask blackhole-2ch < /dev/tty; then
    echo "      BlackHole installed."
    echo "      To capture what you are playing: open 'Audio MIDI Setup', create a"
    echo "      Multi-Output Device that ticks BOTH your speakers/headphones AND"
    echo "      'BlackHole 2ch', and set it as the system output. You then still"
    echo "      hear the sound, and Cryptex can loop back the BlackHole side."
  else
    echo "      NOTE: BlackHole did not install (skipped or cancelled). The app still"
    echo "      builds - live loopback just will not be available until it is present."
    echo "      File decoding and real inputs work regardless."
  fi
}

# Apple's /usr/bin/python3 links against system Tk 8.5, which PyInstaller
# cannot bundle: the app builds and then never opens a window. Only accept an
# interpreter whose tkinter reports 8.6 or newer. Resolve candidates with
# readlink rather than running python3, because on a clean Mac running
# python3 pops up the Xcode command line tools installer.
pick_python() {
  local c real
  if [ -n "$CRYPTEX_BUILD_PYTHON" ] && [ -x "$CRYPTEX_BUILD_PYTHON" ]; then
    if "$CRYPTEX_BUILD_PYTHON" -c 'import tkinter,sys;sys.exit(0 if tkinter.TkVersion>=8.6 else 1)' 2>/dev/null; then
      echo "$CRYPTEX_BUILD_PYTHON"; return 0
    fi
  fi
  for c in /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
           /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.10 /opt/homebrew/bin/python3.9 \
           /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 \
           /usr/local/bin/python3.11 /usr/local/bin/python3.10 /usr/local/bin/python3.9 \
           /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.10/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.9/bin/python3; do
    [ -e "$c" ] || continue
    real="$(readlink -f "$c" 2>/dev/null || python3 -c "import os,sys;print(os.path.realpath(sys.argv[1]))" "$c" 2>/dev/null || echo "$c")"
    [ -x "$real" ] || continue
    case "$real" in /usr/bin/python3) continue ;; esac
    if "$real" -c 'import tkinter,sys;sys.exit(0 if tkinter.TkVersion>=8.6 else 1)' 2>/dev/null; then
      echo "$real"; return 0
    fi
  done
  return 1
}

echo "[1/8] Finding a Python with a usable Tk..."
PY="$(pick_python)" || {
  echo "      None found. Installing Python and Tk through Homebrew..."
  brew_install python python-tk
  PY="$(pick_python)" || die "Even after installing python and python-tk, no interpreter reports Tk 8.6+."
}
echo "      using $PY"
"$PY" -c 'import sys,tkinter;print("      python",sys.version.split()[0],"tk",tkinter.TkVersion)'

echo "[2/8] Creating a clean build environment..."
VENV="$HERE/.venv-build-mac"
rm -rf "$VENV"
"$PY" -m venv "$VENV" || die "Could not create the build environment."
VPY="$VENV/bin/python"

echo "[3/8] Installing dependencies (wheels only, no compiling)..."
"$VPY" -m pip install --upgrade pip wheel >/dev/null || die "pip would not upgrade."
"$VPY" -m pip install --only-binary :all: -r "$HERE/requirements.txt" || die "A dependency has no wheel for this Mac."
"$VPY" -m pip install --only-binary :all: pyinstaller || die "PyInstaller would not install."

echo "[4/8] Setting up audio loopback (BlackHole, optional)..."
ensure_blackhole

echo "[5/8] Checking the code before packaging..."
"$VPY" -c "import sys; sys.path.insert(0,'.'); from cryptexlib import registry; print('      tools:', len(registry.REGISTRY))" \
  || die "The application does not import cleanly."

echo "[6/8] Packaging (this takes a couple of minutes)..."
rm -rf "$HERE/build" "$HERE/dist"
"$VPY" -m PyInstaller --noconfirm --clean --windowed \
  --name "Cryptex" \
  --osx-bundle-identifier "uk.lowther.cryptex" \
  --collect-all cryptography \
  --collect-all PIL \
  --collect-all imageio_ffmpeg \
  --hidden-import sounddevice \
  --hidden-import soundcard \
  --collect-submodules soundcard \
  --collect-submodules cryptexlib \
  --hidden-import _cffi_backend \
  --exclude-module pytest \
  --exclude-module numpy.tests \
  --exclude-module numpy.f2py \
  --hidden-import argon2 \
  --hidden-import argon2.low_level \
  --hidden-import tkinter \
  --hidden-import tkinter.ttk \
  --hidden-import tkinter.filedialog \
  --hidden-import tkinter.messagebox \
  "$HERE/cryptex_app.py" || die "PyInstaller failed - see the log above."
[ -d "$HERE/dist/Cryptex.app" ] || die "dist/Cryptex.app was not produced."

echo "[7/8] Clearing quarantine and signing locally..."
# the bundled ffmpeg has to stay executable, and the microphone entitlement
# has to be declared or macOS silently hands the app an empty input stream
PLIST="$HERE/dist/Cryptex.app/Contents/Info.plist"
if [ -f "$PLIST" ]; then
  /usr/libexec/PlistBuddy -c "Delete :NSMicrophoneUsageDescription" "$PLIST" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :NSMicrophoneUsageDescription string 'Cryptex listens to the microphone or line-in to decode slow-scan pictures, touch-tones and Morse.'" "$PLIST" || true
fi
find "$HERE/dist/Cryptex.app" -name "ffmpeg*" -type f -exec chmod +x {} \; 2>/dev/null || true
# Without these two an app built on Apple silicon is killed the moment it opens.
xattr -cr "$HERE/dist/Cryptex.app" || true
codesign --force --deep --sign - "$HERE/dist/Cryptex.app" || die "Ad-hoc signing failed."

echo "[8/8] Running the self-test on the built app..."
echo "      This exercises every tool - a couple of minutes, and it will look"
echo "      idle while it works."
rm -f "$HERE/dist/cryptex-selftest.txt"
"$HERE/dist/Cryptex.app/Contents/MacOS/Cryptex" selftest || true
sleep 2
if [ -f "$HERE/dist/cryptex-selftest.txt" ]; then
  echo
  cat "$HERE/dist/cryptex-selftest.txt"
  if grep -q "PROBLEMS FOUND" "$HERE/dist/cryptex-selftest.txt"; then
    echo
    echo "==============================================="
    echo "  BUILT, BUT THE SELF-TEST REPORTED PROBLEMS."
    echo "  See dist/cryptex-selftest.txt above."
    echo "==============================================="
    echo
    echo "Press return to close."
    read -r
    exit 2
  fi
else
  echo "      (no self-test report was written - check it by hand)"
fi

echo
echo "==============================================="
echo "  DONE.  dist/Cryptex.app is ready."
echo "  Drag it to your Applications folder."
echo "==============================================="
echo
echo "Press return to close."
read -r
