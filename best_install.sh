#!/bin/sh
# install_cf_env_final.sh
# 一键最小化安装：masscan + libpcap + xray + python3(aiohttp,requests) + curl/unzip + setcap
# 适配：Debian / Ubuntu / Alpine
# 要求：以 root 运行
set -eu

XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/usr/local/bin}"
XRAY_BIN="${XRAY_INSTALL_DIR}/xray"
WORKDIR="$(mktemp -d)"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

need_root() {
  [ "$(id -u)" = "0" ] || { echo "ERROR: please run as root"; exit 1; }
}

detect_os() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
      alpine) OS_FAMILY=alpine ;;
      debian|ubuntu) OS_FAMILY=debian ;;
      *) case "${ID_LIKE:-}" in
           *debian*) OS_FAMILY=debian ;;
           *alpine*) OS_FAMILY=alpine ;;
           *) echo "ERROR: unsupported OS: ${ID:-unknown}"; exit 1 ;;
         esac ;;
    esac
  else
    echo "ERROR: can't detect OS (/etc/os-release missing)"; exit 1
  fi
  log "detected OS family: $OS_FAMILY"
}

install_min_packages() {
  case "$OS_FAMILY" in
    debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y --no-install-recommends \
        ca-certificates curl unzip python3 python3-requests python3-aiohttp \
        masscan libcap2-bin libpcap0.8 || true
      apt-get clean || true
      rm -rf /var/lib/apt/lists/* || true
      ;;
    alpine)
      apk update
      apk add --no-cache \
        ca-certificates curl unzip python3 py3-requests py3-aiohttp \
        masscan libpcap || true
      # setcap provider
      apk add --no-cache libcap-setcap || apk add --no-cache libcap-utils || true
      ;;
  esac
}

check_libpcap() {
  log "checking libpcap presence..."
  case "$OS_FAMILY" in
    debian)
      if ! dpkg -l 2>/dev/null | grep -qi libpcap; then
        log "libpcap not found, installing libpcap0.8..."
        apt-get update -y
        apt-get install -y --no-install-recommends libpcap0.8 || true
      fi
      ;;
    alpine)
      if ! apk info | grep -qi '^libpcap' 2>/dev/null; then
        log "libpcap not found, installing libpcap..."
        apk update
        apk add --no-cache libpcap || true
      fi
      ;;
  esac

  # quick existence checks
  if [ -f /usr/lib/libpcap.so ] || [ -f /usr/lib/libpcap.so.1 ] || [ -f /usr/lib/libpcap.so.* ] || [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 ]; then
    log "libpcap files exist (runtime library present)."
  fi
}

masscan_dynamic_check() {
  if ! command -v masscan >/dev/null 2>&1; then
    log "masscan not installed by package manager."
    MASSCAN_PRESENT=0
    return
  fi
  MASSCAN_PRESENT=1
  MPATH="$(command -v masscan)"
  log "masscan found at: $MPATH"

  # Use ldd if available, else 'file'
  if command -v ldd >/dev/null 2>&1; then
    LDDOUT="$(ldd "$MPATH" 2>&1 || true)"
    echo "$LDDOUT" | grep -qi "not a dynamic executable" && {
      # static binary
      log "masscan is static (not dynamic)."
      MASSCAN_STATIC=1
      return
    }
    echo "$LDDOUT" | grep -qi "libpcap.so" || {
      # If ldd doesn't mention libpcap, still check for 'not found'
      echo "$LDDOUT" | grep -qi "not found" && MASSCAN_MISSING_LIBS=1 || MASSCAN_MISSING_LIBS=0
    }
    if echo "$LDDOUT" | grep -qi "libpcap.so"; then
      if echo "$LDDOUT" | grep -qi "libpcap.so.*=> not found"; then
        MASSCAN_MISSING_LIBS=1
      else
        MASSCAN_MISSING_LIBS=0
      fi
    fi
    # detect glibc vs musl linkage (for Alpine musl incompat)
    if echo "$LDDOUT" | grep -qi "ld-linux"; then MASSCAN_GLIBC=1; else MASSCAN_GLIBC=0; fi
  else
    # fallback: use file
    FFILE="$(file "$MPATH" 2>/dev/null || true)"
    echo "$FFILE" | grep -qi "not a dynamic executable" && MASSCAN_STATIC=1 || MASSCAN_STATIC=0
    echo "$FFILE" | grep -qi "glibc" && MASSCAN_GLIBC=1 || MASSCAN_GLIBC=0
    MASSCAN_MISSING_LIBS=0
  fi

  MASSCAN_STATIC="${MASSCAN_STATIC:-0}"
  MASSCAN_MISSING_LIBS="${MASSCAN_MISSING_LIBS:-0}"
  MASSCAN_GLIBC="${MASSCAN_GLIBC:-0}"

  log "masscan_static=$MASSCAN_STATIC missing_libs=$MASSCAN_MISSING_LIBS masscan_glibc=$MASSCAN_GLIBC"
}

build_masscan_from_source() {
  log "building masscan from source (will install build deps temporarily)..."
  case "$OS_FAMILY" in
    debian)
      apt-get update -y
      apt-get install -y --no-install-recommends git gcc make libpcap-dev || true
      git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$WORKDIR/masscan"
      make -C "$WORKDIR/masscan" -j"$(nproc)" || make -C "$WORKDIR/masscan"
      install -m 0755 "$WORKDIR/masscan/bin/masscan" /usr/local/bin/masscan
      # remove build deps
      apt-get purge -y git gcc make libpcap-dev || true
      apt-get autoremove -y || true
      apt-get clean || true
      rm -rf /var/lib/apt/lists/* || true
      ;;
    alpine)
      apk add --no-cache --virtual .build-deps build-base git libpcap-dev || true
      git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$WORKDIR/masscan"
      make -C "$WORKDIR/masscan" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" || make -C "$WORKDIR/masscan"
      install -m 0755 "$WORKDIR/masscan/bin/masscan" /usr/local/bin/masscan
      apk del .build-deps || true
      ;;
  esac
  strip /usr/local/bin/masscan 2>/dev/null || true
  log "masscan built and installed to /usr/local/bin/masscan"
}

ensure_masscan_usable() {
  # If masscan not present or has missing libs or is glibc binary on Alpine (musl), build from source
  if [ "${MASSCAN_PRESENT:-0}" -eq 0 ] || [ "${MASSCAN_MISSING_LIBS:-0}" -eq 1 ] || ( [ "$OS_FAMILY" = "alpine" ] && [ "${MASSCAN_GLIBC:-0}" -eq 1 ] ); then
    log "masscan needs rebuild or install from source"
    build_masscan_from_source
  else
    log "masscan binary seems OK"
  fi
  # final check
  if ! command -v masscan >/dev/null 2>&1; then
    log "ERROR: masscan still missing after attempts"
    exit 1
  fi
}

ensure_setcap() {
  if command -v setcap >/dev/null 2>&1; then
    log "setcap present"
    return
  fi
  log "installing setcap tool..."
  case "$OS_FAMILY" in
    debian) apt-get update -y && apt-get install -y --no-install-recommends libcap2-bin || true ;;
    alpine) apk add --no-cache libcap-setcap || apk add --no-cache libcap-utils || true ;;
  esac
}

apply_masscan_caps() {
  MBIN="$(command -v masscan || true)"
  if [ -n "$MBIN" ] && command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=+ep "$MBIN" || true
    log "setcap applied to masscan (if supported)"
  fi
}

install_xray_singlefile() {
  if command -v xray >/dev/null 2>&1 || [ -x "$XRAY_BIN" ]; then
    log "xray already present, skip"
    return
  fi
  mkdir -p "$XRAY_INSTALL_DIR"
  # detect arch mapping
  case "$(uname -m)" in
    x86_64|amd64) XRAY_ARCH=64 ;;
    i386|i686) XRAY_ARCH=32 ;;
    aarch64) XRAY_ARCH=arm64-v8a ;;
    armv7*|armv7l) XRAY_ARCH=arm32-v7a ;;
    armv6*|armv6l) XRAY_ARCH=arm32-v6 ;;
    riscv64) XRAY_ARCH=riscv64 ;;
    ppc64le) XRAY_ARCH=ppc64le ;;
    ppc64) XRAY_ARCH=ppc64 ;;
    s390x) XRAY_ARCH=s390x ;;
    mips*) XRAY_ARCH=mips32 ;;
    *) XRAY_ARCH=64 ;;
  esac
  ZIP="Xray-linux-${XRAY_ARCH}.zip"
  URL="https://github.com/XTLS/Xray-core/releases/latest/download/${ZIP}"
  log "downloading xray from $URL"
  curl -fsSL --retry 5 -o "$WORKDIR/xray.zip" "$URL" || { log "xray download failed"; return 1; }
  unzip -q "$WORKDIR/xray.zip" -d "$WORKDIR" || { log "unzip failed"; return 1; }
  if [ -f "$WORKDIR/xray" ]; then
    install -m 0755 "$WORKDIR/xray" "$XRAY_BIN"
    log "xray installed to $XRAY_BIN"
  else
    log "xray binary not found inside zip"
  fi
}

clean_up() {
  log "cleaning temporary files and stale requirements.txt..."
  rm -rf "$WORKDIR" 2>/dev/null || true
  rm -f requirements.txt 2>/dev/null || true
  find . -maxdepth 1 -type f -name 'requirements.txt' -delete 2>/dev/null || true
  rm -rf /tmp/* /var/tmp/* ~/.cache/pip 2>/dev/null || true
}

verify_install() {
  log "verifying components..."
  printf "masscan: "; if command -v masscan >/dev/null 2>&1; then masscan --version 2>/dev/null | head -n1 || echo "masscan present"; else echo "missing"; fi
  printf "libpcap: "; (ls /usr/lib/libpcap.so* 2>/dev/null || ls /usr/lib/x86_64-linux-gnu/libpcap.so* 2>/dev/null || true)
  printf "xray:    "; if command -v xray >/dev/null 2>&1; then xray -version 2>/dev/null | head -n1 || echo "xray present"; else [ -x "$XRAY_BIN" ] && "$XRAY_BIN" -version 2>/dev/null | head -n1 || echo "missing"; fi
  printf "python3: "; python3 --version 2>/dev/null || echo "missing"
  python3 - <<'PY' || true
try:
    import aiohttp, requests
    print("[OK] aiohttp and requests import succeeded")
except Exception as e:
    print("[FAIL] python modules import error:", e)
PY
}

main() {
  need_root
  detect_os
  install_min_packages
  check_libpcap
  masscan_dynamic_check
  ensure_masscan_usable
  ensure_setcap
  apply_masscan_caps
  install_xray_singlefile || log "xray install skipped/failed (non-fatal)"
  clean_up
  verify_install
  log "ALL DONE. You can run: python3 loopcf.py"
}

# run
main "$@"
