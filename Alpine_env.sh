#!/bin/sh
# 一键最小化安装脚本（Alpine Linux 专用）
# 功能：安装 masscan + libpcap + xray + python3(aiohttp,requests) + setcap + curl/unzip
set -eu

XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/usr/local/bin}"
XRAY_BIN="${XRAY_INSTALL_DIR}/xray"
WORKDIR="$(mktemp -d)"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

cleanup_on_exit() {
  [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup_on_exit EXIT INT TERM

need_root() {
  [ "$(id -u)" = "0" ] || { echo "ERROR: 请以 root 权限运行"; exit 1; }
}

ensure_repos() {
  # masscan / py3-aiohttp 位于 community 仓库，确保已启用
  [ -f /etc/apk/repositories ] || return 0
  if ! grep -q '/community' /etc/apk/repositories 2>/dev/null; then
    V="$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || true)"
    [ -n "$V" ] || V="latest-stable"
    echo "https://dl-cdn.alpinelinux.org/alpine/v${V}/community" >> /etc/apk/repositories
    log "已启用 community 仓库 (v${V})"
  fi
}

install_min_packages() {
  apk update
  apk add --no-cache \
    ca-certificates curl unzip \
    python3 py3-requests py3-aiohttp \
    libcap libpcap \
    git gcc make musl-dev libpcap-dev binutils
  rm -rf /var/cache/apk/* 2>/dev/null || true
}

check_masscan() {
  if ! command -v masscan >/dev/null 2>&1; then
    log "masscan 未安装，开始源码编译..."
    build_masscan_from_source
  else
    MPATH="$(command -v masscan)"
    log "检测 masscan: $MPATH"
    if command -v ldd >/dev/null 2>&1 && ldd "$MPATH" 2>/dev/null | grep -q "not found"; then
      log "masscan 依赖缺失，重新编译..."
      build_masscan_from_source
    fi
  fi
}

build_masscan_from_source() {
  log "正在源码编译 masscan..."
  git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$WORKDIR/masscan"
  JOBS="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
  case "$JOBS" in ''|*[!0-9]*) JOBS=1 ;; esac
  [ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1
  make -C "$WORKDIR/masscan" -j"$JOBS" || make -C "$WORKDIR/masscan"
  install -m 0755 "$WORKDIR/masscan/bin/masscan" /usr/local/bin/masscan
  strip /usr/local/bin/masscan 2>/dev/null || true
  log "masscan 编译并安装完成"
}

apply_setcap() {
  if command -v setcap >/dev/null 2>&1; then
    MBIN="$(command -v masscan || true)"
    if [ -n "$MBIN" ]; then
      setcap cap_net_raw,cap_net_admin=+ep "$MBIN" || true
      log "已为 masscan 设置权限 (cap_net_raw, cap_net_admin)"
    fi
  else
    log "警告：系统缺少 setcap 工具"
  fi
}

install_xray() {
  if command -v xray >/dev/null 2>&1 || [ -x "$XRAY_BIN" ]; then
    log "xray 已存在，跳过安装"
    return
  fi

  mkdir -p "$XRAY_INSTALL_DIR"
  case "$(uname -m)" in
    x86_64|amd64) XRAY_ARCH=64 ;;
    i386|i686) XRAY_ARCH=32 ;;
    aarch64) XRAY_ARCH=arm64-v8a ;;
    armv7*|armv7l) XRAY_ARCH=arm32-v7a ;;
    armv6*|armv6l) XRAY_ARCH=arm32-v6 ;;
    riscv64) XRAY_ARCH=riscv64 ;;
    *) XRAY_ARCH=64 ;;
  esac

  ZIP="Xray-linux-${XRAY_ARCH}.zip"
  URL="https://github.com/XTLS/Xray-core/releases/latest/download/${ZIP}"

  log "正在下载 xray：$URL"
  curl -fsSL --retry 5 -o "$WORKDIR/xray.zip" "$URL"
  unzip -q "$WORKDIR/xray.zip" -d "$WORKDIR"
  install -m 0755 "$WORKDIR/xray" "$XRAY_BIN"
  log "xray 安装完成：$XRAY_BIN"
}

clean_up() {
  log "清理无用文件..."
  rm -rf "$WORKDIR" 2>/dev/null || true
  rm -rf /tmp/* /var/tmp/* /root/.cache 2>/dev/null || true
}

verify_all() {
  log "验证组件："
  printf "masscan: "; command -v masscan >/dev/null 2>&1 && masscan --version | head -n1 || echo "未安装"
  printf "xray:    "; command -v xray >/dev/null 2>&1 && xray -version | head -n1 || echo "未安装"
  printf "python3: "; python3 --version 2>/dev/null || echo "未安装"
  python3 - <<'PY'
try:
    import aiohttp, requests
    print("[OK] 成功导入 aiohttp 和 requests")
except Exception as e:
    print("[FAIL] Python 模块导入失败:", e)
PY
}

main() {
  need_root
  ensure_repos
  install_min_packages
  check_masscan
  apply_setcap
  install_xray
  clean_up
  verify_all
  log "✅ 所有组件已安装完毕，可直接运行：python3 loopcf.py"
}

main "$@"
