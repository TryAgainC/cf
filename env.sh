#!/bin/sh
# 一键最小化安装脚本（Debian / Ubuntu 专用）
# 功能：安装 masscan + libpcap + xray + python3(aiohttp,requests) + setcap + curl/unzip
set -eu

XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/usr/local/bin}"
XRAY_BIN="${XRAY_INSTALL_DIR}/xray"
WORKDIR="$(mktemp -d)"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

need_root() {
  [ "$(id -u)" = "0" ] || { echo "ERROR: 请以 root 权限运行"; exit 1; }
}

install_min_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl unzip python3 python3-requests python3-aiohttp \
    masscan libcap2-bin libpcap0.8 git gcc make libpcap-dev
  apt-get clean || true
  rm -rf /var/lib/apt/lists/* || true
}

check_masscan() {
  if ! command -v masscan >/dev/null 2>&1; then
    log "masscan 未安装，开始源码编译..."
    build_masscan_from_source
  else
    MPATH="$(command -v masscan)"
    log "检测 masscan: $MPATH"
    if ldd "$MPATH" 2>/dev/null | grep -q "not found"; then
      log "masscan 依赖缺失，重新编译..."
      build_masscan_from_source
    fi
  fi
}

build_masscan_from_source() {
  log "正在源码编译 masscan..."
  git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$WORKDIR/masscan"
  make -C "$WORKDIR/masscan" -j"$(nproc)" || make -C "$WORKDIR/masscan"
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
  rm -f requirements.txt 2>/dev/null || true
  find . -maxdepth 1 -name 'requirements.txt' -delete 2>/dev/null || true
  rm -rf /tmp/* /var/tmp/* ~/.cache/pip 2>/dev/null || true
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
  install_min_packages
  check_masscan
  apply_setcap
  install_xray
  clean_up
  verify_all
  log "✅ 所有组件已安装完毕，可直接运行：python3 loopcf.py"
}

main "$@"
