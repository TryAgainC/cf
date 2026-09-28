#!/bin/sh
# 一键最小化安装脚本（Alpine Linux 专用，512M 磁盘友好版）
# 功能：安装 masscan + libpcap + xray + python3(aiohttp,requests) + setcap + curl/unzip
set -eu

XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/usr/local/bin}"
XRAY_BIN="${XRAY_INSTALL_DIR}/xray"
WORKDIR="$(mktemp -d)"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

cleanup_on_exit() {
  [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR" 2>/dev/null || true
  # 万一中途退出，也把临时编译工具清掉
  apk del .build-deps 2>/dev/null || true
}
trap cleanup_on_exit EXIT INT TERM

need_root() {
  [ "$(id -u)" = "0" ] || { echo "ERROR: 请以 root 权限运行"; exit 1; }
}

ensure_repos() {
  [ -f /etc/apk/repositories ] || return 0
  if ! grep -q '/community' /etc/apk/repositories 2>/dev/null; then
    V="$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || true)"
    [ -n "$V" ] || V="latest-stable"
    echo "https://dl-cdn.alpinelinux.org/alpine/v${V}/community" >> /etc/apk/repositories
    log "已启用 community 仓库 (v${V})"
  fi
}

install_min_packages() {
  # 只装运行时必需：不含任何编译器
  apk add --no-cache \
    ca-certificates curl unzip \
    python3 py3-requests py3-aiohttp \
    libcap libcap-utils libpcap
  rm -rf /var/cache/apk/* 2>/dev/null || true
}

check_and_install_masscan() {
  if command -v masscan >/dev/null 2>&1; then
    MPATH="$(command -v masscan)"
    log "检测 masscan: $MPATH"
    if command -v ldd >/dev/null 2>&1 && ldd "$MPATH" 2>/dev/null | grep -q "not found"; then
      log "masscan 依赖缺失，重新安装..."
    else
      return 0
    fi
  fi

  # 优先走仓库，节省 100MB+ 编译工具链
  if apk add --no-cache masscan 2>/dev/null; then
    log "已从仓库安装 masscan（最小开销）"
    return 0
  fi

  log "仓库无 masscan，改用源码编译（临时安装编译工具）"
  build_masscan_from_source
}

build_masscan_from_source() {
  # 用虚拟包名，编完可以一键卸载
  apk add --no-cache --virtual .build-deps \
    git gcc make musl-dev binutils linux-headers libpcap-dev

  git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$WORKDIR/masscan"
  JOBS="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
  case "$JOBS" in ''|*[!0-9]*) JOBS=1 ;; esac
  [ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1

  export CFLAGS="-I/usr/include -O2 -Wall"

  make -C "$WORKDIR/masscan" -j"$JOBS" || make -C "$WORKDIR/masscan"
  install -m 0755 "$WORKDIR/masscan/bin/masscan" /usr/local/bin/masscan
  strip /usr/local/bin/masscan 2>/dev/null || true

  # 关键：立即删除编译工具，回收空间
  apk del .build-deps 2>/dev/null || true
  rm -rf "$WORKDIR/masscan" /var/cache/apk/* 2>/dev/null || true
  log "masscan 编译并安装完成（编译工具已清理）"
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
  # 只解压需要的文件，省空间
  unzip -q "$WORKDIR/xray.zip" xray geoip.dat geosite.dat -d "$WORKDIR" 2>/dev/null \
    || unzip -q "$WORKDIR/xray.zip" -d "$WORKDIR"
  install -m 0755 "$WORKDIR/xray" "$XRAY_BIN"
  rm -f "$WORKDIR/xray.zip"
  log "xray 安装完成：$XRAY_BIN"
}

clean_up() {
  log "清理无用文件..."
  rm -rf "$WORKDIR" 2>/dev/null || true
  rm -rf /tmp/* /var/tmp/* /root/.cache /var/cache/apk/* 2>/dev/null || true
}

verify_all() {
  log "验证组件："
  printf "masscan: "; command -v masscan >/dev/null 2>&1 && masscan --version 2>&1 | head -n1 || echo "未安装"
  printf "xray:    "; (command -v xray >/dev/null 2>&1 && xray -version 2>&1 | head -n1) || ([ -x "$XRAY_BIN" ] && "$XRAY_BIN" -version 2>&1 | head -n1) || echo "未安装"
  printf "python3: "; python3 --version 2>/dev/null || echo "未安装"
  python3 - <<'PY'
try:
    import aiohttp, requests
    print("[OK] 成功导入 aiohttp 和 requests")
except Exception as e:
    print("[FAIL] Python 模块导入失败:", e)
PY
  echo
  echo "磁盘占用："
  df -h / | awk 'NR==1 || /\/$/'
}

main() {
  need_root
  ensure_repos
  install_min_packages
  check_and_install_masscan
  apply_setcap
  install_xray
  clean_up
  verify_all
  log "✅ 所有组件已安装完毕，可直接运行：python3 loopcf.py"
}

main "$@"
