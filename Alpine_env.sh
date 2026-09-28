#!/bin/sh
# 一键最小化安装脚本（Alpine Linux 专用，512M 磁盘友好版 v2）
# 功能：masscan + libpcap + libcap + xray + python3(aiohttp/requests/aiofiles/tqdm) + setcap + curl/unzip
# 特性：libpcap 符号链接自愈，masscan 运行时不再报 libpcap not loaded
set -eu

XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/usr/local/bin}"
XRAY_BIN="${XRAY_INSTALL_DIR}/xray"
WORKDIR="$(mktemp -d)"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

cleanup_on_exit() {
  [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR" 2>/dev/null || true
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
  apk add --no-cache \
    ca-certificates curl unzip \
    python3 py3-requests py3-aiohttp py3-aiofiles py3-tqdm \
    libcap libcap-utils libpcap
  rm -rf /var/cache/apk/* 2>/dev/null || true
}

# ============ libpcap 符号链接自愈（关键） ============
ensure_libpcap_symlink() {
  # 清理坏软链：文件存在但指向的目标已经不存在
  for link in /usr/lib/libpcap.so /lib/libpcap.so; do
    if [ -L "$link" ] && [ ! -e "$link" ]; then
      rm -f "$link"
    fi
  done

  # 如果 libpcap.so 已经能解析，直接结束
  if [ -e /usr/lib/libpcap.so ] || [ -e /lib/libpcap.so ]; then
    log "libpcap.so 符号链接已存在，跳过"
    return 0
  fi

  # 找真实的 libpcap 库文件（兼容 .so.0 / .so.1 / .so.2 等）
  REAL_LIB=""
  for candidate in \
    /usr/lib/libpcap.so.1 /usr/lib/libpcap.so.0 /usr/lib/libpcap.so.2 \
    /lib/libpcap.so.1  /lib/libpcap.so.0  /lib/libpcap.so.2 ; do
    if [ -e "$candidate" ]; then
      REAL_LIB="$candidate"
      break
    fi
  done

  # 兜底：全盘搜一次
  if [ -z "$REAL_LIB" ]; then
    REAL_LIB="$(find /usr/lib /lib -maxdepth 2 -name 'libpcap.so.*' 2>/dev/null | head -n1)"
  fi

  # 还是找不到就安装 libpcap
  if [ -z "$REAL_LIB" ]; then
    log "未检测到 libpcap，尝试安装..."
    apk add --no-cache libpcap >/dev/null 2>&1 || true
    REAL_LIB="$(find /usr/lib /lib -maxdepth 2 -name 'libpcap.so.*' 2>/dev/null | head -n1)"
  fi

  if [ -z "$REAL_LIB" ]; then
    log "❌ 无法定位 libpcap.so.X，masscan 可能无法运行"
    return 1
  fi

  # 建软链：/usr/lib 和 /lib 两处都建，兼容不同发行版布局
  ln -sf "$REAL_LIB" /usr/lib/libpcap.so
  [ -d /lib ] && ln -sf "$REAL_LIB" /lib/libpcap.so 2>/dev/null || true

  log "✅ 已创建 libpcap.so 软链 -> $REAL_LIB"
}

# ======================================================

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

  if apk add --no-cache masscan 2>/dev/null; then
    log "已从仓库安装 masscan（最小开销）"
    return 0
  fi

  log "仓库无 masscan，改用源码编译（临时安装编译工具）"
  build_masscan_from_source
}

build_masscan_from_source() {
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
    import aiohttp, aiofiles, requests, tqdm
    print("[OK] aiohttp/aiofiles/requests/tqdm 均可导入")
except Exception as e:
    print("[FAIL] Python 模块导入失败:", e)
PY

  # 实测 masscan 能否正常加载 libpcap（关键验证）
  if command -v masscan >/dev/null 2>&1; then
    if masscan --version 2>&1 | grep -q "libpcap"; then
      log "✅ masscan 已能加载 libpcap"
    else
      # 跑一次真实调用触发 dlopen
      if masscan 127.0.0.1 -p1 --rate 1 --wait 0 2>&1 | grep -qi "libpcap not loaded\|failed to load libpcap"; then
        log "❌ masscan 仍无法加载 libpcap，请检查 /usr/lib/libpcap.so"
        ls -la /usr/lib/libpcap* /lib/libpcap* 2>/dev/null || true
      else
        log "✅ masscan libpcap 加载正常"
      fi
    fi
  fi

  echo
  echo "磁盘占用："
  df -h / | awk 'NR==1 || /\/$/'
}

main() {
  need_root
  ensure_repos
  install_min_packages
  ensure_libpcap_symlink     # ← 关键：先保证 libpcap.so 存在
  check_and_install_masscan
  ensure_libpcap_symlink     # ← 若上面源码编译过程中 -dev 被删，再补一次
  apply_setcap
  install_xray
  clean_up
  verify_all
  log "✅ 所有组件已安装完毕，可直接运行：python3 loopcf.py"
}

main "$@"
