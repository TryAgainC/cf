#!/bin/sh
# =========================================================
# 最终一键最小安装脚本 (Final v2)
# 支持 Debian / Ubuntu / Alpine
# 解决: masscan 缺少 libpcap 动态库问题
# =========================================================
set -eu

XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/usr/local/bin}"
XRAY_BIN="${XRAY_INSTALL_DIR}/xray"

need_root() {
  [ "$(id -u)" = "0" ] || { echo "❌ 请以 root 运行"; exit 1; }
}

detect_os() {
  . /etc/os-release
  case "${ID:-}" in
    alpine) OS_FAMILY="alpine" ;;
    debian|ubuntu) OS_FAMILY="debian" ;;
    *) case "${ID_LIKE:-}" in
         *debian*) OS_FAMILY="debian" ;;
         *alpine*) OS_FAMILY="alpine" ;;
         *) echo "❌ 不支持的系统类型"; exit 1 ;;
       esac ;;
  esac
  echo "[*] 检测系统：${PRETTY_NAME:-$ID} => ${OS_FAMILY}"
}

# ---------------- 核心依赖安装 ----------------
apt_install_min() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl unzip python3 python3-requests python3-aiohttp \
    masscan libcap2-bin libpcap0.8
  apt-get clean
  rm -rf /var/lib/apt/lists/*
}

apk_install_min() {
  apk update
  apk add --no-cache \
    ca-certificates curl unzip python3 py3-requests py3-aiohttp \
    masscan libpcap || true
  apk add --no-cache libcap-setcap || apk add --no-cache libcap-utils || true
}

# ---------------- 补救编译 masscan ----------------
masscan_build_if_needed() {
  if command -v masscan >/dev/null 2>&1; then return 0; fi
  echo "[*] 系统未提供 masscan，源码编译中..."
  tmpdir="$(mktemp -d)"
  case "$OS_FAMILY" in
    debian)
      apt-get update -y
      apt-get install -y --no-install-recommends git gcc make libpcap-dev
      git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$tmpdir/masscan"
      make -C "$tmpdir/masscan" -j"$(nproc)"
      install -m 0755 "$tmpdir/masscan/bin/masscan" /usr/local/bin/masscan
      apt-get purge -y git gcc make libpcap-dev || true
      apt-get autoremove -y || true
      ;;
    alpine)
      apk add --no-cache --virtual .build-deps build-base git libpcap-dev
      git clone --depth=1 https://github.com/robertdavidgraham/masscan.git "$tmpdir/masscan"
      make -C "$tmpdir/masscan" -j"$(getconf _NPROCESSORS_ONLN || echo 1)"
      install -m 0755 "$tmpdir/masscan/bin/masscan" /usr/local/bin/masscan
      apk del .build-deps
      ;;
  esac
  rm -rf "$tmpdir"
}

# ---------------- 给 masscan 提权 ----------------
ensure_masscan_caps() {
  mbin="$(command -v masscan || true)"
  if [ -n "$mbin" ] && command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=+ep "$mbin" || true
  fi
}

# ---------------- 安装 xray ----------------
map_xray_arch() {
  case "$(uname -m)" in
    x86_64|amd64) XRAY_ARCH="64" ;;
    i386|i686) XRAY_ARCH="32" ;;
    aarch64) XRAY_ARCH="arm64-v8a" ;;
    armv7*|armv7l) XRAY_ARCH="arm32-v7a" ;;
    armv6*|armv6l) XRAY_ARCH="arm32-v6" ;;
    mips64el|mips64le) XRAY_ARCH="mips64le" ;;
    mips64) XRAY_ARCH="mips64" ;;
    mipsel|mipsle) XRAY_ARCH="mips32le" ;;
    mips) XRAY_ARCH="mips32" ;;
    riscv64) XRAY_ARCH="riscv64" ;;
    ppc64le) XRAY_ARCH="ppc64le" ;;
    ppc64) XRAY_ARCH="ppc64" ;;
    s390x) XRAY_ARCH="s390x" ;;
    *) echo "❌ 未支持架构 $(uname -m)"; exit 1 ;;
  esac
}

install_xray() {
  if command -v xray >/dev/null 2>&1 || [ -x "$XRAY_BIN" ]; then
    echo "[*] xray 已存在，跳过安装。"
    return
  fi
  echo "[*] 安装 xray（最新官方版本）..."
  map_xray_arch
  tmpdir="$(mktemp -d)"
  url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip"
  curl -fL --retry 5 -o "${tmpdir}/xray.zip" "$url"
  unzip -q "${tmpdir}/xray.zip" -d "$tmpdir"
  install -m 0755 "${tmpdir}/xray" "$XRAY_BIN"
  rm -rf "$tmpdir"
}

# ---------------- 验证与清理 ----------------
verify_all() {
  echo "========== 验证 =========="
  command -v masscan >/dev/null 2>&1 && masscan --version | head -n1
  command -v xray >/dev/null 2>&1 && xray -version | head -n1
  python3 - <<'PY'
import sys
for m in ("aiohttp","requests"):
    try:
        __import__(m)
        print(f"[OK] import {m}")
    except Exception as e:
        print(f"[FAIL] {m}: {e}")
PY
}

clean_all() {
  echo "[*] 清理无用文件..."
  rm -f requirements.txt 2>/dev/null || true
  find . -maxdepth 1 -name 'requirements.txt' -delete 2>/dev/null || true
  rm -rf /tmp/* /var/tmp/* ~/.cache/pip 2>/dev/null || true
}

# ---------------- 主入口 ----------------
main() {
  need_root
  detect_os
  case "$OS_FAMILY" in
    debian) apt_install_min ;;
    alpine) apk_install_min ;;
  esac
  masscan_build_if_needed
  ensure_masscan_caps
  install_xray
  clean_all
  verify_all
  echo "✅ 所有组件安装成功，可以运行：python3 loopcf.py"
}
main "$@"
