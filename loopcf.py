#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
integrated_all.py

一键流程（已按用户要求调整为 ip:port 可用性检测脚本）：
...
（注：已将 config_node.txt 替换为脚本内固定 BASE_VLESS；所有通过的 ip:port 写入 okcf.txt）
"""

from __future__ import annotations
import os
import sys
import subprocess
import asyncio
import aiohttp
import time
import requests
import threading
import json
import queue
import shutil
import signal
import re
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, urlencode
from typing import Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from collections import defaultdict, OrderedDict

# ================== 用户可配置区域 ==================
IP_FILE = 'ip.txt'  # 输入 IP / CIDR 段
CF_IP_FILE = 'cf_ip.txt'  # masscan + 过滤后输出的 ip:port 列表
LOG_FILE = 'cf.log'  # 日志
RATE = 1000000  # masscan 速率
PORTS = '0-65535'  # 扫描所有端口
MASSCAN_PATH = shutil.which('masscan') or 'masscan'  # masscan 可执行路径（优先系统 PATH）

CONCURRENCY = 200  # aiohttp 并发数（Cloudflare 过滤）
TIMEOUT_SECONDS = 1.5  # aiohttp 请求超时（秒）
BATCH_SIZE = 10000  # masscan 输出批量过滤大小

# CONFIG_NODE 已被用户要求移除，改为脚本内写死 BASE_VLESS
# CONFIG_NODE = "config_node.txt"
OUTPUT_NODE = "cf_node.txt"  # （保留变量名以兼容其它逻辑，但脚本不会写这个文件）
BGP_FILE = "BGP.txt"  # BGP 分类与命名（商家: 网段 列表）

XRAY_PATH = shutil.which("xray") or "/usr/local/bin/xray"  # xray 可执行路径
CURL_CMD = shutil.which("curl") or "/usr/bin/curl"  # curl 可执行路径

MAX_WORKERS = 5  # xray 并发进程数（同时测试的节点数量）
LOCAL_SOCKS_BASE = 18080  # 本地 socks 起始端口（多个进程依次+1）

XRAY_START_WAIT = 0.8  # （保留项）xray 启动等待时间（秒）
CURL_TIMEOUT = 12  # curl 每次请求最大耗时（秒）
TEST_URL = "https://www.gstatic.com/generate_204"  # 旧字段，兼容保留（实际以 TEST_URLS 为准）
SUCCESS_HTTP_CODES = {200, 204}  # 检测逻辑改为仅接受 200/204

TMP_DIR = ".xray_tmp"  # 临时目录（存放临时配置）

# ---- 新检测逻辑的额外配置 ----
TEST_URLS = [
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
]  # 每个节点依次测试的 URL 列表（都通过才算成功）
PER_URL_TRIES = 1  # 每个 URL 需要连续通过的次数
SOCKS_READY_TIMEOUT = 5.0  # 等待 socks 端口就绪的最长时间（秒）
USER_AGENT = "Mozilla/5.0"  # curl 使用的 UA
# --------------------------------

# --- Telegram 机器人配置（你提供的） ---
TG_BOT_TOKEN = "8461895834:AAG3jgP69NK8qV32EKBdkeY_Co8ksVCXv04"
TG_CHAT_ID = "1989449209"

# --- 新要求文件：最终通过的 ip:port 写入 okcf.txt ---
OK_FILE = "okcf.txt"

# ---- 你给定的固定测试模板（已写死） ----
BASE_VLESS = (
    "vless://9ec93812-41a1-4c1b-9438-f15e39566a28@1.1.1.1:22"
    "?encryption=none&security=tls&allowInsecure=1&type=ws&host=ak.zhsxsr.top&path=%2Fcsgo#TEST"
)
# ====================================================

# ------------------ 日志（改为 cf.py 的实现） ------------------
class Logger:
    """同时写终端和日志文件，并给每行加时间戳"""
    def __init__(self, log_file):
        self.terminal = sys.__stdout__
        self.log = open(log_file, "w", buffering=1, encoding="utf-8")  # 行缓冲，覆盖写

    def write(self, message):
        if message:
            # 逐行加时间戳（保留空行）
            lines = message.splitlines(True)
            ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
            message = "".join(ts + ln if ln.strip() else ln for ln in lines)
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

# 将 stdout/stderr 重定向到 Logger（subprocess 的输出仍用 PIPE 单独处理）
sys.stdout = Logger(LOG_FILE)
sys.stderr = sys.stdout


# -------------------- Telegram --------------------
def send_telegram(text: str) -> None:
    api = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": text}
    try:
        r = requests.post(api, data=payload, timeout=10)
        if r.status_code != 200:
            print(f"[WARN] Telegram 通知失败：HTTP {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[WARN] Telegram 通知异常：{e}")


# -------------------- masscan + 过滤 --------------------
async def check_ipport_for_cf(ip: str, port: int, session: aiohttp.ClientSession) -> bool:
    url = f"http://{ip}:{port}/cdn-cgi/trace"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
                               allow_redirects=False) as resp:
            text = await resp.text()
            tl = text.lower()
            if ("400 the plain http request was sent to https port" in tl and "cloudflare" in tl) or (
                    "visit_scheme=http" in tl):
                return True
            return False
    except Exception:
        return False


async def filter_batch_and_write(open_ipports, out_file):
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, force_close=True)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        sem = asyncio.Semaphore(CONCURRENCY)

        async def bound(ip, port):
            async with sem:
                ok = await check_ipport_for_cf(ip, port, session)
                return ip, port, ok

        tasks = [bound(ip, port) for (ip, port) in open_ipports]
        for fut in asyncio.as_completed(tasks):
            ip, port, ok = await fut
            if ok:
                out_file.write(f"{ip}:{port}\n")
                out_file.flush()


def pump_stderr_to_log(stream):
    """
    masscan 的进度多用 '\r' 回车刷新，这里把 '\r' 也当作一行结束写出去，
    这样 cf.log 和终端都能实时看到每次刷新。
    """
    buf = ""
    while True:
        ch = stream.read(1)
        if ch == "":  # EOF
            if buf:
                sys.stdout.write(buf + "\n")
                sys.stdout.flush()
            break
        if ch in ("\r", "\n"):
            sys.stdout.write(buf + "\n")
            sys.stdout.flush()
            buf = ""
        else:
            buf += ch


def run_masscan_scan_and_filter():
    if not os.path.isfile(IP_FILE):
        print(f"[ERROR] {IP_FILE} 不存在！")
        sys.exit(1)

    ip_targets = []
    with open(IP_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            ip_targets.append(line)
    if not ip_targets:
        print("[ERROR] ip.txt 里没有有效的 IP 或 CIDR")
        sys.exit(1)

    # 清空输出文件
    with open(CF_IP_FILE, 'w'):
        pass

    cmd = [
        MASSCAN_PATH,
        *ip_targets,
        f'-p{PORTS}',
        '--rate', str(RATE),
        '-oL', '-'          # 结果（open ...）走 stdout
    ]
    print(f"[+] 启动 masscan：{' '.join(cmd)}")

    # 注意：stderr=PIPE，用线程泵到日志/终端；stdout=PIPE，用主线程解析 open 行
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # 开线程实时转发 masscan 的进度（stderr）到日志+终端
    thr = threading.Thread(target=pump_stderr_to_log, args=(proc.stderr,), daemon=True)
    thr.start()

    open_batch = []
    count_total = 0
    t0 = time.time()

    with open(CF_IP_FILE, 'a') as fout:
        # 逐行解析 masscan stdout 的 open 结果
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[0] == 'open':
                # open tcp 443 1.2.3.4 ...
                port = parts[2]
                ip = parts[3]
                try:
                    port_int = int(port)
                except ValueError:
                    continue
                open_batch.append((ip, port_int))
                count_total += 1

                if len(open_batch) >= BATCH_SIZE:
                    asyncio.run(filter_batch_and_write(open_batch, fout))
                    open_batch.clear()

        # masscan 结束
        proc.wait()

        # 收尾：处理剩余 batch
        if open_batch:
            asyncio.run(filter_batch_and_write(open_batch, fout))
            open_batch.clear()

    # 等待进度泵线程吃完最后的 stderr
    thr.join(timeout=2)

    elapsed = time.time() - t0
    print(f"[+] 全部扫描检测完成，总记录扫描 {count_total} 条。用时 {elapsed:.2f} 秒。")
    if proc.returncode != 0:
        print(f"[WARN] masscan 返回码 {proc.returncode}")


# -------------------- VLESS 解析 / 构造 / 测试 --------------------
def parse_vless_url(vless_url: str) -> Dict:
    u = urlparse(vless_url)
    qs = {k: v[0] for k, v in parse_qs(u.query).items()}
    return {
        "uuid": u.username or "",
        "address": u.hostname or "",
        "port": int(u.port) if u.port else 0,
        "params": qs,
        "fragment": u.fragment or "",
        "raw": vless_url
    }


def build_vless_link(uuid: str, ip: str, port: int, params: Dict, fragment: str) -> str:
    query = urlencode(params, doseq=True, safe="%/:?&=")
    link = f"vless://{uuid}@{ip}:{port}"
    if query:
        link += f"?{query}"
    if fragment:
        link += f"#{fragment}"
    return link


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def build_xray_config_for_vless(ip: str, port: int, base: Dict, local_socks_port: int) -> Dict:
    uuid = base["uuid"]
    params = base["params"]
    network = params.get("type", "tcp").lower()
    security = params.get("security", "").lower()
    host_hdr = params.get("host", base["address"]) or base["address"]
    path = unquote(params.get("path", "/") or "/")
    allow_insecure = (params.get("allowInsecure", "0") == "1")
    sni = params.get("sni", host_hdr) or host_hdr

    stream_settings = {"network": network}
    if security == "tls" or params.get("security", "").lower() == "tls":
        tls_settings = {
            "allowInsecure": allow_insecure,
            "serverName": sni,
            "alpn": ["http/1.1"],
            "fingerprint": "chrome"
        }
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = tls_settings
    if network == "ws":
        stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host_hdr}}

    inbounds = [{
        "port": local_socks_port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"udp": True}
    }]
    outbounds = [{
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": ip,
                "port": int(port),
                "users": [{"id": uuid, "encryption": params.get("encryption", "none")}]
            }]
        },
        "streamSettings": stream_settings
    }]
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds}


def run_xray_with_config(cfg: Dict, cfg_path: str) -> subprocess.Popen:
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    proc = subprocess.Popen(
        [XRAY_PATH, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    return proc


def stop_proc(proc: subprocess.Popen):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=3)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


# -------------------- 健康检测 --------------------
def wait_socks_ready(port: int, timeout: float = SOCKS_READY_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except Exception:
            time.sleep(0.1)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def curl_once(url: str, port: int) -> Tuple[bool, int, float]:
    cmd = [
        CURL_CMD,
        "-x", f"socks5h://127.0.0.1:{port}",
        "--max-time", str(CURL_TIMEOUT),
        "-s", "-o", "/dev/null",
        "-w", "%{http_code} %{time_total}",
        "--http2",
        "-A", USER_AGENT,
        url
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        out = (r.stdout or "").strip()
        parts = out.split()
        code = int(parts[0]) if parts and parts[0].isdigit() else -1
        t_total = float(parts[1]) if len(parts) > 1 else CURL_TIMEOUT
        ok = (code in SUCCESS_HTTP_CODES)
        return ok, code, t_total
    except Exception:
        return False, -1, CURL_TIMEOUT


def curl_check_stable(url: str, port: int, tries: int = PER_URL_TRIES) -> bool:
    for _ in range(tries):
        ok, code, t_total = curl_once(url, port)
        if not ok:
            return False
    return True


def parse_ip_port(line: str) -> Optional[Tuple[str, int]]:
    s = line.strip()
    if not s:
        return None
    if s.startswith("["):  # IPv6
        try:
            i = s.index("]")
            ip = s[1:i]
            rem = s[i + 1:]
            if rem.startswith(":"):
                return ip, int(rem[1:])
            return None
        except Exception:
            return None
    else:
        if ":" not in s:
            return None
        a, b = s.rsplit(":", 1)
        try:
            return a, int(b)
        except Exception:
            return None


def test_one_replaced_node(ip_port: str, base_parsed: Dict, local_port: int, tmp_dir: str) -> bool:
    parsed = parse_ip_port(ip_port)
    if not parsed:
        return False
    ip, port = parsed
    cfg = build_xray_config_for_vless(ip, port, base_parsed, local_port)
    cfg_name = os.path.join(tmp_dir, f"x_{sanitize_filename(ip_port)}.json")
    proc = None
    try:
        proc = run_xray_with_config(cfg, cfg_name)
        if not wait_socks_ready(local_port, SOCKS_READY_TIMEOUT):
            return False
        for url in TEST_URLS:
            if not curl_check_stable(url, local_port, PER_URL_TRIES):
                return False
        return True
    except Exception:
        return False
    finally:
        if proc:
            stop_proc(proc)
        try:
            os.remove(cfg_name)
        except Exception:
            pass


# ------------------ A 脚本 ------------------
def parse_vless_line_for_a(line: str) -> Optional[Tuple[str, int, str]]:
    s = line.strip()
    if not s:
        return None
    m = re.match(r'^vless://[^@]+@([\d\.]+):(\d+)(\?.*)?$', s)
    if m:
        return m.group(1), int(m.group(2)), s
    m2 = re.match(r'^vless://[^@]+@([\d\.]+):(\d+)(#.*)?$', s)
    if m2:
        return m2.group(1), int(m2.group(2)), s
    return None


def load_bgp_file(filename: str) -> OrderedDict:
    bgp_map = OrderedDict()
    if not os.path.exists(filename):
        print(f"[WARN] BGP 文件 {filename} 不存在")
        return bgp_map
    cur = None
    with open(filename, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                cur = None
                continue
            if line.endswith(":"):
                cur = line.rstrip(":")
                bgp_map[cur] = []
                continue
            if cur:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    bgp_map[cur].append(net)
                except Exception:
                    print(f"[WARN] BGP 无法解析网段: {line}")
    return bgp_map


def find_vendor_for_ip(ip: str, bgp_map: OrderedDict) -> Optional[str]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return None
    for vendor, nets in bgp_map.items():
        for net in nets:
            if ip_obj in net:
                return vendor
    return None


def replace_fragment(line: str, new_name: str) -> str:
    m = re.match(r'^(.*?)(?:#.*)?$', line)
    if m:
        return f"{m.group(1)}#{new_name}"
    return line


def run_a_filter_on_file(input_file: str, bgp_file: str, output_file: str) -> int:
    parsed = {}
    with open(input_file, "r", encoding="utf-8") as fin:
        for raw in fin:
            raw = raw.strip()
            if not raw:
                continue
            res = parse_vless_line_for_a(raw)
            if not res:
                continue
            ip, port, line = res
            key = (ip, port)
            if key not in parsed:   # ✅ 只在完全相同 ip+port 时去重
                parsed[key] = line

    bgp_map = load_bgp_file(bgp_file)

    vendor_nodes = defaultdict(list)
    no_vendor = []
    for (ip, port), line in parsed.items():
        vendor = find_vendor_for_ip(ip, bgp_map)
        if vendor:
            vendor_nodes[vendor].append((ip, line))
        else:
            no_vendor.append((ip, line))

    output_lines = []
    for vendor in bgp_map.keys():
        if vendor not in vendor_nodes:
            continue
        for idx, (ip, line) in enumerate(vendor_nodes[vendor], start=1):
            new_name = f"HK-优化MAX-{vendor}-{idx:02d}"
            output_lines.append(replace_fragment(line, new_name))
    for idx, (ip, line) in enumerate(no_vendor, start=1):
        new_name = f"HK-优化-{idx:02d}"
        output_lines.append(replace_fragment(line, new_name))

    with open(output_file, "w", encoding="utf-8") as fout:
        for l in output_lines:
            fout.write(l + "\n")
    return len(output_lines)



# ------------------ 辅助统计 ------------------
def count_vendors(filename: str, bgp_file: str) -> dict[str, int]:
    bgp_map = load_bgp_file(bgp_file)
    counts = {}
    if not os.path.exists(filename):
        return counts
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parsed = parse_vless_line_for_a(line)
            if not parsed:
                continue
            ip, _, _ = parsed
            vendor = find_vendor_for_ip(ip, bgp_map) or "未分类"
            counts[vendor] = counts.get(vendor, 0) + 1
    return counts


# ------------------ 主流程 ------------------
def format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}秒"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}分钟{s}秒"
    else:
        h, rem = divmod(int(seconds), 3600)
        m = rem // 60
        return f"{h}小时{m}分钟"


def main():
    start_time = time.time()

    # 读取并解析固定 BASE_VLESS
    base_parsed = parse_vless_url(BASE_VLESS)

    # ---- 在任何修改 okcf.txt 之前，记录初始商家分布 & 初始节点数量 ----
    # 初始节点数 = okcf.txt 在脚本运行前的行数（ip:port）
    if os.path.exists(OK_FILE):
        with open(OK_FILE, "r", encoding="utf-8") as f:
            initial_ok_lines = [ln.strip() for ln in f if ln.strip()]
    else:
        initial_ok_lines = []
    initial_count = len(initial_ok_lines)

    # 为初始商家分布生成临时 vless 文件并统计（保持原来统计逻辑）
    os.makedirs(TMP_DIR, exist_ok=True)
    temp_initial_vless = os.path.join(TMP_DIR, "initial_vless.txt")
    with open(temp_initial_vless, "w", encoding="utf-8") as f:
        for ipport in initial_ok_lines:
            parsed = parse_ip_port(ipport)
            if not parsed:
                continue
            ip, port = parsed
            vlink = build_vless_link(base_parsed["uuid"], ip, port, base_parsed["params"], base_parsed["fragment"])
            f.write(vlink + "\n")
    # run_a_filter_on_file 会对文件重命名/去重，返回最终数量（我们在临时文件上运行，以保持统计方式一致）
    run_a_filter_on_file(temp_initial_vless, BGP_FILE, temp_initial_vless)
    initial_vendor_count = count_vendors(temp_initial_vless, BGP_FILE)

    print("[STEP 1] 启动 masscan 扫描并过滤（生成 cf_ip.txt）...")
    if not shutil.which(MASSCAN_PATH):
        print(f"[ERROR] 未找到 masscan (路径: {MASSCAN_PATH})")
        return
    run_masscan_scan_and_filter()

    if not os.path.exists(CF_IP_FILE):
        print(f"[ERROR] 扫描后未生成 {CF_IP_FILE}，退出。")
        return

    # 读取 cf_ip.txt，但按 ip:port 去重（用户要求：相同 ip 不同 port 视为不同）
    seen = set()
    ipports = []
    with open(CF_IP_FILE, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            # 只按 ip:port 去重
            if s not in seen:
                seen.add(s)
                ipports.append(s)

    if not ipports:
        print("[INFO] cf_ip.txt 为空，无需后续检测。")
        return

    # 现有 okcf.txt 的内容（用来避免重复写入）
    exist_ok_set = set()
    if os.path.exists(OK_FILE):
        with open(OK_FILE, "r", encoding="utf-8") as f:
            for l in f:
                if l.strip():
                    exist_ok_set.add(l.strip())

    # 并发测试 ip:port 列表，测试通过则加入 final_ok_links（ip:port 形式）
    final_ok_links = []

    os.makedirs(TMP_DIR, exist_ok=True)
    port_pool = queue.Queue()
    for i in range(MAX_WORKERS):
        port_pool.put(LOCAL_SOCKS_BASE + i)

    def task_test_ipport(ipport: str):
        local = port_pool.get()
        try:
            ok = test_one_replaced_node(ipport, base_parsed, local, TMP_DIR)
            return ipport, ok
        finally:
            port_pool.put(local)

    futures = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for ipp in ipports:
            futures.append(ex.submit(task_test_ipport, ipp))
        for fut in as_completed(futures):
            ipp, ok = fut.result()
            if ok:
                final_ok_links.append(ipp)

    # 将通过的 ip:port 写入 okcf.txt（保持已有的不重复追加）
    if final_ok_links:
        # 保证文件存在
        if not os.path.exists(OK_FILE):
            open(OK_FILE, "a").close()
        with open(OK_FILE, "a", encoding="utf-8") as f:
            for ipp in final_ok_links:
                if ipp not in exist_ok_set:
                    f.write(ipp + "\n")
                    exist_ok_set.add(ipp)

    # 读取 okcf.txt 的最终全部内容（作为最终节点集）
    with open(OK_FILE, "r", encoding="utf-8") as f:
        all_ok_final = [ln.strip() for ln in f if ln.strip()]
    final_count = len(all_ok_final)

    # 为了保持“节点变化和最终商家分布”与原来逻辑一致：
    # 把 okcf.txt 中的 ip:port 转成 vless 行写入临时文件，运行 A 脚本逻辑（重命名/去重），然后统计商家
    temp_final_vless = os.path.join(TMP_DIR, "final_vless.txt")
    with open(temp_final_vless, "w", encoding="utf-8") as f:
        for ipport in all_ok_final:
            parsed = parse_ip_port(ipport)
            if not parsed:
                continue
            ip, port = parsed
            vlink = build_vless_link(base_parsed["uuid"], ip, port, base_parsed["params"], base_parsed["fragment"])
            f.write(vlink + "\n")
    # 运行 A 脚本的去重/重命名逻辑（在临时文件上操作）
    final_count_after_a = run_a_filter_on_file(temp_final_vless, BGP_FILE, temp_final_vless)
    final_vendor_count = count_vendors(temp_final_vless, BGP_FILE)

    # ---- 节点变化计算：最终分布 - 初始分布 ----
    diff_entries = []
    vendors_union = set(initial_vendor_count) | set(final_vendor_count)
    for vendor in vendors_union:
        before = initial_vendor_count.get(vendor, 0)
        after = final_vendor_count.get(vendor, 0)
        diff = after - before
        if diff != 0:
            diff_entries.append((vendor, diff))

    diff_lines = []
    for vendor, diff in diff_entries:
        emoji = "🟢" if diff > 0 else "🔴"
        diff_lines.append(f"{emoji} {vendor}：{diff}")
    diff_text = "\n".join(diff_lines) if diff_lines else "无变化"

    try:
        os.rmdir(TMP_DIR)
    except Exception:
        pass

    elapsed = time.time() - start_time
    elapsed_str = format_elapsed(elapsed)

    vendor_lines = []
    for vendor, count in sorted(final_vendor_count.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            vendor_lines.append(f"🏷️ {vendor}：{count}")
    vendor_text = "\n".join(vendor_lines) if vendor_lines else "无"

    msg = (
        f"📡【CloudFlare-循环扫描】\n"
        f"📡【服务器】 人民云-法国\n"
        f"🔹 初始节点：{initial_count}\n"
        f"📦 最终节点：{final_count}\n"
        f"⏱️ 耗时：{elapsed_str}\n\n"
        f"📊 节点变化\n{diff_text}\n\n"
        f"📍 最终商家分布\n{vendor_text}"
    )
    print(msg)
    send_telegram(msg)


if __name__ == "__main__":
    while True:
        # 进入 main() 前清空日志
        open(LOG_FILE, "w").close()
        main()
        time.sleep(60)
