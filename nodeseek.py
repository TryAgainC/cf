#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NodeSeek 关键词监控脚本
========================

功能：
  - 抓取 NodeSeek 的 RSS 最新发帖列表 (https://rss.nodeseek.com/)
  - 按你设置的关键词过滤标题（可选也过滤正文摘要）
  - 命中关键词的新帖子，通过 Bark 推送到你的 iPhone
  - 已经推送过的帖子不会重复推送（本地文件去重）

使用方式：
  1. 在下面 KEYWORDS 里填你关心的关键词（支持中英文，大小写不敏感）
  2. 在 CHECK_INTERVAL_SECONDS 里设置每隔多少秒检查一次
  3. 直接运行脚本即可，它会自己常驻并按设定的间隔循环检查，
     不再需要 cron 定时调度：
        python3 nodeseek_monitor.py
     建议配合 nohup / screen / tmux / systemd 等方式让它在后台持续运行，例如：
        nohup python3 /path/to/nodeseek_monitor.py >> /path/to/nodeseek_monitor.log 2>&1 &

依赖：
  pip3 install requests feedparser
"""

import os
import sys
import time
import json
import html
import fcntl
import tempfile
import requests
import feedparser
from datetime import datetime

# ================== 配置区（按需修改） ==================

# 你要监控的关键词列表，命中标题（或正文摘要）中的任意一个即推送
KEYWORDS = [
    "JP",
    "bage",
    "zouter"
    # 在这里继续添加你自己的关键词...
]

# 每隔多少秒检查一次（例如 300 表示每 5 分钟检查一次）
CHECK_INTERVAL_SECONDS = 10

# 是否同时匹配正文摘要（RSS summary/description），不仅仅是标题
MATCH_SUMMARY_TOO = True

# 关键词匹配是否大小写不敏感（英文关键词建议保持 True）
CASE_INSENSITIVE = True

# NodeSeek RSS 地址（一般不需要改）
RSS_URL = "https://rss.nodeseek.com/"

# 你的 Bark 推送地址（不要在结尾多加斜杠）
BARK_BASE_URL = "https://api.day.app/LzKC6mQqMS3aKiX2RA3MML"

# 去重状态文件：记录已经推送/已经见过的帖子 ID
# 默认放在脚本所在目录，保证每次调用都能读到同一份文件
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodeseek_seen.json")

# 单实例锁文件。即使不小心多次执行 nohup，也只允许一个进程真正运行。
# fcntl.flock 是 Debian/Linux 自带的进程锁；进程退出或被杀后会自动释放。
LOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodeseek.lock")

# 单次最多推送几条，防止一次性关键词命中过多刷屏（0 表示不限制）
MAX_NOTIFY_PER_RUN = 10

# 请求超时时间（秒）
REQUEST_TIMEOUT = 15

# =========================================================


def acquire_single_instance_lock():
    """获取进程级单实例锁；已有实例运行时返回 None。"""
    try:
        lock_handle = open(LOCK_FILE, "a+", encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"无法打开单实例锁文件 {LOCK_FILE}: {e}") from e

    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_handle.seek(0)
        owner = lock_handle.read().strip()
        lock_handle.close()
        owner_text = f"（锁文件记录：{owner}）" if owner else ""
        print(f"已有一个 NodeSeek 监控实例正在运行，本次启动退出{owner_text}")
        return None

    # PID 仅用于排查；真正防止并发的是上面的 flock，而不是这个文本内容。
    lock_handle.seek(0)
    lock_handle.truncate()
    lock_handle.write(f"pid={os.getpid()} started={datetime.now().isoformat(timespec='seconds')}\n")
    lock_handle.flush()
    os.fsync(lock_handle.fileno())
    return lock_handle


def load_seen_ids():
    """
    读取已经处理过的帖子 ID。

    返回 (seen_list, seen_set, is_first_run)：
    - seen_list 保持"发现顺序"（旧 -> 新），用于后续按时间顺序截断
    - seen_set  用于 O(1) 查重
    - is_first_run 表示是否首次运行
    """
    if not os.path.exists(STATE_FILE):
        return [], set(), True  # 第三个返回值表示"是否首次运行"
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        ids_list = list(data.get("seen_ids", []))
        return ids_list, set(ids_list), False
    except Exception as e:
        print(f"[警告] 读取状态文件失败，将视为首次运行: {e}")
        return [], set(), True


def save_seen_ids(seen_ids_list, keep_latest=500):
    """
    保存已处理过的帖子 ID（有序列表，旧 -> 新）。
    只保留最近 keep_latest 个，避免文件无限增长
    （RSS 本身只提供最近几十条，这个上限完全够用）。

    注意：之前的实现是把 set 转成 list 再截断，而 Python 的 set
    不保证顺序，导致"保留最近500个"实际上是随机丢弃/保留，
    可能把仍在 RSS 最新窗口内、已经推送过的帖子ID 误删，
    造成下一轮又被判定为"新帖子"而重复推送。
    这里改成始终维护一个按发现顺序排列的 list，截断时
    只丢弃列表最前面（最旧）的部分，保证语义正确。
    """
    ids_to_save = seen_ids_list[-keep_latest:] if len(seen_ids_list) > keep_latest else seen_ids_list
    state_dir = os.path.dirname(STATE_FILE)
    temp_path = None
    try:
        # 必须在同一目录创建临时文件，os.replace 才能保证原子替换。
        fd, temp_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(STATE_FILE)}.",
            suffix=".tmp",
            dir=state_dir,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"seen_ids": ids_to_save}, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, STATE_FILE)
        temp_path = None
    except Exception as e:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        # 状态没有可靠落盘时绝不能继续推送，否则下一轮还会把帖子当成新的。
        raise RuntimeError(f"写入状态文件失败，已取消本轮推送: {e}") from e


def fetch_posts():
    """抓取并解析 NodeSeek RSS，返回 [(post_id, title, link, summary), ...]"""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        )
    }
    resp = requests.get(RSS_URL, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    feed = feedparser.parse(resp.content)
    if feed.bozo and not feed.entries:
        raise RuntimeError(f"RSS 解析失败: {feed.bozo_exception}")

    posts = []
    for entry in feed.entries:
        # 帖子唯一标识：优先用 guid/id，没有就退化用 link
        post_id = entry.get("id") or entry.get("guid") or entry.get("link")
        link = entry.get("link", "")
        title = html.unescape(entry.get("title", "").strip())
        summary = html.unescape(entry.get("summary", "").strip()) if entry.get("summary") else ""
        if not post_id:
            continue
        posts.append((str(post_id), title, link, summary))

    return posts


def match_keywords(title, summary):
    """返回命中的关键词，没命中返回 None"""
    haystack = title + ("\n" + summary if MATCH_SUMMARY_TOO else "")
    if CASE_INSENSITIVE:
        haystack_cmp = haystack.lower()
    else:
        haystack_cmp = haystack

    for kw in KEYWORDS:
        kw_cmp = kw.lower() if CASE_INSENSITIVE else kw
        if kw_cmp in haystack_cmp:
            return kw
    return None


def send_bark_notification(title, body, url=None, group="NodeSeek"):
    """通过 Bark 推送通知"""
    # Bark 的 GET 接口路径需要对内容做 URL 编码，requests 的 params 会自动处理
    endpoint = f"{BARK_BASE_URL}/{requests.utils.quote(title)}/{requests.utils.quote(body)}"
    params = {"group": group}
    if url:
        params["url"] = url
    try:
        r = requests.get(endpoint, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as e:
        print(f"[错误] Bark 推送失败: {e}")
        return False


def run_once():
    """执行一轮检查：抓取 RSS -> 过滤新帖 -> 匹配关键词 -> 推送"""
    print("=" * 50)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] NodeSeek 关键词监控 - 开始本轮检查")
    print(f"监控关键词: {KEYWORDS}")

    seen_list, seen_set, is_first_run = load_seen_ids()

    try:
        posts = fetch_posts()
    except Exception as e:
        print(f"[错误] 抓取 RSS 失败: {e}")
        return

    print(f"抓取到 {len(posts)} 条帖子")

    if is_first_run:
        # 首次运行：只建立基线，不发送通知，避免把历史帖子当新帖子推送一遍
        for post_id, _, _, _ in posts:
            if post_id not in seen_set:
                seen_set.add(post_id)
                seen_list.append(post_id)
        save_seen_ids(seen_list)
        print("首次运行，已建立基线，本次不发送通知。之后的检查会正常推送新命中的帖子。")
        return

    new_matches = []
    state_changed = False
    for post_id, title, link, summary in posts:
        if post_id in seen_set:
            continue
        # 无论是否命中关键词，都标记为已见过，防止下次重复判断/重复推送
        seen_set.add(post_id)
        seen_list.append(post_id)
        state_changed = True

        hit_kw = match_keywords(title, summary)
        if hit_kw:
            new_matches.append((post_id, title, link, hit_kw))

    # 先把所有新看到的 ID 可靠落盘，再调用 Bark。
    # 这样即使 Bark 已收到消息后脚本被 kill，重启也不会重复发送同一帖子。
    if state_changed:
        save_seen_ids(seen_list)

    if not new_matches:
        print("没有发现新命中的关键词帖子。")
    else:
        print(f"发现 {len(new_matches)} 条命中关键词的新帖子:")
        to_send = new_matches
        if MAX_NOTIFY_PER_RUN and len(to_send) > MAX_NOTIFY_PER_RUN:
            print(f"[提示] 命中数量超过 {MAX_NOTIFY_PER_RUN} 条，仅推送最新的 {MAX_NOTIFY_PER_RUN} 条")
            to_send = to_send[-MAX_NOTIFY_PER_RUN:]

        for post_id, title, link, hit_kw in to_send:
            print(f"  - [{hit_kw}] {title} -> {link}")
            ok = send_bark_notification(
                title=f"NodeSeek: {hit_kw}",
                body=title,
                url=link,
            )
            if ok:
                print("    推送成功")
            else:
                print("    推送失败")

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 本轮检查结束。")


def main():
    """常驻运行：每隔 CHECK_INTERVAL_SECONDS 秒执行一轮检查，直到被手动终止（Ctrl+C）"""
    # nohup 重定向到文件时 stdout 默认会块缓冲；改为逐行刷新，方便实时 tail 日志。
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(line_buffering=True)

    lock_handle = acquire_single_instance_lock()
    if lock_handle is None:
        return

    try:
        print(f"脚本已启动（PID {os.getpid()}），将每隔 {CHECK_INTERVAL_SECONDS} 秒检查一次。按 Ctrl+C 可停止。")
        while True:
            try:
                run_once()
            except Exception as e:
                # 捕获单轮检查中未预料到的异常，避免因为一次报错导致整个监控进程退出
                print(f"[错误] 本轮检查出现未捕获的异常: {e}")

            time.sleep(CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("收到停止信号，脚本退出。")
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


if __name__ == "__main__":
    main()
