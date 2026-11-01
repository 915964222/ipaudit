"""免费代理预筛（proxy-harvest）。

抓公共免费代理源 → 并发验证连通性与延迟 → 输出 ClaudeCN「自定义列表」
可粘贴的格式（每行一条，http://ip:port 或 socks5://ip:port）。

定位：把「几百比一」的盲试漏斗收窄——先在这里用 TCP 连通 + 简单 HTTP
探活筛掉死代理，剩下活着的再交给 ClaudeCN 做上游额度检测。
红线不变：只做连通性探测，不建立数据通道，不做任何穿透。
"""

from __future__ import annotations

import concurrent.futures
import random
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

HEADERS = {"User-Agent": "ipaudit/0.1 (+local diagnostic tool)"}

# 公共免费代理源（与 ClaudeCN 同源家族，去重后保留稳定端点）
SOURCES: list[dict] = [
    {"id": "thespeedx_http", "name": "TheSpeedX HTTP",
     "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
     "proto": "http"},
    {"id": "thespeedx_socks5", "name": "TheSpeedX SOCKS5",
     "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
     "proto": "socks5"},
    {"id": "roosterkid_https", "name": "OpenProxyList HTTPS",
     "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
     "proto": "http"},
    {"id": "roosterkid_socks5", "name": "OpenProxyList SOCKS5",
     "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
     "proto": "socks5"},
    {"id": "hookzof_socks5", "name": "hookzof SOCKS5",
     "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
     "proto": "socks5"},
    {"id": "vpslab_ssl", "name": "VPSLab HTTP SSL",
     "url": "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_ssl.txt",
     "proto": "http"},
    {"id": "databay_http", "name": "DataBay HTTP",
     "url": "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
     "proto": "http"},
    {"id": "databay_socks5", "name": "DataBay SOCKS5",
     "url": "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt",
     "proto": "socks5"},
]

# 探活目标：走代理请求一个轻量端点，2xx/3xx 即视为代理可用
PROBE_URL = "http://ip-api.com/line/?fields=query"


@dataclass
class HarvestResult:
    total_fetched: int = 0
    total_alive: int = 0
    output: list[str] = field(default_factory=list)   # ClaudeCN 自定义列表格式
    source_results: list[dict] = field(default_factory=list)
    duration_ms: int = 0


def fetch_source(src: dict, timeout: float = 15.0, retries: int = 2) -> tuple[dict, set[str]]:
    """拉一个源（源服务器波动大，失败重试），返回结果与代理集合。"""
    last_err = ""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(src["url"], headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
            proxies = parse_proxy_lines(text, src["proto"])
            return {"id": src["id"], "name": src["name"],
                    "count": len(proxies), "error": ""}, proxies
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(1.5)
    return {"id": src["id"], "name": src["name"], "count": 0, "error": last_err}, set()


def parse_proxy_lines(text: str, proto: str) -> set[str]:
    """解析 ip:port 行 / protocol://ip:port 行，返回内部键 proto://ip:port。"""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 允许 "1.2.3.4:8080"、"http://1.2.3.4:8080"、"socks5://1.2.3.4:1080"
        if "://" in line:
            p, _, rest = line.partition("://")
            p = p.lower()
            if p not in ("http", "socks4", "socks5"):
                continue
        else:
            p, rest = proto, line
        rest = rest.split()[0].split(",")[0]
        if ":" not in rest:
            continue
        ip, _, port = rest.rpartition(":")
        if not _valid_ipv4(ip) or not port.isdigit() or not (1 <= int(port) <= 65535):
            continue
        out.add(f"{p}://{ip}:{int(port)}")
    return out


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def probe_proxy(key: str, timeout: float = 4.0) -> tuple[str, int | None, str]:
    """验证单条代理：TCP 连上后发一个 HTTP 请求，2xx/3xx = 活。

    只探测不穿透：拿到响应码即断开。返回 (key, latency_ms|None, error)。
    socks4/socks5 不做握手验证（标准库无 SOCKS 客户端），只做 TCP 连通，
    交给 ClaudeCN 的上游检测做真验证。
    """
    proto, _, rest = key.partition("://")
    ip, _, port = rest.rpartition(":")
    t0 = time.time()
    try:
        if proto == "http":
            proxy_handler = urllib.request.ProxyHandler({"http": key})
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(PROBE_URL, headers=HEADERS)
            with opener.open(req, timeout=timeout):
                latency = int((time.time() - t0) * 1000)
            return key, latency, ""
        # socks4/socks5：TCP 连通性探测（确认端口活着，握手交给下游）
        with socket.create_connection((ip, int(port)), timeout=timeout):
            latency = int((time.time() - t0) * 1000)
        return key, latency, ""
    except OSError as e:
        return key, None, str(e)


def harvest(max_alive: int = 30, sample_per_source: int = 400,
            workers: int = 64, probe_timeout: float = 4.0,
            progress=None) -> HarvestResult:
    """抓取全部源 → 去重 → 分层抽样 → 并发探活 → 输出 ClaudeCN 列表。

    max_alive: 凑够这么多活代理就停（ClaudeCN 目标 10 个，留 3 倍余量）
    sample_per_source: 每个源最多抽多少条进验证（免费源动辄几千条，全验太慢）
    progress: 可选回调 (done, total)，用于 CLI 进度显示
    """
    result = HarvestResult()
    t0 = time.time()

    # 1. 并发抓源
    candidates: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        futs = {ex.submit(fetch_source, s): s for s in SOURCES}
        for fut in concurrent.futures.as_completed(futs):
            r, proxies = fut.result()
            result.source_results.append(r)
            candidates |= proxies
    result.total_fetched = len(candidates)
    if progress:
        progress(0, len(candidates))

    # 2. 分层抽样：http 与 socks 分开抽，避免 http 占满名额
    http_keys = sorted(k for k in candidates if k.startswith("http://"))
    socks_keys = sorted(k for k in candidates if not k.startswith("http://"))
    rng = random.Random()
    sample = (rng.sample(http_keys, min(len(http_keys), sample_per_source))
              + rng.sample(socks_keys, min(len(socks_keys), sample_per_source)))
    rng.shuffle(sample)

    # 3. 并发探活，凑够 max_alive 即止
    alive: list[tuple[str, int]] = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe_proxy, k, probe_timeout): k for k in sample}
        for fut in concurrent.futures.as_completed(futures):
            key, latency, _err = fut.result()
            done += 1
            if latency is not None:
                alive.append((key, latency))
                if len(alive) >= max_alive:
                    for f in futures:
                        f.cancel()
                    break
            if progress and done % 50 == 0:
                progress(done, len(sample))

    alive.sort(key=lambda x: x[1])               # 按延迟排序，快的在前
    result.total_alive = len(alive)
    result.output = [k for k, _ in alive]
    result.duration_ms = int((time.time() - t0) * 1000)
    return result
