"""采集层 U1–U6。原则（设计方案 3.1）：全部并行、各自独立超时、任一失败不阻断。
失败项标 unavailable 并写明原因，绝不把“查不到”当“没问题”。"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .dnsbl import query_all_dnsbl, resolve_ptr
from .models import Observation, PortFinding

HTTP_TIMEOUT = 5.0
UA = "ipaudit/0.1 (+local diagnostic tool)"
_HEADERS = {"User-Agent": UA}

# 只探测、不穿透：确认是代理端口就停，不建立数据通道
PROXY_PORTS = [1080, 3128, 8080, 8118, 8888, 9050, 10808]


def _http_json(url: str, timeout: float = HTTP_TIMEOUT, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers={**_HEADERS, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _http_get(url: str, timeout: float = HTTP_TIMEOUT) -> str:
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


# ---------------------------------------------------------------- U1+U5 地理

def fetch_geo(ip: str) -> dict:
    """ip-api.com 免费版 45 req/min，一次返回地理 + ASN + proxy/hosting 标注。"""
    fields = "status,message,country,countryCode,city,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
    try:
        j = _http_json(f"http://ip-api.com/json/{ip}?fields={fields}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"unavailable": f"ip-api 请求失败: {e}"}
    if j.get("status") != "success":
        return {"unavailable": f"ip-api 返回失败: {j.get('message', '?')}"}
    asn = 0
    org = j.get("as", "")
    # as 形如 "AS15169 Google LLC"
    if org.startswith("AS"):
        head = org.split(" ", 1)
        try:
            asn = int(head[0][2:])
            org = head[1] if len(head) > 1 else ""
        except ValueError:
            pass
    return {
        "asn": asn or None,
        "asn_org": org or j.get("asname", ""),
        "isp_name": j.get("isp", ""),
        "country": j.get("country", ""),
        "country_code": j.get("countryCode", ""),
        "city": j.get("city", ""),
        "timezone": j.get("timezone", ""),
        "rdns_hint": j.get("reverse", "") or None,
        "flag_proxy": bool(j.get("proxy")),
        "flag_hosting": bool(j.get("hosting")),
        "flag_mobile": bool(j.get("mobile")),
    }


# ---------------------------------------------------------------- U2 反向解析

RDNS_RESIDENTIAL = [
    "dynamic", "dsl", "ppp", "pool", "dhcp", "res.", "cust.", "broadband",
    "cable", "hsd", "lightspeed", "fios", "sbcglobal", "comcast", "centurylink",
    "fibertel", "telefonica", "orange", "wanadoo", "kpn", "telenet",
]
RDNS_HOSTING = [
    "ec2", "compute", "cloud", "vps", "dedicated", "server", "host",
    "linode", "vultr", "ovh", "hetzner", "digitalocean", "contabo", "scaleway",
]


def fetch_rdns(ip: str, resolver: str | None) -> dict:
    try:
        name = resolve_ptr(ip, timeout=3.0, resolver=resolver)
    except OSError as e:
        return {"rdns": None, "error": str(e)}
    hits: list[str] = []
    low = (name or "").lower()
    for kw in RDNS_RESIDENTIAL:
        if kw in low:
            hits.append(f"residential:{kw}")
    for kw in RDNS_HOSTING:
        if kw in low:
            hits.append(f"hosting:{kw}")
    return {"rdns": name, "error": "", "pattern_hits": hits}


# ---------------------------------------------------------------- U3 信誉库

def fetch_abuseipdb(ip: str) -> dict:
    """免费额度 1000/天，需要 key。没有 key 就诚实标 unavailable。"""
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"score": None, "unavailable": "未配置 ABUSEIPDB_API_KEY"}
    req = urllib.request.Request(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={**_HEADERS, "Key": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return {"score": int(data["data"]["abuseConfidenceScore"])}
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            OSError, KeyError, ValueError) as e:
        return {"score": None, "unavailable": f"AbuseIPDB 请求失败: {e}"}


def fetch_ipqs(ip: str) -> dict:
    """免费 5000/月，需要 key。"""
    key = os.environ.get("IPQS_API_KEY")
    if not key:
        return {"score": None, "unavailable": "未配置 IPQS_API_KEY"}
    try:
        j = _http_json(f"https://www.ipqualityscore.com/api/json/ip/{key}/{ip}?strictness=0")
        if not j.get("success", False):
            return {"score": None, "unavailable": f"IPQS 返回失败: {j.get('message', '?')}"}
        return {"score": int(j.get("fraud_score", 0))}
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            OSError, ValueError) as e:
        return {"score": None, "unavailable": f"IPQS 请求失败: {e}"}


def fetch_scamalytics(ip: str) -> dict:
    """无官方免费 API，抓公开页面里的 Fraud Score。页面改版则标 unavailable。"""
    try:
        html = _http_get(f"https://scamalytics.com/ip/{ip}", timeout=6.0)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        return {"score": None, "unavailable": f"Scamalytics 请求失败: {e}"}
    idx = html.find("Fraud Score:")
    if idx < 0:
        idx = html.find("Fraud Score</div>")
    if idx < 0:
        return {"score": None, "unavailable": "页面结构变化，取不到分数"}
    seg = html[idx:idx + 400]
    num = ""
    for ch in seg:
        if ch.isdigit():
            num += ch
        elif num:
            break
    if not num:
        return {"score": None, "unavailable": "取不到分数"}
    return {"score": int(num)}


def fetch_ipapi_is(ip: str) -> dict:
    """证据 D：ipapi.is 免费接口，返回 is_datacenter / is_vpn / asn.type 等。"""
    try:
        j = _http_json(f"https://api.ipapi.is/?q={ip}")
        asn = j.get("asn") if isinstance(j.get("asn"), dict) else {}
        company = j.get("company") if isinstance(j.get("company"), dict) else {}
        return {
            "is_datacenter": j.get("is_datacenter"),
            "is_vpn": j.get("is_vpn"),
            "is_proxy": j.get("is_proxy"),
            "is_abuser": j.get("is_abuser"),
            "is_crawler": j.get("is_crawler"),
            "asn_type": asn.get("type", "") or "",
            "company_type": company.get("type", "") or "",
        }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            OSError, ValueError) as e:
        return {"unavailable": f"ipapi.is 请求失败: {e}"}


# ---------------------------------------------------------------- U4 端口指纹

def probe_ports(ip: str, timeout: float = 1.2) -> list[PortFinding]:
    """TCP connect 探常见代理端口 + HTTP 代理特征 + SOCKS5 握手。
    铁律：只探测，不穿透——握手确认即断开。"""
    findings: list[PortFinding] = []
    open_ports: list[int] = []
    for port in PROXY_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                pass
            open_ports.append(port)
            findings.append(PortFinding(port, "proxy-port", "常见代理端口开放"))
        except OSError:
            continue
    for port in open_ports:
        # HTTP 代理特征：发绝对 URI 的 GET，看是否当代理用
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"GET http://ip-api.com/line/?fields=query HTTP/1.1\r\n"
                          b"Host: ip-api.com\r\nConnection: close\r\n\r\n")
                if s.recv(256)[:4] == b"HTTP":
                    findings.append(PortFinding(port, "http-proxy", "响应 HTTP 代理请求"))
        except OSError:
            pass
        # SOCKS5 握手：\x05\x01\x00 → 回 \x05\x00 即无认证 SOCKS
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"\x05\x01\x00")
                data = s.recv(8)
                if len(data) >= 2 and data[0] == 5 and data[1] == 0:
                    findings.append(PortFinding(port, "socks5", "SOCKS5 握手成功"))
        except OSError:
            pass
    return findings


# ---------------------------------------------------------------- 证据 C /24 抽样

def sample_subnet(ip: str, resolver: str | None, n: int = 16) -> dict:
    """取 /24 抽样 16 个地址查 rDNS：全部存在且命名同构 → 倾向机房。"""
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    hosts = list(net.hosts())
    if len(hosts) <= 1:
        return {"total": 0, "resolved": 0, "homogeneous": False, "sample": []}
    step = max(1, len(hosts) // n)
    picks = [str(h) for h in hosts[::step]][:n]
    if ip not in picks:
        picks[0] = ip

    def one(addr: str) -> str | None:
        try:
            return resolve_ptr(addr, timeout=2.0, resolver=resolver)
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        names = list(ex.map(one, picks))
    resolved = [x for x in names if x]

    # 同构判定：数字替换成 * 后骨架是否一致（如 ec2-*-*.compute-1.amazonaws.com）
    def skeleton(name: str) -> str:
        out = []
        for label in name.lower().split("."):
            out.append("".join("*" if ch.isdigit() else ch for ch in label))
        return ".".join(out)

    skels = {skeleton(x) for x in resolved}
    return {
        "total": len(picks),
        "resolved": len(resolved),
        "homogeneous": len(resolved) >= 12 and len(skels) <= 3,
        "sample": resolved[:8],
    }


# ---------------------------------------------------------------- 总调度

def collect(ip: str, deep: bool = False, resolver: str | None = None) -> Observation:
    """六单元并行采集，组装 Observation。任一单元失败不阻断其余。"""
    obs = Observation(ip=ip, scanned_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    jobs: dict[str, callable] = {
        "geo": lambda: fetch_geo(ip),
        "rdns": lambda: fetch_rdns(ip, resolver),
        "dnsbl": lambda: query_all_dnsbl(ip, resolver=resolver),
        "abuse": lambda: fetch_abuseipdb(ip),
        "fraud": lambda: fetch_ipqs(ip),
        "scam": lambda: fetch_scamalytics(ip),
        "thirdparty": lambda: fetch_ipapi_is(ip),
    }
    if deep:
        def do_ports():
            try:
                return {"findings": probe_ports(ip), "error": ""}
            except OSError as e:
                return {"findings": [], "error": f"端口探测失败: {e}"}

        jobs["ports"] = do_ports
        jobs["subnet"] = lambda: sample_subnet(ip, resolver)

    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {k: ex.submit(fn) for k, fn in jobs.items()}
        results = {k: f.result() for k, f in futs.items()}

    geo = results["geo"]
    if "unavailable" in geo:
        obs.geo_unavailable = geo["unavailable"]
    else:
        obs.asn = geo.get("asn")
        obs.asn_org = geo.get("asn_org", "")
        obs.isp_name = geo.get("isp_name", "")
        obs.country = geo.get("country", "")
        obs.country_code = geo.get("country_code", "")
        obs.city = geo.get("city", "")
        obs.timezone = geo.get("timezone", "")
        obs.thirdparty["ip_api"] = {
            "proxy": geo.get("flag_proxy"), "hosting": geo.get("flag_hosting"),
            "mobile": geo.get("flag_mobile")}
        if geo.get("rdns_hint"):
            obs.rdns = geo["rdns_hint"]

    r = results["rdns"]
    if r.get("rdns"):
        if not obs.rdns:
            obs.rdns = r["rdns"]
        if r.get("pattern_hits"):
            obs.rdns_pattern_hits = r["pattern_hits"]
    elif r.get("error"):
        obs.rdns_error = r["error"]

    obs.dnsbl = results["dnsbl"]
    obs.abuse_score = results["abuse"].get("score")
    obs.abuse_unavailable = results["abuse"].get("unavailable", "")
    obs.fraud_score = results["fraud"].get("score")
    obs.fraud_unavailable = results["fraud"].get("unavailable", "")
    obs.scamalytics_score = results["scam"].get("score")
    obs.scamalytics_unavailable = results["scam"].get("unavailable", "")
    tp = results["thirdparty"]
    obs.thirdparty["ipapi_is"] = tp
    if "unavailable" not in tp:
        if tp.get("asn_type") and not obs.asn_type:
            obs.asn_type = tp["asn_type"]

    if deep:
        obs.ports_scanned = True
        obs.port_findings = results["ports"]["findings"]
        obs.port_error = results["ports"]["error"]
        obs.subnet_sample = results["subnet"]

    return obs
