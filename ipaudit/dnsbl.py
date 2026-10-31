"""自实现 DNS 报文查询与 DNSBL 聚合。

不依赖 dnspython：DNSBL 只需要 A / PTR 两种查询，标准库 socket 足够。
关键坑（设计方案 3.3）：
- Spamhaus 拒绝来自公共解析器的查询，返回 127.255.255.252/254/255，
  这是“查询无效”不是命中，把它当命中会产生大量假阳性。
- hostkarma 的 127.0.0.1 是白名单语义（信任），不是黑名单命中。
- zen 的 127.0.0.10/11 是 PBL（动态段），对“住宅判定”反而是佐证而非滥用。
"""

from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# ---------------------------------------------------------------- 名单定义

@dataclass
class Zone:
    key: str          # 短名
    zone: str         # DNSBL 域名
    severity: int     # 命中扣分权重（评分层取最严重，不叠加）
    note: str = ""

ZONES: list[Zone] = [
    Zone("spamhaus_zen", "zen.spamhaus.org", 30,
         "SBL/XBL/PBL；.4-.7 被劫持主机，.10/.11 动态段"),
    Zone("spamcop", "bl.spamcop.net", 20, "举报制，反应快"),
    Zone("barracuda", "b.barracudacentral.org", 25, "需注册免费账号，无 key 时 unavailable"),
    Zone("sorbs", "dnsbl.sorbs.net", 15, "覆盖广，误报偏高"),
    Zone("uceprotect1", "dnsbl-1.uceprotect.net", 15, "严格，易误报"),
    Zone("psbl", "psbl.surriel.com", 10, "被动收集"),
    Zone("s5h", "all.s5h.net", 10, ""),
    Zone("gbudb", "truncate.gbudb.net", 10, ""),
    Zone("hostkarma", "hostkarma.junkemailfilter.com", 10, "返回码含白名单语义"),
    Zone("justspam", "dnsbl.justspam.org", 10, ""),
    Zone("spamrats", "spam.spamrats.com", 10, ""),
    Zone("nordspam", "dnsbl.nordspam.com", 5, ""),
]

SEVERITY: dict[str, int] = {z.key: z.severity for z in ZONES}

# Spamhaus 对公共解析器返回的“查询无效”码（不可当命中）
SPAMHAUS_INVALID = {
    ipaddress.ip_address("127.255.255.252"),
    ipaddress.ip_address("127.255.255.254"),
    ipaddress.ip_address("127.255.255.255"),
}
# hostkarma 白名单语义
HOSTKARMA_WHITELIST = ipaddress.ip_address("127.0.0.1")
# hostkarma 黄名单（中性，非命中）：127.0.0.2；真正的黑名单是 .4/.5
HOSTKARMA_YELLOW = ipaddress.ip_address("127.0.0.2")
# zen PBL：动态/拨号段被收录，属于“住宅特征”佐证，不是滥用
ZEN_PBL = {ipaddress.ip_address("127.0.0.10"), ipaddress.ip_address("127.0.0.11")}

# ---------------------------------------------------------------- DNS 报文

# 随机源端口 + 随机事务 ID 是防 DNS 缓存投毒的基本功，id 由调用方传入
_QTYPE_A = 1
_QTYPE_PTR = 12
_CLASS_IN = 1


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        if not 0 < len(raw) < 64:
            raise ValueError(f"非法 DNS 标签: {label!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _skip_name(pkt: bytes, off: int) -> int:
    """跳过一个可能带压缩指针的域名，返回结束偏移。"""
    while True:
        ln = pkt[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:          # 压缩指针，2 字节
            return off + 2
        off += 1 + ln


def _read_name(pkt: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None             # 指针跳走后，报文名真正的结束位置
    while True:
        ln = pkt[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", pkt[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            off = ptr
            continue
        labels.append(pkt[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if end is not None else off)


def _build_query(name: str, qtype: int, qid: int) -> bytes:
    # RD=1：允许解析器递归
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, _CLASS_IN)


def _parse_answer_a(pkt: bytes, qid: int) -> list[ipaddress.IPv4Address]:
    if len(pkt) < 12:
        raise ValueError("响应过短")
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", pkt[:12])
    if rid != qid:
        raise ValueError("事务 ID 不匹配")
    rcode = flags & 0x0F
    if rcode == 3:                      # NXDOMAIN：DNSBL 的标准“未命中”
        return []
    if rcode != 0:
        raise ValueError(f"DNS rcode={rcode}")
    off = 12
    for _ in range(qd):
        off = _skip_name(pkt, off) + 4
    out: list[ipaddress.IPv4Address] = []
    for _ in range(an):
        off = _skip_name(pkt, off)
        if off + 10 > len(pkt):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", pkt[off:off + 10])
        off += 10
        rdata = pkt[off:off + rdlen]
        off += rdlen
        if rtype == _QTYPE_A and rdlen == 4:
            out.append(ipaddress.IPv4Address(rdata))
    return out


def _parse_answer_ptr(pkt: bytes, qid: int) -> str | None:
    if len(pkt) < 12:
        raise ValueError("响应过短")
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", pkt[:12])
    if rid != qid:
        raise ValueError("事务 ID 不匹配")
    if flags & 0x0F != 0:
        return None
    off = 12
    for _ in range(qd):
        off = _skip_name(pkt, off) + 4
    for _ in range(an):
        off = _skip_name(pkt, off)
        if off + 10 > len(pkt):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", pkt[off:off + 10])
        off += 10
        rdata = pkt[off:off + rdlen]
        off += rdlen
        if rtype == _QTYPE_PTR:
            name, _ = _read_name(pkt, off - rdlen)
            return name.rstrip(".")
    return None


def _resolve(name: str, qtype: int, timeout: float, resolver: str | None) -> list[str] | str:
    """向解析器发一次 UDP 查询。返回 A 记录列表 / PTR 名；解析失败抛 OSError。"""
    server = resolver or _system_resolver()
    qid = random.SystemRandom().randint(1, 0xFFFF)
    sport = random.SystemRandom().randint(20000, 60000)
    pkt = _build_query(name, qtype, qid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", sport))
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    if qtype == _QTYPE_PTR:
        ptr = _parse_answer_ptr(data, qid)
        return [ptr] if ptr else []
    return [str(a) for a in _parse_answer_a(data, qid)]


def _system_resolver() -> str:
    """Windows 上没有 /etc/resolv.conf，从注册表拿当前接口的 DNS 服务器。"""
    if os.name != "nt":
        with open("/etc/resolv.conf", encoding="ascii") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    return line.split()[1]
        raise OSError("找不到系统 DNS")
    import winreg
    key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
        i = 0
        candidates: list[str] = []
        while True:
            try:
                sub = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break
            try:
                with winreg.OpenKey(root, sub) as k:
                    for value_name in ("DhcpNameServer", "NameServer"):
                        try:
                            raw, _ = winreg.QueryValueEx(k, value_name)
                        except OSError:
                            continue
                        for ns in str(raw).replace(",", " ").split():
                            if ns and not ns.startswith("127."):
                                candidates.append(ns)
            except OSError:
                continue
    if not candidates:
        raise OSError("注册表里找不到 DNS 服务器")
    return candidates[0]


# ---------------------------------------------------------------- 对外接口

def resolve_a(name: str, timeout: float = 3.0, resolver: str | None = None) -> list[str]:
    return _resolve(name, _QTYPE_A, timeout, resolver)


def resolve_ptr(ip: str, timeout: float = 3.0, resolver: str | None = None) -> str | None:
    rev = ipaddress.ip_address(ip).reverse_pointer
    out = _resolve(rev + ".in-addr.arpa", _QTYPE_PTR, timeout, resolver)
    return out[0] if out else None


@dataclass
class DnsblResult:
    zone: str
    status: str = "clean"              # clean / hit / unavailable
    codes: list[str] = field(default_factory=list)
    severity: int = 0
    note: str = ""                     # 命中语义说明（如 PBL / 白名单）


def query_dnsbl(ip: str, z: Zone, resolver: str | None = None,
                timeout: float = 5.0) -> DnsblResult:
    """查单个名单。三态返回：clean / hit / unavailable，绝不把查不到当干净。"""
    rev = ipaddress.ip_address(ip).reverse_pointer
    name = f"{rev}.{z.zone}"
    try:
        addrs = _resolve(name, _QTYPE_A, timeout, resolver)
    except (OSError, ValueError) as e:
        return DnsblResult(z.key, "unavailable", note=str(e))
    if not addrs:
        return DnsblResult(z.key, "clean")
    codes = [ipaddress.ip_address(a) for a in addrs]
    if z.zone == "zen.spamhaus.org" and any(c in SPAMHAUS_INVALID for c in codes):
        return DnsblResult(z.key, "unavailable",
                           note="公共解析器被 Spamhaus 拒绝，需自建解析器")
    # hostkarma：127.0.0.1 白名单、127.0.0.2 黄名单（中性），只有 .4/.5 是黑名单
    if z.zone == "hostkarma.junkemailfilter.com":
        if HOSTKARMA_WHITELIST in codes:
            return DnsblResult(z.key, "clean", note="white 命中（信任名单）")
        hit = [c for c in codes
               if c not in SPAMHAUS_INVALID and c != HOSTKARMA_YELLOW]
        if not hit:
            if HOSTKARMA_YELLOW in codes:
                return DnsblResult(z.key, "clean",
                                   [str(HOSTKARMA_YELLOW)], note="yellow（中性，不计命中）")
            return DnsblResult(z.key, "clean")
        return DnsblResult(z.key, "hit", [str(c) for c in hit], z.severity)
    if z.zone == "zen.spamhaus.org":
        pbl = [c for c in codes if c in ZEN_PBL]
        abuse = [c for c in codes if c not in ZEN_PBL and c not in SPAMHAUS_INVALID]
        if abuse:
            return DnsblResult(z.key, "hit", [str(c) for c in abuse], z.severity)
        if pbl:
            # 动态段收录：不算滥用命中，但对住宅判定是佐证
            return DnsblResult(z.key, "clean",
                               [str(c) for c in pbl], note="PBL 动态段收录（佐证住宅特征）")
    return DnsblResult(z.key, "hit", [str(c) for c in codes if int(c) >> 24 == 127],
                       z.severity)


def query_all_dnsbl(ip: str, resolver: str | None = None,
                    timeout: float = 5.0,
                    zones: list[Zone] | None = None,
                    workers: int = 12) -> list[DnsblResult]:
    """12 个名单并发查询。任一失败不影响其他名单。"""
    zones = zones or ZONES
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(query_dnsbl, ip, z, resolver, timeout) for z in zones]
        return [f.result() for f in futs]


def check_resolver_health(resolver: str | None = None) -> dict:
    """部署自检：解析器能不能正常走 Spamhaus。

    返回 {resolver, status, detail}：
      ok          → zen 正常应答（clean 或 hit 都算通）
      refused     → 拿到 127.255.255.x（公共解析器被拒），需自建 unbound
      unreachable → 解析器无响应
    """
    z = next(z for z in ZONES if z.key == "spamhaus_zen")
    r = query_dnsbl("8.8.8.8", z, resolver=resolver, timeout=5.0)
    if r.status == "unavailable":
        if "公共解析器" in r.note:
            return {"resolver": resolver or "system", "status": "refused",
                    "detail": r.note}
        return {"resolver": resolver or "system", "status": "unreachable",
                "detail": r.note}
    # clean 或 hit 都说明解析路径正常（8.8.8.8 在 zen 上常为 clean/NXDOMAIN）
    return {"resolver": resolver or "system", "status": "ok",
            "detail": f"zen 应答正常（status={r.status}）"}


def check_open_recursion(listen_ip: str) -> dict:
    """验证解析器没有开放递归（防放大器核心检查）。

    对 listen_ip 发一个带 RD=1 的递归查询，期望 REFUSED / 超时；
    拿到答案说明 ACL 没配好，正在当开放解析器。
    """
    try:
        out = _resolve("ipaudit-recursion-test.example.com", _QTYPE_A, 3.0, listen_ip)
        # NXDOMAIN 也会返回 []——区分不了 REFUSED，所以再查一个肯定有答案的
        out2 = _resolve("whoami.akamai.net", _QTYPE_A, 3.0, listen_ip)
        if out2:
            return {"listen": listen_ip, "open_recursion": True,
                    "detail": "解析器返回了递归答案 → 开放递归，立即修 access-control"}
        return {"listen": listen_ip, "open_recursion": False,
                "detail": "拒绝递归（测试域 NXDOMAIN）"}
    except OSError as e:
        return {"listen": listen_ip, "open_recursion": False,
                "detail": f"无响应/拒绝（{e}）"}
