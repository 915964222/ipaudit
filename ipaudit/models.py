"""共享数据结构：Observation（采集产物）与 Report（最终输出）。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PortFinding:
    port: int
    kind: str            # proxy-port / http-proxy / socks5 / transparent-proxy
    detail: str = ""


@dataclass
class Observation:
    """一个 IP 的全部采集产物。某项查不到就置 unavailable_*，绝不用空值冒充干净。"""
    ip: str
    scanned_at: str

    # U1 ASN / U5 地理（ip-api 一次拿全）
    asn: int | None = None
    asn_org: str = ""
    asn_type: str = ""                 # isp / hosting / business / education / ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    timezone: str = ""
    isp_name: str = ""
    geo_unavailable: str = ""

    # U2 反向解析
    rdns: str | None = None            # None = 查不到（可能是无 rDNS 或查询失败）
    rdns_error: str = ""
    rdns_pattern_hits: list[str] = field(default_factory=list)

    # U3 黑名单
    dnsbl: list = field(default_factory=list)     # list[dnsbl.DnsblResult]
    abuse_score: int | None = None
    abuse_unavailable: str = ""
    fraud_score: int | None = None
    fraud_unavailable: str = ""
    scamalytics_score: int | None = None
    scamalytics_unavailable: str = ""

    # U4 端口指纹（--deep 才启用）
    ports_scanned: bool = False
    port_findings: list[PortFinding] = field(default_factory=list)
    port_error: str = ""

    # 证据 C：/24 抽样（--deep 才执行）
    subnet_sample: dict = field(default_factory=dict)   # {total, resolved, homogeneous, sample[]}

    # 证据 D：第三方类型标注
    thirdparty: dict = field(default_factory=dict)      # {is_datacenter, is_vpn, ...}

    # 探针（环境维度，由 probe 会话回传后合并）
    probe: dict | None = None

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["dnsbl"] = [r.__dict__ for r in self.dnsbl]
        d["port_findings"] = [p.__dict__ for p in self.port_findings]
        return d


@dataclass
class Evidence:
    layer: str           # identity / reputation / exposure / consistency
    item: str
    verdict: str
    value: str
    penalty: int
    source: str
    confidence: str = "high"


@dataclass
class Report:
    ip: str
    scanned_at: str
    score: int
    grade: str                                   # clean / usable / risky / dead
    residence: str                               # resident / ambiguous / hosting
    evidence: list[Evidence] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    conclusion: str = ""
    duration_ms: int = 0
    probe_grade: str | None = None               # 环境维度单独评级
    fix_hints: list[str] = field(default_factory=list)   # 精确到配置项的修复指引
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["evidence"] = [e.__dict__ for e in self.evidence]
        return d


GRADE_ORDER = {"clean": 0, "usable": 1, "risky": 2, "dead": 3}
