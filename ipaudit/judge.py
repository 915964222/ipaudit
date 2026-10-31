"""判定层（四路证据投票）+ 评分层（扣分制）+ 结论生成。

四路证据（设计方案 3.2）：
  A ASN 分类表     B rDNS 命名模式     C /24 网段粒度     D 第三方类型标注
输出三分类：resident(>=55) / ambiguous(25-54) / hosting(<25)。
ambiguous 必须明确说“无法确证”，不许四舍五入成“通过”。
"""

from __future__ import annotations

from .asn_data import classify_asn
from .collector import RDNS_HOSTING, RDNS_RESIDENTIAL
from .models import Evidence, Observation, Report

# ---------------------------------------------------------------- 住宅判定

R_MAX = 100.0


def _residence_evidence(obs: Observation) -> list[tuple[str, float, str]]:
    """返回 [(证据名, 得分贡献, 说明)]，总分 0..100。"""
    ev: list[tuple[str, float, str]] = []
    hosting_signals = 0                # 强机房信号计数，用于证据冲突消解

    # 证据 A：ASN 类型表
    at = classify_asn(obs.asn)
    if not at and obs.asn_type:
        at = obs.asn_type            # ipapi.is 的 asn.type 兜底
    if at == "isp":
        ev.append(("A_asn_table", 45, f"ASN {obs.asn} 在人工表中标为 ISP"))
    elif at == "hosting":
        ev.append(("A_asn_table", 0, f"ASN {obs.asn} 在人工表中标为机房"))
        hosting_signals += 1
    elif at in ("business", "education"):
        ev.append(("A_asn_table", 15, f"ASN {obs.asn} 为 {at}，中性偏可疑"))
    else:
        ev.append(("A_asn_table", 12, f"ASN {obs.asn} 未知，需其他证据补强"))

    # 证据 B：rDNS 命名模式
    res_hits = [h.split(":", 1)[1] for h in obs.rdns_pattern_hits
                if h.startswith("residential:")]
    host_hits = [h.split(":", 1)[1] for h in obs.rdns_pattern_hits
                 if h.startswith("hosting:")]
    if res_hits:
        ev.append(("B_rdns", 35, f"rDNS 含住宅特征词: {','.join(res_hits[:4])}"))
    elif host_hits:
        ev.append(("B_rdns", 0, f"rDNS 含机房特征词: {','.join(host_hits[:4])}"))
        hosting_signals += 1
    elif obs.rdns:
        # rDNS 存在但无特征词。注意：基建 IP（DNS/CDN）的 rDNS 必然与 org 同源，
        # 「同源」本身不构成住宅证据——只有配合 ISP 型 ASN 才加分，否则中性。
        org_word = (obs.asn_org or obs.isp_name or "").split()[0].lower() \
            if (obs.asn_org or obs.isp_name) else ""
        same_org = org_word and org_word in obs.rdns.lower()
        if at == "isp":
            ev.append(("B_rdns", 20 if same_org else 12,
                       f"rDNS {'与 ' + org_word + ' 同源' if same_org else '无特征词'}，ISP ASN 佐证分配: {obs.rdns}"))
        else:
            ev.append(("B_rdns", 5,
                       f"rDNS 与 {'org 同源但 ASN 非住宅型' if same_org else 'ASN 无关联（转手常见）'}: {obs.rdns}"))
    else:
        ev.append(("B_rdns", 10, f"无 rDNS（{obs.rdns_error or '未设置'}），不能单独定罪"))

    # 证据 C：/24 粒度抽样（deep 模式才有）
    sub = obs.subnet_sample or {}
    if sub.get("total"):
        if sub["homogeneous"]:
            ev.append(("C_subnet", 0, f"/24 抽样 {sub['resolved']}/{sub['total']} 同构，倾向机房整段持有"))
            hosting_signals += 1
        elif sub["resolved"] <= 4:
            ev.append(("C_subnet", 30, f"/24 抽样仅 {sub['resolved']}/{sub['total']} 有 rDNS，动态分配特征"))
        else:
            ev.append(("C_subnet", 15, f"/24 抽样 {sub['resolved']}/{sub['total']} 命名各异，混合分配"))
    else:
        ev.append(("C_subnet", 0, "未执行 /24 抽样（--deep 开启）"))

    # 证据 D：第三方标注投票
    tp_is = obs.thirdparty.get("ipapi_is") or {}
    ip_api = obs.thirdparty.get("ip_api") or {}
    votes_res, votes_host = 0, 0
    if tp_is.get("asn_type") == "isp":
        votes_res += 1
    if tp_is.get("is_datacenter") is False and tp_is.get("asn_type") == "isp":
        votes_res += 1
    if tp_is.get("is_datacenter"):
        votes_host += 1
    if ip_api.get("hosting"):
        votes_host += 1
    if votes_res and not votes_host:
        ev.append(("D_thirdparty", 20, "第三方一致标注 ISP/非机房"))
    elif votes_host and not votes_res:
        ev.append(("D_thirdparty", 0, f"第三方标注机房（datacenter={tp_is.get('is_datacenter')}, hosting={ip_api.get('hosting')}）"))
        hosting_signals += 1
    else:
        ev.append(("D_thirdparty", 10, "第三方标注分歧或缺失"))

    return ev, hosting_signals


def judge_residence(obs: Observation) -> tuple[str, int, list[tuple[str, float, str]]]:
    ev, hosting_signals = _residence_evidence(obs)
    score = min(R_MAX, sum(s for _, s, _ in ev))
    # 冲突消解：有强机房信号时，其他证据再好也不能判 resident——
    # 1 路机房证据压到存疑，≥2 路直接机房。防止「Comcast ASN + EC2 rDNS」这类
    # 矛盾组合被多数票洗成真住宅。
    if hosting_signals >= 2:
        score = min(score, 20)
    elif hosting_signals == 1:
        score = min(score, 54)
    if score >= 55:
        return "resident", int(score), ev
    if score >= 25:
        return "ambiguous", int(score), ev
    return "hosting", int(score), ev


# ---------------------------------------------------------------- 评分

def score_report(obs: Observation) -> Report:
    """扣分制：从 100 起扣。声誉层取最严重，不叠加。"""
    s = 100
    detail: list[str] = []
    evidence: list[Evidence] = []
    unavailable: list[str] = list(obs.unavailable_list()) if hasattr(obs, "unavailable_list") else []

    def take(n: int):
        nonlocal s
        s -= n

    # ---- 身份层 ----
    residence, res_score, res_ev = judge_residence(obs)
    if classify_asn(obs.asn) == "hosting":
        take(40)
        detail.append("ASN 属机房")
        evidence.append(Evidence("identity", "asn_type", "hosting",
                                 f"AS{obs.asn} {obs.asn_org}", -40, "asn_type.json", "high"))
    elif classify_asn(obs.asn) == "" and obs.asn:
        evidence.append(Evidence("identity", "asn_type", "unknown",
                                 f"AS{obs.asn} {obs.asn_org}", 0, "asn_type.json", "low"))
    if residence == "hosting":
        take(25)
        detail.append("住宅特征判定为机房伪装")
        evidence.append(Evidence("identity", "residence", "hosting",
                                 f"四路证据得分 {res_score}/100", -25, "四路投票", "medium"))
    elif residence == "ambiguous":
        take(12)
        detail.append("住宅特征存疑，无法确证")
        evidence.append(Evidence("identity", "residence", "ambiguous",
                                 f"四路证据得分 {res_score}/100", -12, "四路投票", "low"))

    # ---- 声誉层（取最严重，不叠加）----
    hits = [r for r in obs.dnsbl if r.status == "hit"]
    pbl_notes = [r for r in obs.dnsbl if r.note and "PBL" in r.note]
    if hits:
        worst = max(hits, key=lambda r: r.severity)
        take(worst.severity)
        detail.append(f"黑名单命中: {worst.zone}({worst.codes[0]})")
        evidence.append(Evidence(
            "reputation", "dnsbl", "hit",
            f"{worst.zone} → {','.join(worst.codes)}（另 {len(hits)-1} 个名单命中）"
            if len(hits) > 1 else f"{worst.zone} → {','.join(worst.codes)}",
            -worst.severity, "DNSBL 聚合", "high"))
    elif pbl_notes:
        evidence.append(Evidence("reputation", "dnsbl_pbl", "pbl",
                                 "Spamhaus PBL：动态/拨号段收录（佐证住宅特征，非滥用）",
                                 0, "zen.spamhaus.org", "high"))
    unav_zones = [r.zone for r in obs.dnsbl if r.status == "unavailable"]
    if unav_zones:
        unavailable.append(f"DNSBL 查询无效: {','.join(unav_zones)}")

    if obs.abuse_score is not None:
        if obs.abuse_score >= 75:
            take(25); detail.append(f"AbuseIPDB 滥用分 {obs.abuse_score}")
        elif obs.abuse_score >= 40:
            take(12); detail.append(f"AbuseIPDB 滥用分 {obs.abuse_score}")
        evidence.append(Evidence("reputation", "abuseipdb", "scored",
                                 f"abuseConfidenceScore={obs.abuse_score}",
                                 -25 if obs.abuse_score >= 75 else -12 if obs.abuse_score >= 40 else 0,
                                 "AbuseIPDB", "high"))
    elif obs.abuse_unavailable:
        unavailable.append(f"AbuseIPDB: {obs.abuse_unavailable}")

    if obs.fraud_score is not None:
        if obs.fraud_score >= 75:
            take(20); detail.append(f"IPQS 欺诈分 {obs.fraud_score}")
        elif obs.fraud_score >= 50:
            take(10); detail.append(f"IPQS 欺诈分 {obs.fraud_score}")
        evidence.append(Evidence("reputation", "ipqs", "scored",
                                 f"fraud_score={obs.fraud_score}",
                                 -20 if obs.fraud_score >= 75 else -10 if obs.fraud_score >= 50 else 0,
                                 "IPQualityScore", "high"))
    elif obs.fraud_unavailable:
        unavailable.append(f"IPQS: {obs.fraud_unavailable}")

    if obs.scamalytics_score is not None:
        if obs.scamalytics_score >= 75:
            take(15); detail.append(f"Scamalytics 欺诈分 {obs.scamalytics_score}")
        elif obs.scamalytics_score >= 50:
            take(8)
        evidence.append(Evidence("reputation", "scamalytics", "scored",
                                 f"Fraud Score={obs.scamalytics_score}",
                                 -15 if obs.scamalytics_score >= 75 else -8 if obs.scamalytics_score >= 50 else 0,
                                 "Scamalytics", "medium"))
    elif obs.scamalytics_unavailable:
        unavailable.append(f"Scamalytics: {obs.scamalytics_unavailable}")

    # ---- 暴露层 ----
    if obs.port_findings:
        confirmed = [p for p in obs.port_findings if p.kind in ("http-proxy", "socks5")]
        if confirmed:
            take(25)
            detail.append(f"确认开放代理: {','.join(str(p.port) for p in confirmed)}")
            evidence.append(Evidence("exposure", "proxy", "confirmed",
                                     f"端口 {','.join(str(p.port) for p in confirmed)} 代理握手成功",
                                     -25, "主动探测", "high"))
        else:
            opened = sorted({p.port for p in obs.port_findings})
            take(20)
            detail.append(f"常见代理端口开放: {','.join(map(str, opened))}")
            evidence.append(Evidence("exposure", "proxy-port", "open",
                                     f"端口 {','.join(map(str, opened))} 开放（未确认为代理）",
                                     -20, "主动探测", "medium"))
    if obs.ports_scanned and not obs.port_findings and not obs.port_error:
        evidence.append(Evidence("exposure", "proxy-port", "closed",
                                 "7 个常见代理端口全部关闭", 0, "主动探测", "high"))

    probe = obs.probe or {}
    # WebRTC 四态（设计方案 3.5）：只有 leak 扣分；disabled 不扣分但记环境特征；
    # blocked/unavailable 必须显式列出，不能当通过
    w_state = webrtc_state_of(probe)
    if w_state == "leak":
        take(25); detail.append("WebRTC 泄漏真实 IP")
        evidence.append(Evidence("exposure", "webrtc", "leak",
                                 f"STUN 采集到: {', '.join(probe.get('webrtc_ips', [])[:3])}",
                                 -25, "客户端探针", "high"))
    elif w_state == "restricted":
        evidence.append(Evidence("exposure", "webrtc", "restricted",
                                 "仅 srflx（出口 IP），无 host candidate——合规", 0,
                                 "客户端探针", "high"))
    elif w_state == "disabled":
        evidence.append(Evidence("exposure", "webrtc", "disabled",
                                 "零 candidate（已禁用）——不扣分，但记为环境特征："
                                 "与「从未配置」可区分，某些平台视为异常指纹", 0,
                                 "客户端探针", "high"))
        detail.append("WebRTC 已禁用（环境特征，非扣分项）")
    else:
        evidence.append(Evidence("exposure", "webrtc", "unavailable",
                                 "探针被拦截（CSP/扩展/不支持），本次未测到", 0,
                                 "客户端探针", "low"))
        unavailable.append("WebRTC 检测: 探针被拦截，不能当通过")
    if probe.get("dns_leak"):
        take(20); detail.append("DNS 解析走本地，未走代理")
        evidence.append(Evidence("exposure", "dns", "leak",
                                 str(probe.get("dns_leak_detail", "解析器在本地国")),
                                 -20, "客户端探针", "high"))

    # ---- 一致性层（环境维度）----
    if probe.get("tz_mismatch"):
        take(15); detail.append(f"时区({probe.get('tz')})与 IP 时区({obs.timezone})不符")
        evidence.append(Evidence("consistency", "timezone", "mismatch",
                                 f"浏览器 {probe.get('tz')} vs IP {obs.timezone}", -15,
                                 "客户端探针", "high"))
    if probe.get("tz_offset_anomaly"):
        take(10); detail.append("时区偏移与 IANA 推算不符")
        evidence.append(Evidence("consistency", "tz_offset", "anomaly",
                                 str(probe.get("tz_offset_detail", "")), -10,
                                 "客户端探针", "medium"))
    if probe.get("lang_mismatch"):
        take(10); detail.append(f"语言({probe.get('lang')})与 IP 国家不符")
        evidence.append(Evidence("consistency", "language", "mismatch",
                                 f"浏览器 {probe.get('lang')} vs IP {obs.country}", -10,
                                 "客户端探针", "medium"))
    if probe.get("platform_ua_mismatch"):
        take(20); detail.append("平台与 UA 声明不符")
        evidence.append(Evidence("consistency", "platform", "mismatch",
                                 f"platform={probe.get('platform')} vs UA={probe.get('ua_os')}", -20,
                                 "客户端探针", "high"))
    if probe.get("font_mismatch"):
        take(15); detail.append("字体集与声明系统不符")
        evidence.append(Evidence("consistency", "fonts", "mismatch",
                                 str(probe.get("font_detail", "")), -15, "客户端探针", "medium"))
    if probe.get("gpu_sw"):
        take(10); detail.append("WebGL 为软渲染（SwiftShader 等）")
        evidence.append(Evidence("consistency", "webgl", "software",
                                 str(probe.get("renderer", "")), -10, "客户端探针", "medium"))
    if probe.get("hc_anomaly"):
        take(5); detail.append("hardwareConcurrency 异常")

    # geo 全挂时该 IP 根本没法判，直接报告
    if obs.geo_unavailable:
        unavailable.append(f"地理/ASN: {obs.geo_unavailable}")

    s = max(0, s)
    grade = ("clean" if s >= 90 else "usable" if s >= 70 else
             "risky" if s >= 50 else "dead")
    rep = Report(
        ip=obs.ip, scanned_at=obs.scanned_at, score=s, grade=grade,
        residence=residence, evidence=evidence, unavailable=unavailable,
        conclusion=_conclusion(obs, residence, detail), raw=obs.to_dict())
    rep.probe_grade = judge_probe(probe) if probe else None
    rep.fix_hints = fix_hints(probe) if probe else []
    return rep


def judge_probe(probe: dict) -> str:
    """环境维度单独评级：环境问题和 IP 问题分开说，客户才知道换 IP 有没有用。
    WebRTC 按四态：只有 leak 扣分；disabled/blocked 不扣分（disabled 记特征，
    blocked 在 unavailable 显式列出）。"""
    s = 100
    if webrtc_state_of(probe) == "leak": s -= 35
    if probe.get("dns_leak"): s -= 25
    if probe.get("tz_mismatch"): s -= 20
    if probe.get("tz_offset_anomaly"): s -= 10
    if probe.get("lang_mismatch"): s -= 10
    if probe.get("platform_ua_mismatch"): s -= 25
    if probe.get("font_mismatch"): s -= 15
    if probe.get("gpu_sw"): s -= 10
    s = max(0, s)
    return "clean" if s >= 90 else "usable" if s >= 70 else "risky" if s >= 50 else "dead"


WEBRTC_FIX_HINTS = {
    "企业策略": "注册表字符串值 WebRtcIPHandlingPolicy=disable_non_proxied_udp（Chrome: HKLM\\SOFTWARE\\Policies\\Google\\Chrome；Edge: HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge）——用户改不掉，域内可批量下发",
    "启动参数": "--webrtc-ip-handling-policy=disable_non_proxied_udp（四选值里唯一同时挡内网+直连公网的）；前提：①完全退出浏览器再启动（旧实例会把参数当 URL 丢弃——「加了还漏」多半是这条）②写进快捷方式（手敲下次就丢）③排查会自建 WebRTC 的扩展",
    "扩展临时": "uBlock Origin（仅 MV2 版）勾选防泄漏——只挡内网/host，公网 IP 经 STUN 仍可能暴露；Lite(MV3) 没有此项；多一层扩展多一层环境信号",
    "指纹浏览器": "环境设置 WebRTC 选 replace 或 disabled，不要 real；实现质量参差，设置显示已关≠真关，必须复测实检",
    "Firefox": "about:config → media.peerconnection.enabled=false，或 default_address_only=true + 代理",
}


def webrtc_state_of(probe: dict) -> str:
    """WebRTC 四态（设计方案 3.5）：leak / restricted / disabled / blocked。
    兼容旧探针数据：无 state 字段时按 webrtc_public 推断。"""
    state = probe.get("webrtc_state")
    if state in ("leak", "restricted", "disabled", "blocked"):
        return state
    return "leak" if probe.get("webrtc_public") or probe.get("webrtc_leak") else "restricted"


def fix_hints(probe: dict) -> list[str]:
    """按检测结果给出精确到配置项的修复指引。只指导修复真实泄漏，
    不提供伪造功能（红线 2）。"""
    hints: list[str] = []
    state = webrtc_state_of(probe)
    if state == "leak":
        pub = probe.get("webrtc_public") or probe.get("webrtc_ips") or []
        hints.append(
            "WebRTC 泄漏（暴露 " + ", ".join(pub[:2]) + "）：推荐顺序 企业策略 > 启动参数 > 扩展。"
            + WEBRTC_FIX_HINTS["企业策略"] + "；"
            + WEBRTC_FIX_HINTS["启动参数"]
            + "。改完在探针页点「WebRTC 复测」验证闭合")
    elif state == "blocked":
        hints.append(
            "WebRTC 检测被拦截（CSP/扩展/浏览器不支持）——本次没测到，不等于安全；"
            "换浏览器或在无拦截环境重开探针页")
    # disabled / restricted 不出修复项；disabled 的"环境特征"提示在结论里说
    if probe.get("tz_mismatch"):
        hints.append(
            f"时区不符（浏览器 {probe.get('tz')}，IP 期望 {probe.get('tz_expected', 'IP 所在时区')}）："
            "把指纹浏览器环境的时区改为 IP 所在时区（多数指纹浏览器支持按时区自动）")
    if probe.get("lang_mismatch"):
        hints.append("语言不符：浏览器首选语言改为 IP 国家主语言")
    if probe.get("platform_ua_mismatch"):
        hints.append("平台与 UA 不符：指纹环境里统一 platform 与 UA 的操作系统声明")
    if probe.get("font_mismatch"):
        hints.append("字体集与声明系统不符：指纹环境勾选与 OS 匹配的字体集")
    if probe.get("gpu_sw"):
        hints.append("WebGL 为软渲染：指纹环境开启硬件加速或真实 GPU 伪装")
    if probe.get("dns_leak"):
        hints.append("DNS 走本地：指纹浏览器开启远程 DNS（socks5h / 代理侧解析）")
    return hints


def _conclusion(obs: Observation, residence: str, detail: list[str]) -> str:
    parts: list[str] = []
    loc = "、".join(x for x in (obs.city, obs.country) if x) or "未知地区"
    at = classify_asn(obs.asn)
    if residence == "resident":
        parts.append(f"该 IP（{loc}，AS{obs.asn} {obs.asn_org}）四路证据判定为真住宅")
    elif residence == "hosting":
        parts.append(f"该 IP（{loc}，AS{obs.asn} {obs.asn_org}）判定为机房网段，非真住宅")
    else:
        parts.append(f"该 IP（{loc}，AS{obs.asn} {obs.asn_org}）住宅特征无法确证，按存疑处理")
    if at == "hosting" and residence != "hosting":
        parts.append("但 ASN 表标为机房，两类证据冲突，置信度降低")
    if detail:
        parts.append("主要问题：" + "；".join(detail[:5]))
    probe = obs.probe or {}
    if probe:
        pg = judge_probe(probe)
        if pg in ("risky", "dead"):
            parts.append("环境维度不达标：这类封号换 IP 没用，按下面修复项逐条改")
        elif pg == "usable":
            parts.append("环境维度有小问题，按修复项修正")
        w_state = webrtc_state_of(probe)
        if w_state == "disabled":
            parts.append("WebRTC 已禁用（不扣分，但与「从未配置」可区分，某些平台视为异常指纹）")
        elif w_state == "blocked":
            parts.append("WebRTC 检测被拦截，本次未测到——不等于安全，需换环境复测")
        hints = fix_hints(probe)
        if hints:
            parts.append("修复：" + "；".join(hints))
    if not detail and not probe:
        parts.append("未发现明显问题，但 unavailable 项需对照确认是否真的测过")
    return "。".join(parts) + "。"
