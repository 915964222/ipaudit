"""账号环境排查服务（clinic）——面向跨境电商卖家的会诊工作流。

一个店铺一次会诊：IP 维度扫描 + 环境维度探针 + 归因结论。
不是"又一个扫描器"——卖家要的是"我为什么被封、下一步做什么"，
所以输出按封号原因排序，每条给可执行动作，并把「换 IP 没用」的情况
明确标出来（省钱比什么都重要）。

红线不变：不存账号关联（店铺用一次性 token 代表），只存结论。
"""

from __future__ import annotations

import json
import time

from .collector import collect
from .judge import fix_hints, judge_probe, score_report, webrtc_state_of
from .models import Observation

# 排查结论的归因框架：环境维度权重高于 IP 维度——封号场景里
# 「IP 干净但环境烂」远多于「IP 脏」，且前者换 IP 无效。
CAUSE_RANK = {
    "env_webrtc": 1,       # WebRTC 泄漏真实 IP——平台一抓一个准
    "env_mismatch": 2,     # 时区/语言/字体与 IP 国家不符——一眼假
    "ip_dnsbl": 3,         # IP 进了黑名单——有滥用历史
    "ip_hosting": 4,       # 机房段冒充住宅——供应商造假
    "env_blocked": 5,      # 探针被拦——测不全，需复测
    "ip_ok_env_ok": 0,     # 未发现异常——封号原因可能在别处（账号行为）
}


class ClinicSession:
    """一次排查会话 = 一个店铺环境。session_token 只在会话内使用，
    不落任何「店铺 ↔ 身份」关联。"""

    def __init__(self, store, session_id: str, ip: str):
        self.store = store
        self.session_id = session_id
        self.ip = ip
        self.obs: Observation | None = None
        self.rep = None
        self.probe_checks: dict = {}

    def run_ip_scan(self, deep: bool = False, resolver: str | None = None):
        t0 = time.time()
        self.obs = collect(self.ip, deep=deep, resolver=resolver)
        self.rep = score_report(self.obs)
        self.rep.duration_ms = int((time.time() - t0) * 1000)
        self.store.save_scan(self.rep,
                             json.dumps(self.obs.to_dict(), ensure_ascii=False),
                             self.rep.duration_ms)
        return self.rep

    def apply_probe(self, payload: dict, ip_seen: str) -> dict:
        """探针回传后合并进会话（复用 server 的纯比对逻辑，不依赖落库）。"""
        if not self.obs:
            raise RuntimeError("先 run_ip_scan 再 apply_probe")
        from .server import AuditService
        svc = AuditService(_db_path_of(self.store))
        tz_ip = self.obs.timezone or ""
        cc = self.obs.country_code or ""
        self.probe_checks = svc.cross_check_by_payload(
            payload, ip_seen, tz_ip=tz_ip, cc=cc)
        self.obs.probe = self.probe_checks        # 合并进 IP 维度做联合评分
        self.rep = score_report(self.obs)
        return self.probe_checks

    # ---- 归因 ----

    def causes(self) -> list[dict]:
        """按封号可能性排序的归因清单。每条含：原因/证据/该做什么/换 IP 有没有用。"""
        out: list[dict] = []
        if not self.rep:
            return out
        probe = self.obs.probe or {}
        w_state = webrtc_state_of(probe)

        if w_state == "leak":
            pub = probe.get("webrtc_public") or probe.get("webrtc_ips") or []
            out.append({
                "rank": CAUSE_RANK["env_webrtc"],
                "cause": "WebRTC 泄漏真实 IP",
                "evidence": f"探针采集到 {', '.join(pub[:2])}",
                "action": "指纹浏览器 WebRTC 选「替换」；Chrome 加启动参数；改完复测",
                "ip_swap_helps": False,
            })
        env_bad = [k for k in ("tz_mismatch", "lang_mismatch",
                               "platform_ua_mismatch", "font_mismatch")
                   if probe.get(k)]
        if env_bad:
            names = {"tz_mismatch": "时区", "lang_mismatch": "语言",
                     "platform_ua_mismatch": "平台/UA", "font_mismatch": "字体集"}
            out.append({
                "rank": CAUSE_RANK["env_mismatch"],
                "cause": "浏览器环境与 IP 国家不符（" +
                         "、".join(names[k] for k in env_bad) + "）",
                "evidence": f"浏览器 {probe.get('tz')} vs IP 期望 {probe.get('tz_expected', self.obs.timezone)}",
                "action": "指纹浏览器环境整体对齐 IP 所在国家；多数工具支持按时区自动",
                "ip_swap_helps": False,
            })
        hits = [h for h in (self.obs.dnsbl or []) if h.status == "hit"]
        if hits:
            worst = max(hits, key=lambda h: h.severity)
            out.append({
                "rank": CAUSE_RANK["ip_dnsbl"],
                "cause": f"IP 有滥用历史（{worst.zone}）",
                "evidence": f"{worst.zone} → {','.join(worst.codes)}",
                "action": "向供应商要求换段或退款；换 IP 前先让供应商出质检报告",
                "ip_swap_helps": True,
            })
        if self.rep.residence == "hosting":
            out.append({
                "rank": CAUSE_RANK["ip_hosting"],
                "cause": "IP 是机房段冒充住宅（供应商造假）",
                "evidence": "四路证据投票判定机房（见报告证据链 ASN/rDNS 项）",
                "action": "找供应商退款，改买能出质检报告的服务商",
                "ip_swap_helps": True,
            })
        if w_state == "blocked":
            out.append({
                "rank": CAUSE_RANK["env_blocked"],
                "cause": "WebRTC 探针被拦截，环境未测全",
                "evidence": "RTCPeerConnection 不可用或零响应",
                "action": "换一个无拦截的环境重新打开探针页",
                "ip_swap_helps": False,
            })
        if not out:
            out.append({
                "rank": CAUSE_RANK["ip_ok_env_ok"],
                "cause": "未发现环境或 IP 异常",
                "evidence": f"IP 评分 {self.rep.score}/100，环境评级 {judge_probe(probe) if probe else '未测'}",
                "action": "封号原因可能不在环境：排查账号行为（登录频率、支付、品类）",
                "ip_swap_helps": False,
            })
        out.sort(key=lambda c: c["rank"])
        return out

    def verdict(self) -> str:
        """一句话结论：先说能不能救，再说救的顺序。"""
        cs = self.causes()
        if not cs:
            return "会话未完成。"
        top = cs[0]
        swap_note = ""
        if cs[0]["rank"] in (CAUSE_RANK["env_webrtc"], CAUSE_RANK["env_mismatch"]):
            swap_note = "先别买新 IP——当前问题换 IP 解决不了。"
        elif top["rank"] == CAUSE_RANK["ip_ok_env_ok"]:
            swap_note = "也别急着换 IP——现有证据不支持 IP 或环境是原因。"
        return (f"最可能的原因：{top['cause']}。{top['action']}。{swap_note} "
                f"排查项共 {len(cs)} 条，按顺序处理。").replace("。。", "。")


def _db_path_of(store) -> str:
    return getattr(store, "db_path", None) or getattr(store, "path", None) or ":memory:"
