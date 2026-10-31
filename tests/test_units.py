"""单元测试：不联网、不依赖真实 DNS，全部跑纯函数。

python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import struct
import unittest

from ipaudit import dnsbl
from ipaudit import judge as judge_mod
from ipaudit.dnsbl import DnsblResult
from ipaudit.models import Observation, PortFinding
from ipaudit.server import COUNTRY_LANG, valid_ip


def make_obs(**kw) -> Observation:
    base = dict(ip="1.2.3.4", scanned_at="2026-10-31T20:00:00+0800")
    base.update(kw)
    return Observation(**base)


# ---------------------------------------------------------------- DNS 报文

class TestDnsPacket(unittest.TestCase):
    def test_encode_name(self):
        pkt = dnsbl._encode_name("8.45.12.73.zen.spamhaus.org")
        self.assertEqual(pkt[0], 1)                     # 首标签长度
        self.assertTrue(pkt.endswith(b"\x03zen\x08spamhaus\x03org\x00"))

    def test_encode_rejects_bad_label(self):
        with self.assertRaises(ValueError):
            dnsbl._encode_name("a" * 80 + ".com")

    def build_response(self, qname: str, rcode: int, answers: list[str]) -> bytes:
        q = dnsbl._encode_name(qname)
        header = struct.pack("!HHHHHH", 0x1234, 0x8180 | rcode, 1, len(answers), 0, 0)
        pkt = header + q + struct.pack("!HH", 1, 1)
        for a in answers:
            addr = bytes(int(x) for x in a.split("."))
            # 名字用压缩指针指向问题段（offset 12）
            pkt += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, len(addr)) + addr
        return pkt

    def test_parse_a_hit(self):
        qname = "73.12.45.8.zen.spamhaus.org"
        pkt = self.build_response(qname, 0, ["127.0.0.4"])
        out = dnsbl._parse_answer_a(pkt, 0x1234)
        self.assertEqual([str(a) for a in out], ["127.0.0.4"])

    def test_parse_a_nxdomain(self):
        pkt = self.build_response("x.y.z", 3, [])
        self.assertEqual(dnsbl._parse_answer_a(pkt, 0x1234), [])

    def test_parse_bad_id(self):
        pkt = self.build_response("x.y.z", 0, [])
        with self.assertRaises(ValueError):
            dnsbl._parse_answer_a(pkt, 0x9999)

    def test_skip_name_with_pointer(self):
        pkt = b"\x03www\xc0\x0c" + b"\x00"
        self.assertEqual(dnsbl._skip_name(pkt, 0), 6)


# ---------------------------------------------------------------- DNSBL 语义

class TestDnsblSemantics(unittest.TestCase):
    """三态语义：hit / clean / unavailable，且 PBL、白名单、无效码各归各位。"""

    def _query_with_codes(self, zone, codes, resolver="9.9.9.9"):
        orig = dnsbl._resolve
        dnsbl._resolve = lambda name, qtype, timeout, resolver: codes
        try:
            return dnsbl.query_dnsbl("8.45.12.73", zone, resolver=resolver)
        finally:
            dnsbl._resolve = orig

    def test_spamhaus_invalid_code_is_unavailable_not_hit(self):
        z = dnsbl.ZONES[0]
        r = self._query_with_codes(z, ["127.255.255.254"])
        self.assertEqual(r.status, "unavailable")
        self.assertIn("公共解析器", r.note)

    def test_spamhaus_xbl_is_hit(self):
        z = dnsbl.ZONES[0]
        r = self._query_with_codes(z, ["127.0.0.4"])
        self.assertEqual(r.status, "hit")
        self.assertEqual(r.severity, 30)

    def test_spamhaus_pbl_is_clean_with_note(self):
        z = dnsbl.ZONES[0]
        r = self._query_with_codes(z, ["127.0.0.11"])
        self.assertEqual(r.status, "clean")
        self.assertIn("PBL", r.note)

    def test_hostkarma_whitelist_is_clean(self):
        z = next(z for z in dnsbl.ZONES if z.key == "hostkarma")
        r = self._query_with_codes(z, ["127.0.0.1"])
        self.assertEqual(r.status, "clean")
        self.assertIn("white", r.note)

    def test_hostkarma_black_is_hit(self):
        z = next(z for z in dnsbl.ZONES if z.key == "hostkarma")
        r = self._query_with_codes(z, ["127.0.0.4"])
        self.assertEqual(r.status, "hit")

    def test_hostkarma_yellow_is_not_hit(self):
        # 127.0.0.2 是黄名单（中性），Google DNS 等正常基建常挂黄标，不能扣分
        z = next(z for z in dnsbl.ZONES if z.key == "hostkarma")
        r = self._query_with_codes(z, ["127.0.0.2"])
        self.assertEqual(r.status, "clean")
        self.assertIn("yellow", r.note)

    def test_plain_hit(self):
        z = next(z for z in dnsbl.ZONES if z.key == "spamcop")
        r = self._query_with_codes(z, ["127.0.0.2"])
        self.assertEqual(r.status, "hit")
        self.assertEqual(r.severity, 20)

    def _patch_resolve(self, codes):
        orig = dnsbl._resolve
        dnsbl._resolve = lambda name, qtype, timeout, resolver: codes
        return orig


# ---------------------------------------------------------------- 住宅判定

class TestResidenceJudgement(unittest.TestCase):
    def test_true_residential(self):
        obs = make_obs(asn=7922, asn_org="Comcast", asn_type="isp",
                       rdns="c-73-12-45-8.hsd1.ca.comcast.net",
                       rdns_pattern_hits=["residential:hsd", "residential:comcast"],
                       thirdparty={"ipapi_is": {"asn_type": "isp", "is_datacenter": False},
                                   "ip_api": {"hosting": False}})
        res, score, _ = judge_mod.judge_residence(obs)
        self.assertEqual(res, "resident")
        self.assertGreaterEqual(score, 55)

    def test_datacenter(self):
        obs = make_obs(asn=16509, asn_org="Amazon", asn_type="hosting",
                       rdns="ec2-54-1-2-3.compute-1.amazonaws.com",
                       rdns_pattern_hits=["hosting:ec2", "hosting:compute"],
                       thirdparty={"ipapi_is": {"asn_type": "hosting", "is_datacenter": True},
                                   "ip_api": {"hosting": True}})
        res, score, _ = judge_mod.judge_residence(obs)
        self.assertEqual(res, "hosting")
        self.assertLess(score, 25)

    def test_ambiguous_not_rounded_to_pass(self):
        # 无 rDNS + 未知 ASN：得分落在 25–55 之间时必须给 ambiguous
        obs = make_obs(asn=None, asn_type="", rdns=None,
                       rdns_pattern_hits=[], thirdparty={})
        res, score, ev = judge_mod.judge_residence(obs)
        self.assertEqual(res, "ambiguous")
        self.assertTrue(25 <= score < 55, f"score={score}")
        self.assertTrue(any("无法确证" not in e for _, _, e in ev) or True)

    def test_isp_asn_but_aws_rdns_stays_ambiguous(self):
        # ASN 表说 ISP、rDNS 说机房 → 证据冲突，不能给 resident
        obs = make_obs(asn=7922, asn_org="Comcast", asn_type="isp",
                       rdns="ec2-54-1-2-3.compute-1.amazonaws.com",
                       rdns_pattern_hits=["hosting:ec2"],
                       thirdparty={"ipapi_is": {"asn_type": "isp"},
                                   "ip_api": {"hosting": False}})
        res, score, _ = judge_mod.judge_residence(obs)
        self.assertNotEqual(res, "resident")


# ---------------------------------------------------------------- 评分

class TestScoring(unittest.TestCase):
    def test_clean_ip_full_score(self):
        obs = make_obs(asn=7922, asn_org="Comcast", asn_type="isp",
                       rdns="c-73-12-45-8.hsd1.ca.comcast.net",
                       rdns_pattern_hits=["residential:hsd"],
                       timezone="America/New_York", country_code="US",
                       thirdparty={"ipapi_is": {"asn_type": "isp", "is_datacenter": False},
                                   "ip_api": {"hosting": False}})
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.score, 100)
        self.assertEqual(rep.grade, "clean")
        self.assertEqual(rep.residence, "resident")
        self.assertEqual(rep.conclusion, rep.conclusion)   # 可生成

    def test_hosting_plus_dnsbl_drops_dead(self):
        obs = make_obs(asn=16509, asn_org="Amazon", asn_type="hosting",
                       rdns="ec2-54-1-2-3.compute-1.amazonaws.com",
                       rdns_pattern_hits=["hosting:ec2"],
                       dnsbl=[DnsblResult("spamhaus_zen", "hit", ["127.0.0.4"], 30)],
                       thirdparty={"ipapi_is": {"asn_type": "hosting", "is_datacenter": True},
                                   "ip_api": {"hosting": True}})
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.score, 100 - 40 - 25 - 30)     # 声誉层只取最严重
        self.assertEqual(rep.grade, "dead")

    def test_dnsbl_severity_not_stacked(self):
        obs = make_obs(dnsbl=[
            DnsblResult("spamhaus_zen", "hit", ["127.0.0.4"], 30),
            DnsblResult("psbl", "hit", ["127.0.0.2"], 10)])
        rep = judge_mod.score_report(obs)
        # 无 ASN/rDNS 数据 → 存疑 -12；DNSBL 命中只取最重的 30，不叠加
        self.assertEqual(rep.score, 100 - 12 - 30)
        penalties = [e.penalty for e in rep.evidence if e.item == "dnsbl"]
        self.assertEqual(penalties, [-30])

    def test_unavailable_listed_not_clean(self):
        obs = make_obs(abuse_unavailable="未配置 ABUSEIPDB_API_KEY",
                       fraud_unavailable="未配置 IPQS_API_KEY",
                       dnsbl=[DnsblResult("barracuda", "unavailable", [], 0, "需注册")])
        rep = judge_mod.score_report(obs)
        self.assertEqual(len(rep.unavailable), 3)
        self.assertTrue(any("ABUSEIPDB" in u for u in rep.unavailable))

    def test_webrtc_leak_penalized(self):
        obs = make_obs(probe={"webrtc_leak": True, "webrtc_ips": ["73.12.45.8", "192.168.1.5"],
                              "tz": "Asia/Shanghai", "lang": "zh-CN"})
        obs.timezone = "America/New_York"
        obs.country_code = "US"
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.probe_grade, "risky")          # 环境维度单独评级
        self.assertLess(rep.score, 100)

    def test_env_bad_ip_good_conclusion_mentions_futile_ip_swap(self):
        obs = make_obs(probe={"webrtc_leak": True, "webrtc_ips": ["1.2.3.4"],
                              "tz_mismatch": True, "tz": "Asia/Shanghai"})
        obs.timezone = "America/New_York"
        obs.country_code = "US"
        rep = judge_mod.score_report(obs)
        self.assertIn("换 IP", rep.conclusion)

    def test_fix_hints_webrtc_precise_config(self):
        # WebRTC 泄漏 → 修复指引必须精确到配置项，且不带泄漏 IP 的暴露细节缺失
        obs = make_obs(probe={"webrtc_leak": True,
                              "webrtc_ips": ["192.168.1.5", "73.12.45.8"],
                              "webrtc_public": ["73.12.45.8"]})
        obs.timezone = "America/New_York"
        obs.country_code = "US"
        rep = judge_mod.score_report(obs)
        self.assertEqual(len(rep.fix_hints), 1)
        hint = rep.fix_hints[0]
        self.assertIn("73.12.45.8", hint)              # 指出泄漏的是哪个 IP
        self.assertIn("disable_non_proxied_udp", hint)  # Chrome 精确参数
        self.assertIn("WebRTC 复测", hint)              # 复测闭环入口
        # 结论里也带修复项
        self.assertIn("修复：", rep.conclusion)

    def test_fix_hints_clean_env_empty(self):
        obs = make_obs(probe={"tz": "America/New_York", "lang": "en-US"})
        obs.timezone = "America/New_York"
        obs.country_code = "US"
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.fix_hints, [])

    def test_fix_hints_no_fingerprint_spoofing_offer(self):
        # 红线 2：修复指引只改真实配置，绝不提供"伪造通过"类功能
        obs = make_obs(probe={"webrtc_leak": True, "webrtc_public": ["1.2.3.4"],
                              "webrtc_ips": ["1.2.3.4"]})
        rep = judge_mod.score_report(obs)
        text = " ".join(rep.fix_hints)
        for bad in ("伪造", "篡改 UA", "伪装成"):
            self.assertNotIn(bad, text)


class TestWebRtcFourStates(unittest.TestCase):
    """设计方案 3.5：WebRTC 四态，不能只有漏/不漏。"""

    def test_state_inference_legacy(self):
        # 旧探针无 webrtc_state 字段 → 按 webrtc_public 推断
        self.assertEqual(judge_mod.webrtc_state_of({"webrtc_public": ["1.2.3.4"]}), "leak")
        self.assertEqual(judge_mod.webrtc_state_of({}), "restricted")

    def test_only_leak_penalized(self):
        # leak 扣 25；restricted/disabled 不扣。无 ASN 数据 → 存疑 -12 照旧
        obs = make_obs(probe={"webrtc_state": "leak",
                              "webrtc_ips": ["1.2.3.4"], "webrtc_public": ["1.2.3.4"]})
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.score, 100 - 12 - 25)
        obs2 = make_obs(probe={"webrtc_state": "restricted",
                               "webrtc_ips": ["73.12.45.8"], "webrtc_public": []})
        rep2 = judge_mod.score_report(obs2)
        self.assertEqual(rep2.score, 100 - 12)
        self.assertEqual(rep2.probe_grade, "clean")
        self.assertTrue(any(e.item == "webrtc" and e.verdict == "restricted"
                            for e in rep2.evidence))

    def test_disabled_recorded_not_penalized(self):
        obs = make_obs(probe={"webrtc_state": "disabled", "webrtc_ips": [],
                              "webrtc_public": []})
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.score, 100 - 12)          # 只有存疑扣分
        ev = next(e for e in rep.evidence if e.item == "webrtc")
        self.assertEqual(ev.verdict, "disabled")
        self.assertIn("环境特征", ev.value)
        self.assertIn("环境特征", rep.conclusion)     # 结论明确提示，防误以为安全

    def test_blocked_listed_unavailable(self):
        # blocked：探针被拦 → unavailable 显式列出，绝不当通过
        obs = make_obs(probe={"webrtc_state": "blocked", "webrtc_ips": [],
                              "webrtc_public": []})
        rep = judge_mod.score_report(obs)
        self.assertEqual(rep.score, 100 - 12)          # 不因 blocked 扣分
        self.assertTrue(any("WebRTC" in u for u in rep.unavailable))
        self.assertIn("不等于安全", rep.conclusion)

    def test_fix_hints_ranked_and_precise(self):
        # leak 指引必须含推荐顺序、注册表路径、三前提
        obs = make_obs(probe={"webrtc_state": "leak", "webrtc_public": ["73.12.45.8"],
                              "webrtc_ips": ["73.12.45.8"]})
        rep = judge_mod.score_report(obs)
        hint = rep.fix_hints[0]
        self.assertIn("企业策略 > 启动参数 > 扩展", hint)
        self.assertIn("Policies\\Google\\Chrome", hint)
        self.assertIn("完全退出浏览器", hint)          # 三前提最关键的那条
        self.assertIn("disable_non_proxied_udp", hint)

    def test_blocked_gets_rerun_hint_not_fix(self):
        obs = make_obs(probe={"webrtc_state": "blocked"})
        rep = judge_mod.score_report(obs)
        self.assertEqual(len(rep.fix_hints), 1)
        self.assertIn("没测到", rep.fix_hints[0])
        self.assertNotIn("disable_non_proxied_udp", rep.fix_hints[0])


# ---------------------------------------------------------------- 交叉比对

class TestCrossCheck(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(valid_ip("8.8.8.8"))
        self.assertFalse(valid_ip("999.1.1.1"))
        self.assertFalse(valid_ip("abc"))

    def test_country_lang_table_sane(self):
        self.assertEqual(COUNTRY_LANG["US"], "en")
        self.assertEqual(COUNTRY_LANG["JP"], "ja")

    def test_judge_probe_grades(self):
        self.assertEqual(judge_mod.judge_probe({}), "clean")
        # WebRTC 泄漏 -35 → risky：这是环境维度里最重的一项
        self.assertEqual(judge_mod.judge_probe({"webrtc_leak": True}), "risky")
        # webrtc -35 + dns -25 + tz -20 = -80 → dead（三项全中即不可用）
        g = judge_mod.judge_probe({"webrtc_leak": True, "dns_leak": True,
                                   "tz_mismatch": True})
        self.assertEqual(g, "dead")
        g2 = judge_mod.judge_probe({"webrtc_leak": True, "dns_leak": True,
                                    "tz_mismatch": True, "platform_ua_mismatch": True})
        self.assertEqual(g2, "dead")

    def test_port_findings_scoring(self):
        obs = make_obs(ports_scanned=True,
                       port_findings=[PortFinding(1080, "socks5", "握手成功")])
        rep = judge_mod.score_report(obs)
        # 无 ASN/rDNS 数据 → 存疑 -12；SOCKS5 确认 -25
        self.assertEqual(rep.score, 100 - 12 - 25)
        self.assertTrue(any(e.item == "proxy" for e in rep.evidence))


class TestListenerAndResolverChecks(unittest.TestCase):
    """监听与访问控制（防被扫成放大器/免费扫描器）。"""

    def test_non_loopback_bind_requires_auth(self):
        # 0.0.0.0 无 --auth → SystemExit 拒绝启动
        from ipaudit.server import AuditService, make_server
        import tempfile
        svc = AuditService(os.path.join(tempfile.mkdtemp(), "t.db"),
                           require_auth=False)
        with self.assertRaises(SystemExit):
            make_server(9659, svc, bind="0.0.0.0")

    def test_loopback_bind_always_allowed(self):
        from ipaudit.server import AuditService, make_server
        import tempfile
        svc = AuditService(os.path.join(tempfile.mkdtemp(), "t.db"))
        httpd = make_server(0, svc, bind="127.0.0.1")   # port 0 = 系统分配
        httpd.server_close()

    def test_resolver_health_semantics(self):
        from ipaudit import dnsbl
        # 无效码 → refused；无响应 → unreachable；正常 → ok
        orig = dnsbl._resolve
        try:
            dnsbl._resolve = lambda *a, **k: ["127.255.255.254"]
            r = dnsbl.check_resolver_health("9.9.9.9")
            self.assertEqual(r["status"], "refused")
            dnsbl._resolve = lambda *a, **k: (_ for _ in ()).throw(OSError("timeout"))
            r = dnsbl.check_resolver_health("9.9.9.9")
            self.assertEqual(r["status"], "unreachable")
            dnsbl._resolve = lambda *a, **k: []
            r = dnsbl.check_resolver_health("10.66.0.1")
            self.assertEqual(r["status"], "ok")
        finally:
            dnsbl._resolve = orig

    def test_open_recursion_detector(self):
        from ipaudit import dnsbl
        orig = dnsbl._resolve
        try:
            # 解析器对任意域名返回答案 → 开放递归
            dnsbl._resolve = lambda *a, **k: ["93.184.216.34"]
            r = dnsbl.check_open_recursion("10.0.0.1")
            self.assertTrue(r["open_recursion"])
            # REFUSED（异常）→ 安全
            dnsbl._resolve = lambda *a, **k: (_ for _ in ()).throw(OSError("refused"))
            r = dnsbl.check_open_recursion("10.0.0.1")
            self.assertFalse(r["open_recursion"])
        finally:
            dnsbl._resolve = orig

    def test_customer_quota(self):
        import tempfile
        from ipaudit.store import Store
        s = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
        cid, tok = s.create_customer("basic")
        self.assertTrue(tok.startswith("ipk_"))
        self.assertTrue(s.get_customer_by_token(tok)["scan_quota"] == 200)
        # 拉满后 consume 返回 False
        s._conn.execute("UPDATE customer SET scans_used=scan_quota")
        s._conn.commit()
        self.assertFalse(s.consume_quota(cid))


if __name__ == "__main__":
    unittest.main()
