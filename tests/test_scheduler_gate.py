"""调度器加载闸门与熔断的单测。

重点验证两条容易被改坏的不变量：
  1. 非自有上游永远进不了调度表（这是产品边界，不是配置）
  2. 配额故障的熔断时长必须长于普通故障（否则每次重试都在烧额度）
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from ipaudit.scheduler import (
    FAIL_THRESHOLD,
    OPEN_SECONDS,
    QUOTA_SECONDS,
    State,
    apply_result,
    candidates,
    explain_exclusions,
    QUOTA,
    OK,
    CONNECT_FAIL,
)
from ipaudit.upstreams import Upstream, load_registry, validate


def _u(**kw) -> Upstream:
    base = dict(id="x", type="llm", base_url="http://127.0.0.1:1",
                owned=True, owner="self", source="自有 VPS", model="m")
    base.update(kw)
    return Upstream(**base)


class TestGate(unittest.TestCase):
    def test_valid_upstream_passes(self):
        self.assertEqual(validate(_u()), [])

    def test_public_proxy_type_rejected(self):
        errs = validate(_u(type="proxy"))
        self.assertTrue(any("不是上游类型" in e for e in errs), errs)

    def test_not_owned_rejected(self):
        errs = validate(_u(owned=False))
        self.assertTrue(any("owned=false" in e for e in errs), errs)

    def test_missing_source_rejected(self):
        errs = validate(_u(source=""))
        self.assertTrue(any("source" in e for e in errs), errs)

    def test_missing_owner_rejected(self):
        errs = validate(_u(owner=""))
        self.assertTrue(any("owner" in e for e in errs), errs)

    def test_llm_without_model_rejected(self):
        errs = validate(_u(model=""))
        self.assertTrue(any("model" in e for e in errs), errs)

    def test_bad_base_url_rejected(self):
        errs = validate(_u(base_url="ftp://x"))
        self.assertTrue(any("base_url" in e for e in errs), errs)

    def test_egress_needs_no_url(self):
        self.assertEqual(validate(_u(type="egress", base_url="", model="")), [])

    def test_registry_drops_bad_items(self):
        items = [
            _u(id="ok-one").to_dict(),
            _u(id="bad-one", owned=False).to_dict(),
        ]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "reg.json"
            p.write_text(json.dumps({"version": 1, "upstreams": items}), encoding="utf-8")
            good, bad = load_registry(p)
        self.assertEqual([u.id for u in good], ["ok-one"])
        self.assertEqual([r.id for r in bad], ["bad-one"])

    def test_duplicate_id_rejected(self):
        items = [_u(id="dup").to_dict(), _u(id="dup").to_dict()]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "reg.json"
            p.write_text(json.dumps({"version": 1, "upstreams": items}), encoding="utf-8")
            good, bad = load_registry(p)
        self.assertEqual(len(good), 1)
        self.assertTrue(any("重复" in e for r in bad for e in r.reasons))


class TestCircuit(unittest.TestCase):
    def test_quota_opens_longer_than_normal_failure(self):
        st = State(id="a")
        apply_result(_u(), st, QUOTA, "HTTP 429", 100.0)
        quota_left = st.circuit_until - time.time()
        self.assertGreater(quota_left, QUOTA_SECONDS - 5)

        st2 = State(id="b")
        apply_result(_u(), st2, CONNECT_FAIL, "refused", 10.0)
        self.assertLess(st2.circuit_until, time.time() + 0.1)  # 首次失败不熔断

        apply_result(_u(), st2, CONNECT_FAIL, "refused", 10.0)
        self.assertGreater(st2.circuit_until - time.time(), OPEN_SECONDS - 5)
        self.assertLess(st2.circuit_until - time.time(), QUOTA_SECONDS)

    def test_success_resets_streak_and_moves_ewma(self):
        st = State(id="c", ewma_ms=1000.0)
        apply_result(_u(), st, CONNECT_FAIL, "e", 0.0)
        self.assertEqual(st.fail_streak, 1)
        apply_result(_u(), st, OK, "", 400.0)
        self.assertEqual(st.fail_streak, 0)
        self.assertEqual(st.ok_streak, 1)
        self.assertLess(st.ewma_ms, 1000.0)

    def test_unprobed_is_not_candidate(self):
        ups = [_u(id="never")]
        picked = candidates(ups, {})
        self.assertEqual(picked, [])
        self.assertTrue(any("未探测" in s for s in explain_exclusions(ups, {})))

    def test_open_circuit_excluded(self):
        u = _u(id="broken")
        st = State(id="broken", last_verdict=CONNECT_FAIL, fail_streak=FAIL_THRESHOLD)
        st.open_for(OPEN_SECONDS)
        self.assertEqual(candidates([u], {"broken": st}), [])
        self.assertTrue(any("熔断" in s for s in explain_exclusions([u], {"broken": st})))

    def test_healthy_upstream_ranked_by_latency(self):
        fast, slow = _u(id="fast"), _u(id="slow")
        states = {"fast": State(id="fast", last_verdict=OK, ewma_ms=100.0),
                  "slow": State(id="slow", last_verdict=OK, ewma_ms=900.0)}
        picked = candidates([slow, fast], states)
        self.assertEqual([p[0].id for p in picked], ["fast", "slow"])


if __name__ == "__main__":
    unittest.main()


class TestQuotaPrecheck(unittest.TestCase):
    """L3 配额预检：余量 0 直接熔断，端点挂了不熔断交给 L2。"""

    def _with_response(self, payload):
        import ipaudit.scheduler as sch
        import urllib.request as _ur
        orig = _ur.urlopen
        class FakeResp:
            def read(self, n=-1): return json.dumps(payload).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        _ur.urlopen = lambda req, timeout: FakeResp()
        return orig, _ur

    def test_zero_remaining_all_windows_is_quota(self):
        import ipaudit.scheduler as sch
        import urllib.request as _ur
        orig, _ur = self._with_response({"data": [{"windows": [
            {"name": "GLM", "remaining": 0}, {"name": "GLM", "remaining": 0}]}]})
        try:
            from ipaudit.upstreams import Upstream
            u = Upstream(id="t", base_url="http://x", quota_path="/q", quota_match="glm")
            v, d = sch.probe_quota(u)
            self.assertEqual(v, "quota")
            self.assertIn("余量为 0", d)
        finally:
            _ur.urlopen = orig

    def test_some_remaining_is_ok(self):
        import ipaudit.scheduler as sch
        import urllib.request as _ur
        orig, _ur = self._with_response({"data": [{"windows": [
            {"name": "GLM", "remaining": 0}, {"name": "GLM", "remaining": 68}]}]})
        try:
            from ipaudit.upstreams import Upstream
            u = Upstream(id="t", base_url="http://x", quota_path="/q", quota_match="glm")
            v, _ = sch.probe_quota(u)
            self.assertEqual(v, "ok")
        finally:
            _ur.urlopen = orig

    def test_endpoint_down_is_not_circuit_open(self):
        # 配额端点失败不代表上游不可用：返回 quota_unavailable，L2 说了算
        import ipaudit.scheduler as sch
        import urllib.request as _ur
        orig = _ur.urlopen
        def boom(req, timeout):
            raise OSError("down")
        _ur.urlopen = boom
        try:
            from ipaudit.upstreams import Upstream
            u = Upstream(id="t", base_url="http://x", quota_path="/q")
            v, d = sch.probe_quota(u)
            self.assertEqual(v, "quota_unavailable")
        finally:
            _ur.urlopen = orig

    def test_no_quota_path_short_circuits_to_ok(self):
        import ipaudit.scheduler as sch
        from ipaudit.upstreams import Upstream
        u = Upstream(id="t", base_url="http://x")
        v, _ = sch.probe_quota(u)
        self.assertEqual(v, "ok")


class TestClinicCauses(unittest.TestCase):
    """会诊归因：按封号可能性排序，「换 IP 有没有用」是核心输出。"""

    def _session(self, probe: dict, ip="73.12.45.8", asn=7922, org="Comcast"):
        import tempfile
        from ipaudit.clinic import ClinicSession
        from ipaudit.models import Observation
        from ipaudit.judge import score_report
        from ipaudit.server import AuditService
        svc = AuditService(os.path.join(tempfile.mkdtemp(), "t.db"))
        cs = ClinicSession(svc.store, "t1", ip)
        cs.obs = Observation(ip=ip, scanned_at="t", asn=asn, asn_org=org,
                             asn_type="isp", country_code="US", country="United States",
                             timezone="America/New_York",
                             rdns="c-73-12-45-8.hsd1.ca.comcast.net",
                             rdns_pattern_hits=["residential:hsd"],
                             thirdparty={"ipapi_is": {"asn_type": "isp", "is_datacenter": False},
                                         "ip_api": {"hosting": False}})
        cs.obs.probe = probe
        cs.rep = score_report(cs.obs)
        return cs

    def test_webrtc_ranks_first_and_no_ip_swap(self):
        from ipaudit.clinic import CAUSE_RANK
        cs = self._session({"webrtc_state": "leak", "webrtc_public": ["1.2.3.4"],
                            "webrtc_ips": ["1.2.3.4"], "tz": "America/New_York",
                            "lang": "en-US"})
        cs.obs.probe["tz_mismatch"] = False
        cs.obs.probe["lang_mismatch"] = False
        from ipaudit.judge import score_report
        cs.rep = score_report(cs.obs)
        causes = cs.causes()
        self.assertEqual(causes[0]["rank"], CAUSE_RANK["env_webrtc"])
        self.assertFalse(causes[0]["ip_swap_helps"])

    def test_env_mismatch_says_dont_buy_ip(self):
        cs = self._session({"webrtc_state": "restricted", "webrtc_public": [],
                            "webrtc_ips": [], "tz": "Asia/Shanghai", "tz_mismatch": True,
                            "tz_expected": "America/New_York", "lang": "en-US"})
        cs.obs.probe["tz_mismatch"] = True
        from ipaudit.judge import score_report
        cs.rep = score_report(cs.obs)
        causes = cs.causes()
        self.assertTrue(any("换 IP 解决不了" in c["action"] or not c["ip_swap_helps"]
                            for c in causes if c["rank"] == 2))
        v = cs.verdict()
        self.assertIn("别买新 IP", v)

    def test_clean_env_points_to_account_behavior(self):
        cs = self._session({"webrtc_state": "restricted", "webrtc_public": [],
                            "webrtc_ips": [], "tz": "America/New_York", "lang": "en-US"})
        causes = cs.causes()
        self.assertEqual(len(causes), 1)
        self.assertIn("账号行为", causes[0]["action"])

    def test_dnsbl_hit_says_ip_swap_helps(self):
        from ipaudit.dnsbl import DnsblResult
        cs = self._session({"webrtc_state": "restricted", "webrtc_public": [],
                            "webrtc_ips": [], "tz": "America/New_York", "lang": "en-US"})
        cs.obs.dnsbl = [DnsblResult("spamhaus_zen", "hit", ["127.0.0.4"], 30)]
        from ipaudit.judge import score_report
        cs.rep = score_report(cs.obs)
        causes = cs.causes()
        bl = next(c for c in causes if c["rank"] == 3)
        self.assertTrue(bl["ip_swap_helps"])
