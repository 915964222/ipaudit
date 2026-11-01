"""调度器加载闸门与熔断的单测。

重点验证两条容易被改坏的不变量：
  1. 非自有上游永远进不了调度表（这是产品边界，不是配置）
  2. 配额故障的熔断时长必须长于普通故障（否则每次重试都在烧额度）
"""

import json
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
