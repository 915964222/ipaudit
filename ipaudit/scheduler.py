"""上游调度器 P0：分层探测 + 熔断 + 加权选择 + 计量。

与 nginx upstream / HAProxy health check 的唯一区别，也是最关键的一处：
**HTTP 200 不等于健康。**

一个上游可以返回 200，同时：在响应体里塞 quota 报错、首字节 40 秒、
把你要的模型偷偷换成便宜的、或者只在流式下崩。只看状态码的探测会把
它当成健康的，然后把流量持续推过去。

所以健康判定分三层：

  L1 连通   TCP 握手成功，且握手耗时 < 阈值
  L2 语义   真实业务请求：状态码分类 + 响应体校验 + 模型回显比对
  L3 质量   滑动窗口成功率、EWMA 延迟、连续失败、配额余量

选择规则固定：未熔断 > 未配额 > 延迟或成本。**没测过的不算健康。**

用法：
    python -m ipaudit.scheduler list
    python -m ipaudit.scheduler probe [--id X] [--json]
    python -m ipaudit.scheduler pick --n 2 --strategy latency
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .upstreams import Upstream, load_registry

BASE = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = BASE / "upstreams.json"
STATE_FILE = BASE / "state" / "upstream_state.json"
USAGE_FILE = BASE / "state" / "upstream_usage.jsonl"

# 熔断参数（可在 CLI 覆盖）
FAIL_THRESHOLD = 2          # 连续失败次数
OPEN_SECONDS = 60.0         # 普通故障熔断时长
QUOTA_SECONDS = 300.0       # 配额耗尽：压更久，避免把额度打空
SAMPLE_WINDOW = 20          # 成功率滑动窗口

# L2 分类
OK, QUOTA, AUTH, UPSTREAM_5XX = "ok", "quota", "auth", "upstream_5xx"
BAD_STATUS, BAD_BODY, TIMEOUT, CONNECT_FAIL = "bad_status", "bad_body", "timeout", "connect_fail"
QUOTA_HINTS = ("quota", "usage limit", "insufficient", "balance", "exceed", "rate limit")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


@dataclass
class State:
    """单个上游的运行态，落盘以便熔断跨进程生效。"""
    id: str
    ewma_ms: float = 0.0
    fail_streak: int = 0
    ok_streak: int = 0
    circuit_until: float = 0.0
    last_verdict: str = "unprobed"
    last_error: str = ""
    last_probe_at: str = ""
    last_ok_at: str = ""
    samples: list[int] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)

    @property
    def probed(self) -> bool:
        return self.last_verdict != "unprobed"

    def open_for(self, seconds: float) -> None:
        self.circuit_until = time.time() + seconds

    @property
    def is_open(self) -> bool:
        return self.circuit_until > time.time()


def load_states() -> dict[str, State]:
    if not STATE_FILE.exists():
        return {}
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, State] = {}
    for sid, d in raw.items():
        try:
            out[sid] = State(**d)
        except TypeError:
            out[sid] = State(id=sid)
    return out


def save_states(states: dict[str, State]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps({k: asdict(v) for k, v in states.items()}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _append_usage(row: dict) -> None:
    USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with USAGE_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- L1

def probe_l1(u: Upstream, timeout: float = 5.0) -> tuple[bool, float, str]:
    pr = urlparse(u.base_url)
    host = pr.hostname or ""
    port = pr.port or (443 if pr.scheme == "https" else 80)
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, (time.perf_counter() - t0) * 1000, ""
    except OSError as exc:
        return False, (time.perf_counter() - t0) * 1000, f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------- L2

def _classify_http(status: int, body: str) -> tuple[str, str]:
    low = body.lower()
    if status == 429 or status == 402:
        return QUOTA, f"HTTP {status}"
    if status in (401, 403):
        return AUTH, f"HTTP {status}"
    if 500 <= status < 600:
        return UPSTREAM_5XX, f"HTTP {status}"
    if status >= 400:
        return BAD_STATUS, f"HTTP {status}"
    # 200 也可能是假的：错误体常被包在 200 里
    if any(h in low for h in QUOTA_HINTS) and '"error"' in low:
        return QUOTA, "200 但响应体是配额错误"
    if not body.strip():
        return BAD_BODY, "空响应体"
    return OK, ""


def probe_l2(u: Upstream, timeout: float) -> tuple[str, str, float, str]:
    """返回 (verdict, detail, ms, model_echo)。"""
    headers = {"user-agent": "ipaudit-scheduler/0.1"}
    if u.type == "llm":
        payload = json.dumps({
            "model": u.model,
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "ping"}],
        }).encode()
        headers.update({
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": u.api_key or "none",
        })
        req = urllib.request.Request(u.url, data=payload, headers=headers, method="POST")
    else:
        req = urllib.request.Request(u.url, headers=headers, method="GET")

    ctx = ssl.create_default_context()
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
            ms = (time.perf_counter() - t0) * 1000
            verdict, detail = _classify_http(resp.status, body)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(2048).decode("utf-8", "replace")
        except Exception:
            pass
        ms = (time.perf_counter() - t0) * 1000
        verdict, detail = _classify_http(exc.code, body)
        detail = f"{detail} {body[:120]}".strip()
    except (socket.timeout, TimeoutError):
        return TIMEOUT, f"超时 >{timeout:.0f}s", (time.perf_counter() - t0) * 1000, ""
    except urllib.error.URLError as exc:
        reason = str(getattr(exc, "reason", exc))
        if "timed out" in reason.lower():
            return TIMEOUT, reason, (time.perf_counter() - t0) * 1000, ""
        return CONNECT_FAIL, reason, (time.perf_counter() - t0) * 1000, ""
    except OSError as exc:
        return CONNECT_FAIL, f"{type(exc).__name__}: {exc}", (time.perf_counter() - t0) * 1000, ""

    echo = ""
    if u.type == "llm" and body.startswith("{"):
        try:
            echo = str(json.loads(body).get("model") or "")
        except json.JSONDecodeError:
            pass
    return verdict, detail, ms, echo


# ---------------------------------------------------------------- 状态更新

def apply_result(u: Upstream, st: State, verdict: str, detail: str, ms: float) -> None:
    st.last_probe_at = _now()
    st.last_verdict = verdict
    st.last_error = "" if verdict == OK else detail
    st.samples.append(1 if verdict == OK else 0)
    st.samples = st.samples[-SAMPLE_WINDOW:]
    if verdict == OK:
        st.ok_streak += 1
        st.fail_streak = 0
        st.last_ok_at = st.last_probe_at
        st.ewma_ms = ms if st.ewma_ms == 0 else st.ewma_ms * 0.7 + ms * 0.3
        return
    st.ok_streak = 0
    st.fail_streak += 1
    if verdict == QUOTA:
        st.open_for(QUOTA_SECONDS)
    elif st.fail_streak >= FAIL_THRESHOLD:
        st.open_for(OPEN_SECONDS)


def probe_quota(u: Upstream) -> tuple[str, str]:
    """L3 配额预检：上游有配额端点时，余量为 0 直接判 QUOTA，省一次 L2。

    返回 (verdict, detail)：OK / QUOTA / quota_unavailable（端点挂了不熔断，
    让 L2 的真实请求说话——配额端点失败不代表上游不可用）。"""
    if not u.quota_path:
        return OK, ""
    url = u.base_url.rstrip("/") + u.quota_path
    req = urllib.request.Request(url, headers={"user-agent": "ipaudit-scheduler/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return "quota_unavailable", f"配额端点不可达: {url}"

    windows: list[dict] = []
    for entry in data.get("data", []):
        windows.extend(entry.get("windows", []))
    if not windows:
        return "quota_unavailable", "配额端点无窗口数据"

    match = (u.quota_match or "").lower()
    relevant = [w for w in windows
                if not match or match in str(w.get("name", "")).lower()]
    pool = relevant or windows
    if any(float(w.get("remaining", 0) or 0) > 0 for w in pool):
        return OK, ""
    return QUOTA, f"配额窗口余量为 0（{len(pool)} 个窗口，匹配 '{u.quota_match or 'any'}'）"


def probe_one(u: Upstream, st: State, l1_timeout: float = 5.0) -> dict:
    row = {"at": _now(), "id": u.id, "type": u.type, "model": u.model}
    alive, l1_ms, l1_err = probe_l1(u, timeout=l1_timeout)
    row["l1_ms"] = round(l1_ms, 1)
    if not alive:
        row.update(verdict=CONNECT_FAIL, detail=f"L1 {l1_err}", ms=round(l1_ms, 1))
        apply_result(u, st, CONNECT_FAIL, l1_err, l1_ms)
        _append_usage(row)
        return row

    if u.quota_path:
        q_verdict, q_detail = probe_quota(u)
        row["quota"] = q_verdict
        if q_verdict == QUOTA:
            row.update(verdict=QUOTA, detail=q_detail, ms=round(l1_ms, 1))
            apply_result(u, st, QUOTA, q_detail, l1_ms)
            _append_usage(row)
            return row
        # quota_unavailable 不熔断，继续走 L2

    verdict, detail, ms, echo = probe_l2(u, timeout=u.timeout_s)
    row.update(verdict=verdict, detail=detail, ms=round(ms, 1), model_echo=echo)
    if echo and u.type == "llm" and u.model and echo and echo not in u.model and u.model not in echo:
        row["model_mismatch"] = f"请求 {u.model} / 实际 {echo}"
    apply_result(u, st, verdict, detail, ms)
    _append_usage(row)
    return row


# ---------------------------------------------------------------- 选择

def candidates(ups: list[Upstream], states: dict[str, State],
               strategy: str = "latency", include_unprobed: bool = False) -> list[tuple[Upstream, State, str]]:
    """返回可调度上游（按优先级排序），并给出每条被排除的原因。"""
    now = time.time()
    usable: list[tuple[Upstream, State]] = []
    for u in ups:
        st = states.get(u.id) or State(id=u.id)
        if not u.enabled:
            continue
        if st.circuit_until > now:
            continue
        if st.last_verdict == QUOTA:
            continue
        if not st.probed and not include_unprobed:
            continue
        usable.append((u, st))

    if strategy == "weight":
        key = lambda pair: (-pair[0].weight, pair[1].ewma_ms or 1e9)
    elif strategy == "cost":
        key = lambda pair: (pair[0].cost_per_1k, pair[1].ewma_ms or 1e9)
    else:  # latency
        key = lambda pair: (pair[1].ewma_ms or 1e9, -pair[0].weight)
    usable.sort(key=key)
    return [(u, st, strategy) for u, st in usable]


def explain_exclusions(ups: list[Upstream], states: dict[str, State]) -> list[str]:
    now = time.time()
    out = []
    for u in ups:
        st = states.get(u.id) or State(id=u.id)
        if not u.enabled:
            out.append(f"{u.id}: 已禁用")
        elif st.circuit_until > now:
            out.append(f"{u.id}: 熔断中，{st.circuit_until - now:.0f}s 后重试（{st.last_error or st.last_verdict}）")
        elif st.last_verdict == QUOTA:
            out.append(f"{u.id}: 配额耗尽，{st.circuit_until - now:.0f}s 后可探")
        elif not st.probed:
            out.append(f"{u.id}: 未探测，不能当健康")
    return out


# ---------------------------------------------------------------- CLI

def _fmt_table(rows: list[dict], cols: list[tuple[str, str, int]]) -> str:
    head = "  ".join(title.ljust(w) for title, _, w in cols)
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append("  ".join(str(r.get(k, ""))[:w].ljust(w) for k, _, w in cols))
    return "\n".join(lines)


def cmd_list(args: argparse.Namespace) -> int:
    ups, bad = load_registry(args.registry)
    states = load_states()
    rows = []
    for u in ups:
        st = states.get(u.id) or State(id=u.id)
        rows.append({
            "id": u.id, "type": u.type, "base": u.base_url,
            "verdict": st.last_verdict, "ewma": f"{st.ewma_ms:.0f}" if st.ewma_ms else "-",
            "ok%": f"{st.success_rate * 100:.0f}" if st.samples else "-",
            "owned": "yes" if u.owned else "NO", "w": u.weight,
        })
    print(_fmt_table(rows, [("id", "id", 18), ("type", "type", 6), ("base", "base", 34),
                            ("verdict", "verdict", 14), ("ewma", "ewma_ms", 8),
                            ("ok%", "ok%", 4), ("owned", "owned", 5), ("w", "w", 3)]))
    if bad:
        print("\n被拒绝的条目（不会参与调度）：")
        for r in bad:
            print(f"  - {r.id}: {'; '.join(r.reasons)}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    ups, bad = load_registry(args.registry)
    states = load_states()
    targets = [u for u in ups if not args.id or u.id == args.id]
    if not targets:
        print("没有可探测的上游", file=sys.stderr)
        return 2
    rows = []
    for u in targets:
        st = states.setdefault(u.id, State(id=u.id))
        row = probe_one(u, st, l1_timeout=args.l1_timeout)
        rows.append(row)
        if args.verbose:
            print(f"[{row['verdict']:>12}] {u.id}  {row.get('ms')}ms  {row.get('detail', '')}")
    save_states(states)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print(_fmt_table(rows, [("id", "id", 18), ("verdict", "verdict", 14),
                                ("ms", "ms", 8), ("l1", "l1_ms", 7), ("detail", "detail", 46)]))
        if bad:
            print(f"\n（有 {len(bad)} 条被登记表拒绝，运行 list 查看原因）")
    return 0


def cmd_pick(args: argparse.Namespace) -> int:
    ups, _ = load_registry(args.registry)
    states = load_states()
    picked = candidates(ups, states, strategy=args.strategy, include_unprobed=args.include_unprobed)
    if not picked:
        print("没有可用上游：")
        for line in explain_exclusions(ups, states):
            print("  -", line)
        return 1
    for i, (u, st, _) in enumerate(picked[: args.n], 1):
        print(f"{i}. {u.id}  ewma={st.ewma_ms:.0f}ms  ok={st.success_rate * 100:.0f}%  "
              f"weight={u.weight}  cost={u.cost_per_1k}/1k  ->  {u.base_url}")
    extra = explain_exclusions(ups, states)
    if extra:
        print("\n已排除：")
        for line in extra:
            print("  -", line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ipaudit.scheduler", description="自有上游调度器（分层探测 + 熔断）")
    p.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="登记表路径")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="列出登记表与运行态")
    pl.set_defaults(func=cmd_list)

    pp = sub.add_parser("probe", help="探测上游（L1 连通 + L2 语义）")
    pp.add_argument("--id", default="", help="只探某一个")
    pp.add_argument("--l1-timeout", type=float, default=5.0)
    pp.add_argument("--json", action="store_true")
    pp.add_argument("--verbose", "-v", action="store_true")
    pp.set_defaults(func=cmd_probe)

    pk = sub.add_parser("pick", help="按策略选出可用上游")
    pk.add_argument("--n", type=int, default=1)
    pk.add_argument("--strategy", choices=["latency", "weight", "cost"], default="latency")
    pk.add_argument("--include-unprobed", action="store_true", help="把未探测的也算候选（不建议）")
    pk.set_defaults(func=cmd_pick)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
