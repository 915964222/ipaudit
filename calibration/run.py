"""标定脚本（设计方案第九节第 3 条）。

跑 ground_truth.json 里的 20+ 个已知类型 IP，输出：
  - 三分类判准率（P0 验收门槛 ≥80%）
  - 每个 IP 的四路证据明细，判错的 case 直接能看到是哪一路拖了分
结果写 calibration/result.json，权重调整后重跑对比。

用法：
  python calibration/run.py            # 全量
  python calibration/run.py --only 73.12.45.8 8.8.8.8   # 只跑指定 IP
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipaudit.collector import collect                    # noqa: E402
from ipaudit.judge import _residence_evidence, judge_residence, score_report  # noqa: E402
from ipaudit.report import GRADE_CN                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GT_PATH = os.path.join(HERE, "ground_truth.json")
OUT_PATH = os.path.join(HERE, "result.json")


def run(only: list[str] | None = None) -> int:
    with open(GT_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    cases = [c for c in gt["cases"] if c["expected_residence"] != "skip"]
    if only:
        cases = [c for c in cases if c["ip"] in only]

    results = []
    for c in cases:
        ip, expect_res, expect_grades = c["ip"], c["expected_residence"], c["expected_grade"]
        t0 = time.time()
        try:
            obs = collect(ip, deep=False)
        except Exception as e:
            results.append({"ip": ip, "label": c["label"], "error": str(e),
                            "pass": False})
            print(f"  ✗ {ip:<16} 采集异常: {e}")
            continue
        rep = score_report(obs)
        res, score, ev = judge_residence(obs)
        dur = int((time.time() - t0) * 1000)

        res_ok = res == expect_res
        grade_ok = rep.grade in expect_grades
        entry = {
            "ip": ip, "label": c["label"],
            "expected": {"residence": expect_res, "grade": expect_grades},
            "got": {"residence": res, "residence_score": score,
                    "grade": rep.grade, "score": rep.score},
            "pass": res_ok and grade_ok,
            "evidence": [{"name": n, "score": s, "note": t} for n, s, t in ev],
            "conclusion": rep.conclusion,
            "duration_ms": dur,
        }
        results.append(entry)
        mark = "✓" if entry["pass"] else "✗"
        print(f"  {mark} {ip:<16} {c['label']:<22} "
              f"期望 {expect_res:<9} 实得 {res:<9} (四路 {score:>3})  "
              f"评分 {rep.score} {GRADE_CN[rep.grade]}  {dur}ms")
        if not res_ok:
            for n, s, t in ev:
                print(f"        {n:<14} {s:>3}  {t}")

    ok = sum(1 for r in results if r.get("pass"))
    total = len(results)
    rate = ok / total if total else 0
    verdict = "达标" if rate >= 0.8 else "未达标（门槛 80%）"
    print(f"\n三分类判准率: {ok}/{total} = {rate:.0%} — {verdict}")
    # 评级档允许相邻浮动，单独统计严格一致率供参考
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"ran_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "ok": ok, "total": total, "rate": round(rate, 3),
                   "results": results}, f, ensure_ascii=False, indent=2)
    print(f"明细已写 {OUT_PATH}")
    return 0 if rate >= 0.8 else 1


if __name__ == "__main__":
    only = sys.argv[sys.argv.index("--only") + 1:] if "--only" in sys.argv else None
    sys.exit(run(only))
