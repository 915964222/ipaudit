"""输出层 Reporter：终端彩色报告 / JSON / 单文件 HTML。

报告硬性要求（设计方案 5.3）：unavailable 必须显式列出；证据链可复核。
"""

from __future__ import annotations

import html
import json

from .models import Report

GRADE_CN = {"clean": "干净", "usable": "基本可用", "risky": "有风险", "dead": "不可用"}
GRADE_COLOR = {"clean": "\033[92m", "usable": "\033[93m",
               "risky": "\033[38;5;208m", "dead": "\033[91m"}
RES_CN = {"resident": "真住宅", "ambiguous": "存疑", "hosting": "机房伪装"}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


# ---------------------------------------------------------------- 终端

def render_text(rep: Report) -> str:
    out: list[str] = []
    c = GRADE_COLOR.get(rep.grade, "")
    out.append("")
    out.append(f"{BOLD}IP 质量检测报告  {rep.ip}{RESET}")
    out.append(f"{DIM}检测时间 {rep.scanned_at}  耗时 {rep.duration_ms}ms{RESET}")
    out.append("")
    out.append(f"  综合评分  {c}{BOLD}{rep.score} / 100  {GRADE_CN[rep.grade]}{RESET}")
    out.append(f"  住宅判定  {RES_CN[rep.residence]}")
    if rep.probe_grade:
        out.append(f"  环境维度  {GRADE_COLOR.get(rep.probe_grade, '')}"
                   f"{GRADE_CN[rep.probe_grade]}{RESET}（探针页实测，独立于 IP 维度）")
    out.append("")

    if rep.fix_hints:
        out.append(f"{BOLD}  修复项（改完在探针页复测）{RESET}")
        for h in rep.fix_hints:
            out.append(f"   → {h}")
        out.append("")

    if rep.evidence:
        out.append(f"{BOLD}  证据链{RESET}")
        for e in rep.evidence:
            layer = {"identity": "身份", "reputation": "声誉",
                     "exposure": "暴露", "consistency": "一致性"}[e.layer]
            penalty = f"{e.penalty}" if e.penalty else " 0"
            out.append(f"   [{layer}] {e.item} = {e.value}  "
                       f"{c if e.penalty <= -15 else ''}{penalty}{RESET}  "
                       f"{DIM}({e.source}, 置信度 {e.confidence}){RESET}")
        out.append("")

    if rep.unavailable:
        out.append(f"{BOLD}  未测到（不代表干净）{RESET}")
        for u in rep.unavailable:
            out.append(f"   - {u}")
        out.append("")

    if rep.conclusion:
        out.append(f"{BOLD}  结论{RESET}")
        out.append(f"   {rep.conclusion}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- JSON

def render_json(rep: Report) -> str:
    d = rep.to_dict()
    d["grade_cn"] = GRADE_CN[rep.grade]
    d["residence_cn"] = RES_CN[rep.residence]
    return json.dumps(d, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- HTML

_GRADE_BADGE = {
    "clean": ("#0a7d43", "#e7f7ee", "干净 · 可用"),
    "usable": ("#8a6d00", "#fdf6dd", "基本可用 · 环境项自查"),
    "risky": ("#b45309", "#fef0e3", "有风险 · 建议更换"),
    "dead": ("#b91c1c", "#fdeaea", "不可用 · 立即停用"),
}


def render_html(rep: Report) -> str:
    badge, bg, label = _GRADE_BADGE[rep.grade]
    rows = []
    for e in rep.evidence:
        rows.append(
            f"<tr><td>{_LAYER_CN.get(e.layer, e.layer)}</td><td><code>{esc(e.item)}</code></td>"
            f"<td>{esc(e.verdict)}</td><td>{esc(e.value)}</td>"
            f"<td class='pen{' neg' if e.penalty < 0 else ''}'>{e.penalty}</td>"
            f"<td class='dim'>{esc(e.source)} · {e.confidence}</td></tr>")
    unav = "".join(f"<li>{esc(u)}</li>" for u in rep.unavailable) or "<li>无</li>"
    probe_html = ""
    if rep.probe_grade:
        pbg, pbadge = _GRADE_BADGE[rep.probe_grade][0], _GRADE_BADGE[rep.probe_grade][2]
        probe_html = (f"<div class='card' style='border-left-color:{pbg}'>"
                      f"<h3>环境维度（浏览器探针实测）：<span style='color:{pbg}'>{esc(pbadge)}</span></h3>"
                      f"<p class='dim'>环境问题和 IP 问题相互独立——环境不达标时换 IP 无效。</p></div>")
    hints_html = ""
    if rep.fix_hints:
        items = "".join(f"<li>{esc(h)}</li>" for h in rep.fix_hints)
        hints_html = (f"<div class='card'><h3>修复项（改完在探针页复测）</h3>"
                      f"<ul>{items}</ul>"
                      f"<p class='dim'>本工具只检测泄漏、指导修复真实配置，不提供指纹伪造。</p></div>")
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP 报告 {esc(rep.ip)}</title>
<style>
 body{{font-family:'Segoe UI',system-ui,sans-serif;margin:0;background:#f4f6f8;color:#1c2430}}
 .wrap{{max-width:920px;margin:0 auto;padding:32px 20px}}
 h1{{font-size:22px}} h3{{margin:0 0 8px;font-size:15px}}
 .head{{display:flex;gap:24px;align-items:center;margin-bottom:20px}}
 .score{{font-size:52px;font-weight:700;line-height:1}}
 .badge{{display:inline-block;padding:6px 14px;border-radius:6px;font-weight:600}}
 .card{{background:#fff;border-radius:10px;padding:18px 22px;margin-bottom:16px;
        border-left:4px solid {badge};box-shadow:0 1px 3px rgba(0,0,0,.06)}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #eef1f4;vertical-align:top}}
 th{{color:#5b6b7c;font-weight:600;font-size:12px}}
 .pen{{font-weight:700}} .neg{{color:#b91c1c}} .dim{{color:#7a8794;font-size:12px}}
 code{{background:#f0f3f6;padding:1px 5px;border-radius:4px;font-size:12px}}
 ul{{margin:6px 0;padding-left:20px}} li{{margin:3px 0;font-size:13px}}
 .meta{{color:#7a8794;font-size:12px}}
 @media print{{body{{background:#fff}} .card{{box-shadow:none;border:1px solid #ddd}}}}
</style></head><body><div class="wrap">
<div class="head">
 <div><div class="score" style="color:{badge}">{rep.score}</div><div class="meta">/ 100</div></div>
 <div>
  <h1>IP 质量报告 · <code>{esc(rep.ip)}</code></h1>
  <span class="badge" style="background:{bg};color:{badge}">{esc(label)}</span>
  <span class="badge" style="background:#eef2f6;color:#41505f">住宅判定：{esc(RES_CN[rep.residence])}</span>
 </div>
</div>
<div class="card"><p class="meta">检测时间 {esc(rep.scanned_at)} · 耗时 {rep.duration_ms}ms</p>
<p>{esc(rep.conclusion)}</p></div>
{probe_html}
{hints_html}
<div class="card"><h3>证据链（每一条都可自行复核）</h3>
<table><tr><th>层</th><th>检测项</th><th>判定</th><th>值</th><th>扣分</th><th>来源</th></tr>
{''.join(rows) or '<tr><td colspan="6" class="dim">无证据项</td></tr>'}</table></div>
<div class="card"><h3>未测到（不代表干净）</h3><ul>{unav}</ul></div>
<p class="meta">本报告只做诊断，不提供代理/伪装功能；数据仅存结论，不存账号关联。</p>
</div></body></html>"""


_LAYER_CN = {"identity": "身份", "reputation": "声誉", "exposure": "暴露",
             "consistency": "一致性"}


def esc(s: str) -> str:
    return html.escape(str(s), quote=True)
