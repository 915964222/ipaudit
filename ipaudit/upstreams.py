"""自有上游登记表（upstream registry）。

调度对象的定义写死在这里：**只调度你拥有或合法接入的上游**。

公开免费代理不是"可用资源"，是风险——请求内容、API 密钥、访问目标都会
经过陌生主机，且随时消失。它解决不了配额问题（配额按账号/客户端算，
不按 IP 算），只会把故障从"429"变成"502 + 密钥外流"。

所以登记一条上游必须回答三个问题，回答不了的一律拒绝加载：

  1. 它是谁的？            owned / owner
  2. 你凭什么用它？        source（自有 VPS / 公司线路 / 自购账号 / 自建代理）
  3. 它值多少？            weight / cost_per_1k

这不是免责声明，是加载闸门：`owned` 不为真或缺 `source` 的条目直接进
rejected 列表，不参与调度。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_TYPES = {"llm", "http", "egress"}
DEFAULT_PATH = {"llm": "/v1/messages", "http": "/", "egress": ""}
DEFAULT_TIMEOUT = 30.0


@dataclass
class Upstream:
    id: str
    type: str = "llm"                 # llm | http | egress
    base_url: str = ""
    owned: bool = False               # 必须是你的资产
    owner: str = ""                   # self / 公司名 / 供应商名
    source: str = ""                  # 凭什么用它：自有 VPS、包月线路、已购账号
    model: str = ""                   # type=llm 时必填
    api_key: str = ""
    path: str = ""                    # 留空取 DEFAULT_PATH
    weight: int = 10
    cost_per_1k: float = 0.0
    enabled: bool = True
    timeout_s: float = DEFAULT_TIMEOUT
    # L3 配额预检：上游暴露配额查询端点时填这里（相对 base_url）。
    # 例：magpie 是 /v1/magpie/quotas。探测时余量为 0 直接熔断，省一次 L2。
    quota_path: str = ""
    # 配额匹配：上游的窗口名/模型名与本上游对应的规则（不区分大小写的子串）。
    # 空 = 任一窗口余量 > 0 即视为有配额。
    quota_match: str = ""
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def url(self) -> str:
        base = self.base_url.rstrip("/")
        p = self.path or DEFAULT_PATH.get(self.type, "")
        if not p:
            return base
        return base + p if p.startswith("/") else base + "/" + p

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rejected:
    id: str
    reasons: list[str]


def validate(u: Upstream) -> list[str]:
    """返回错误列表，空列表表示可以调度。"""
    errs: list[str] = []
    if not u.id or not u.id.strip():
        errs.append("缺少 id")
    if u.type not in ALLOWED_TYPES:
        if u.type in {"proxy", "socks5", "socks4", "public_proxy"}:
            errs.append(
                f"type={u.type} 不是上游类型：公开代理不能进调度表；"
                "自建代理请登记为 type=http 并在 source 写明归属"
            )
        else:
            errs.append(f"未知 type={u.type}，可选 {'/'.join(sorted(ALLOWED_TYPES))}")
    if u.type != "egress":
        pr = urlparse(u.base_url or "")
        if pr.scheme not in {"http", "https"} or not pr.hostname:
            errs.append(f"base_url 非法：{u.base_url!r}")
    if not u.owned:
        errs.append("owned=false：只调度自有上游")
    if not (u.owner or "").strip():
        errs.append("缺少 owner（谁的资产）")
    if not (u.source or "").strip():
        errs.append("缺少 source（凭什么用它）")
    if u.type == "llm" and not (u.model or "").strip():
        errs.append("type=llm 必须给 model")
    if u.weight <= 0:
        errs.append("weight 必须 > 0")
    return errs


def load_registry(path: str | Path) -> tuple[list[Upstream], list[Rejected]]:
    """读取登记表。非法条目不抛异常，进 rejected 并给出原因。"""
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    items = raw.get("upstreams", raw if isinstance(raw, list) else [])
    ok: list[Upstream] = []
    bad: list[Rejected] = []
    seen: set[str] = set()
    for item in items:
        try:
            u = Upstream(**{k: v for k, v in item.items() if k in Upstream.__dataclass_fields__})
        except TypeError as exc:
            bad.append(Rejected(item.get("id", "?"), [f"字段错误: {exc}"]))
            continue
        errs = validate(u)
        if u.id in seen:
            errs.append("id 重复")
        if errs:
            bad.append(Rejected(u.id, errs))
            continue
        seen.add(u.id)
        ok.append(u)
    return ok, bad


def save_registry(path: str | Path, upstreams: list[Upstream]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"version": 1, "upstreams": [u.to_dict() for u in upstreams]},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
