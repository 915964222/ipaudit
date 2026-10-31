"""CLI 入口。

用法（设计方案 5.1）：
  ipaudit 1.2.3.4                    单 IP，终端彩色报告
  ipaudit 1.2.3.4 --json             机器可读
  ipaudit -f ips.txt --out report/   批量，每 IP 一份 HTML
  ipaudit --deep 1.2.3.4             /24 抽样 + 端口探测
  ipaudit --probe-link 1.2.3.4       生成一次性探针 URL
  ipaudit serve [--port 9650]        本地 API + 探针 + 监控
  ipaudit watch add 1.2.3.4 --every 6h --alert 70
  ipaudit watch list
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import webbrowser

from .collector import collect
from .judge import score_report
from .report import render_html, render_json, render_text
from .server import AuditService, make_handler, make_server
from .store import Store

def _default_db() -> str:
    """默认库路径：源码运行 → 项目 data/；PyInstaller 单文件 → exe 同级 data/。

    不能用 __file__：单文件模式下它指向 %TEMP%\\_MEIxxx 解包目录，
    exe 重启就换目录，扫描历史和探针会话会「莫名丢失」。"""
    if getattr(sys, "frozen", False):          # PyInstaller onefile
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "data", "ipaudit.db")


DEFAULT_DB = _default_db()
DEFAULT_PORT = 9650
IP_LIKE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _print_text(rep) -> None:
    print(render_text(rep))


def cmd_scan(args) -> int:
    if args.resolver:
        print(f"使用指定解析器: {args.resolver}", file=sys.stderr)
    for ip in args.targets:
        t0 = __import__("time").time()
        obs = collect(ip, deep=args.deep, resolver=args.resolver)
        rep = score_report(obs)
        rep.duration_ms = int((__import__("time").time() - t0) * 1000)
        if args.json:
            print(render_json(rep))
        else:
            _print_text(rep)
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            html_path = os.path.join(args.out, f"{ip}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(render_html(rep))
            json_path = os.path.join(args.out, f"{ip}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(render_json(rep))
            print(f"已写出 {html_path}", file=sys.stderr)
    return 0


def cmd_batch(args) -> int:
    with open(args.file, encoding="utf-8") as f:
        ips = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    args.targets = ips
    return cmd_scan(args)


def cmd_serve(args) -> int:
    service = AuditService(args.db, resolver=args.resolver, deep=args.deep,
                           require_auth=args.auth)
    service.start_monitor_loop()
    httpd = make_server(args.port, service, bind=args.bind)
    url = f"http://{args.bind}:{args.port}"
    print(f"ipaudit 服务已启动: {url}")
    print(f"  探针页  {url}/?t=<token>   （先 POST /api/probe/session 拿 token）")
    print(f"  API     {url}/api/scan/1.2.3.4")
    if args.auth:
        print("  鉴权    开启（扫描接口需 X-API-Token；POST /api/customer 建客户）")
    print(f"  数据库  {args.db}")
    print("Ctrl+C 停止")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        service.stop()
        print("\n已停止")
    return 0


def _make_server(port: int, service, bind: str = "127.0.0.1"):
    return make_server(port, service, bind=bind)


def cmd_probe(args) -> int:
    service = AuditService(args.db)
    token = service.store.create_probe_session()
    port = args.port
    httpd = _make_server(port, service)
    url = f"http://127.0.0.1:{port}/?t={token}"
    print(f"一次性探针会话已创建：{token}")
    print(f"在绑定了目标 IP 的浏览器里打开: {url}")
    print(f"（本机回环打开无意义——探针必须在走目标代理的浏览器里打开）")
    print("等待回传中，Ctrl+C 退出…")
    if args.open:
        webbrowser.open(url)

    class OneShot(make_handler(service)):   # type: ignore[misc,valid-type]
        pass

    try:
        # 只等服务把探针收进来；收到后 cross_check 打印结论
        deadline = __import__("time").time() + args.timeout
        while __import__("time").time() < deadline:
            row = service.store.get_probe(token)
            if row and row.get("received_at"):
                checks = service.cross_check(token, row["ip_seen"])
                print(json.dumps(checks, ensure_ascii=False, indent=2))
                if checks.get("linked_scan_id"):
                    scan = service.store.get_scan(checks["linked_scan_id"])
                    if scan:
                        raw = json.loads(scan["raw"])
                        rep = score_report(_obs_from_raw(raw))
                        _print_text(rep)
                return 0
            httpd.handle_request()          # 单步处理，便于轮询
        print("超时：探针未回传")
        return 1
    except KeyboardInterrupt:
        print("\n已退出")
        return 0


def _obs_from_raw(raw: dict):
    from .server import _obs_from_raw as f
    return f(raw)


def cmd_watch(args) -> int:
    store = Store(args.db)
    if args.watch_cmd == "add":
        m = re.fullmatch(r"(\d+)\s*(min|h|d)", str(args.every).strip())
        if not m:
            print(f"无效间隔: {args.every}（示例 30min / 6h / 1d）", file=sys.stderr)
            return 2
        n, unit = int(m.group(1)), m.group(2)
        minutes = n * (60 if unit == "min" else 3600 if unit == "h" else 86400)
        mid = store.add_monitor(args.ip, args.label or "", minutes,
                                args.alert, args.webhook or "")
        print(f"监控已添加 #{mid}: {args.ip} 每 {args.every} 复检，评分低于 {args.alert} 告警")
    else:
        rows = store.list_monitors()
        if not rows:
            print("（无监控）")
        for m in rows:
            print(f"#{m['id']} {m['ip']:<16} 每{m['interval_min']}min  "
                  f"上次 {m['last_run'] or '未运行'} score={m['last_score']} "
                  f"阈值{m['alert_score']}")
    return 0


def cmd_resolver_check(args) -> int:
    """部署自检：解析器是否被 Spamhaus 拒 + 是否开放递归（防放大器）。"""
    from .dnsbl import check_open_recursion, check_resolver_health
    h = check_resolver_health(args.resolver)
    icon = {"ok": "✓", "refused": "✗", "unreachable": "✗"}[h["status"]]
    print(f"{icon} 解析器 {h['resolver']}: {h['status']} — {h['detail']}")
    if h["status"] == "refused":
        print("  → 按 deploy/DEPLOY.md 部署 unbound（直连权威），再跑本命令复查")
    if args.recursion_test:
        r = check_open_recursion(args.recursion_test)
        icon2 = "✗" if r["open_recursion"] else "✓"
        print(f"{icon2} 开放递归测试 @{r['listen']}: {r['detail']}")
        if r["open_recursion"]:
            print("  → 你的解析器正在被全世界白嫖，立即修 access-control（见 deploy/DEPLOY.md 第三节）")
            return 1
    if h["status"] == "refused":
        return 1
    return 0


def cmd_watch_run(args) -> int:
    """立即复检全部到期监控（把 last_run 清零即视为到期），走完整告警链路。
    相当于手动触发一次监控循环体——daemon 化部署前验证告警用。"""
    service = AuditService(args.db, resolver=args.resolver, deep=args.deep)
    store = service.store
    rows = store.list_monitors()
    if not rows:
        print("（无监控）")
        return 0
    for m in rows:
        r = service.scan(m["ip"])
        if not r.get("ok"):
            print(f"✗ #{m['id']} {m['ip']} 复检失败: {r.get('error')}")
            continue
        new = r["report"]["score"]
        old = m["last_score"]
        store.update_monitor_run(m["id"], new)
        fired = None
        if old is not None and (new < m["alert_score"] or new < old):
            reason = f"score {old} → {new} (阈值 {m['alert_score']})"
            store.add_alert(m["id"], old, new, reason)
            if m.get("webhook"):
                service._fire_webhook(m["webhook"], m["ip"], reason, new)
            fired = reason
        mark = "✗告警" if fired else "✓正常"
        print(f"{mark} #{m['id']} {m['ip']:<16} {old} → {new}  {r['report']['grade']}"
              + (f"  [{fired}]" if fired else ""))
    alerts = store._conn.execute(
        "SELECT id, monitor_id, fired_at, reason, delivered FROM alert_log"
        " ORDER BY id DESC LIMIT 10").fetchall()
    if alerts:
        print("\n最近告警记录:")
        for a in alerts:
            print(f"  #{a['id']} monitor={a['monitor_id']} {a['fired_at']} "
                  f"delivered={a['delivered']}  {a['reason']}")
    return 0


def _interactive_menu(p: argparse.ArgumentParser) -> int:
    """双击 exe 的兜底：无参数启动时给一个数字菜单，跑完停在「按回车退出」，
    避免控制台窗口一闪而过。命令行重度用户仍走子命令，不受影响。"""
    print("ipaudit · IP 质量检测（未带参数启动，进入交互模式）\n")
    print("  1. 扫描单个 IP（终端报告）")
    print("  2. 扫描单个 IP（JSON，机器可读）")
    print("  3. 启动本地服务（API + 探针 + 监控，Ctrl+C 停止）")
    print("  4. 解析器自检（Spamhaus 可用性）")
    print("  5. 查看命令行完整帮助")
    choice = input("\n选择 [1-5]（回车退出）: ").strip()
    try:
        if choice == "1" or choice == "2":
            ip = input("要扫描的 IP: ").strip()
            if not IP_LIKE.match(ip):
                print(f"不是合法 IPv4: {ip}")
            else:
                argv = ["scan", ip] + (["--json"] if choice == "2" else [])
                args = p.parse_args(argv)
                return args.func(args)
        elif choice == "3":
            args = p.parse_args(["serve"])
            return args.func(args)
        elif choice == "4":
            args = p.parse_args(["resolver-check"])
            return args.func(args)
        elif choice == "5":
            p.print_help()
        else:
            print("未选择，退出。")
    finally:
        if choice in ("1", "2", "4", "5"):
            input("\n按回车关闭窗口…")
    return 0


def main(argv=None) -> int:
    # Windows GBK 控制台打不出 UTF-8 报告（✓/中文/颜色码），exe 里也没法
    # 靠环境变量兜底——启动时直接重配 stdio 为 UTF-8
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    if argv is None:
        argv = sys.argv[1:]
    # 兼容 `ipaudit 1.2.3.4` / `ipaudit --deep 1.2.3.4`：没写子命令时，
    # 在首个裸 IP 前补 scan 子命令，再交给 argparse 正常解析
    SUBCMDS = {"scan", "batch", "serve", "probe", "watch", "resolver-check",
               "-h", "--help"}
    if argv and argv[0] not in SUBCMDS:
        patched = list(argv)
        for i, a in enumerate(patched):
            if IP_LIKE.match(str(a)):
                patched.insert(i, "scan")
                argv = patched
                break
    p = argparse.ArgumentParser(prog="ipaudit",
                                description="IP 质量检测：卖判断力，不卖通道")
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite 路径")
    p.add_argument("--resolver", default=None, help="指定 DNS 解析器（Spamhaus 需自建）")
    p.add_argument("--deep", action="store_true", help="/24 抽样 + 端口探测")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="扫描 IP")
    sp.add_argument("targets", nargs="+")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--out", default=None, help="输出 HTML/JSON 到目录")
    sp.set_defaults(func=cmd_scan)

    bp = sub.add_parser("batch", help="批量扫描")
    bp.add_argument("-f", "--file", required=True)
    bp.add_argument("--json", action="store_true")
    bp.add_argument("--out", default=None)
    bp.set_defaults(func=cmd_batch)

    vp = sub.add_parser("serve", help="启动本地 API 服务")
    vp.add_argument("--port", type=int, default=DEFAULT_PORT)
    vp.add_argument("--bind", default="127.0.0.1",
                    help="监听地址，默认 127.0.0.1；跨机绑内网/WireGuard IP 并必须配 --auth")
    vp.add_argument("--auth", action="store_true",
                    help="订阅模式：扫描接口要求 X-API-Token 并计配额")
    vp.set_defaults(func=cmd_serve)

    rc = sub.add_parser("resolver-check", help="自检解析器（Spamhaus 可用性 + 开放递归）")
    rc.add_argument("resolver", nargs="?", default=None,
                    help="解析器 IP，默认用系统 DNS")
    rc.add_argument("--recursion-test", dest="recursion_test", default=None,
                    help="对指定监听 IP 验证开放递归（部署 unbound 后跑）")
    rc.set_defaults(func=cmd_resolver_check)

    pp = sub.add_parser("probe", help="生成一次性探针并等待回传")
    pp.add_argument("--port", type=int, default=DEFAULT_PORT)
    pp.add_argument("--open", action="store_true", help="自动打开浏览器")
    pp.add_argument("--timeout", type=int, default=600)
    pp.set_defaults(func=cmd_probe)

    wp = sub.add_parser("watch", help="监控子命令")
    wsub = wp.add_subparsers(dest="watch_cmd")
    wa = wsub.add_parser("add")
    wa.add_argument("ip")
    wa.add_argument("--label", default=None)
    wa.add_argument("--every", default="6h",
                    help="间隔，如 30min / 6h / 1d")
    wa.add_argument("--alert", type=int, default=70)
    wa.add_argument("--webhook", default=None)
    wsub.add_parser("list").set_defaults(func=cmd_watch)
    wr = wsub.add_parser("run", help="立即复检全部到期监控并触发告警")
    wr.set_defaults(func=cmd_watch_run)
    wa.set_defaults(func=cmd_watch)

    # 兼容路径已在上面的 argv 预处理里完成
    args = p.parse_args(argv)
    if not hasattr(args, "func"):
        # 双击 exe 落到这里：打印帮助后立刻退出，控制台窗口一闪而过。
        # 交互菜单兜底——让双击用户至少能用起来
        try:
            return _interactive_menu(p)
        except (KeyboardInterrupt, EOFError):
            return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
