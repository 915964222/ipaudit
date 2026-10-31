"""本地 HTTP 服务（零依赖，ThreadingHTTPServer）+ 环境维度交叉比对 + 监控循环。

接口（设计方案 5.2）：
  GET  /                     探针页（?t=token）
  GET  /api/scan/{ip}        单 IP 扫描
  POST /api/scan             批量 {"ips":[...]}
  GET  /api/report/{id}.html / .json
  POST /api/probe/session    创建探针会话
  POST /api/probe/submit     探针回传（服务端交叉比对，出环境评级）
  GET  /api/probe/{token}    查询探针比对结果
  GET/POST /api/monitor      监控列表 / 新增
  GET  /api/health           存活检查

红线：不提供任何出站代理；probe 不存账号关联。
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .collector import collect
from .judge import judge_probe, score_report
from .probe_page import PROBE_HTML
from .report import render_html, render_json, render_text
from .store import Store

IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# IP 国家 → 主语言（一致性层判据，覆盖主要目标市场；未列出的不判语言扣分）
COUNTRY_LANG = {
    "US": "en", "GB": "en", "CA": "en", "AU": "en", "NZ": "en", "IE": "en",
    "DE": "de", "AT": "de", "CH": "de",
    "FR": "fr", "BE": "fr",
    "ES": "es", "MX": "es", "AR": "es", "CO": "es", "CL": "es",
    "IT": "it", "NL": "nl", "PT": "pt", "BR": "pt",
    "JP": "ja", "KR": "ko", "TW": "zh", "HK": "zh", "SG": "en", "MY": "en",
    "CN": "zh", "SE": "sv", "NO": "no", "DK": "da", "FI": "fi", "PL": "pl",
    "CZ": "cs", "RU": "ru", "TH": "th", "VN": "vi", "ID": "id", "TR": "tr",
}

VALID_IP_TIMEZONES: dict[str, set[str]] = {
    "US": {"America/New_York", "America/Chicago", "America/Denver",
           "America/Los_Angeles", "America/Phoenix", "America/Anchorage",
           "Pacific/Honolulu", "America/Detroit", "America/Boise"},
    "GB": {"Europe/London"}, "DE": {"Europe/Berlin"}, "FR": {"Europe/Paris"},
    "ES": {"Europe/Madrid"}, "IT": {"Europe/Rome"}, "NL": {"Europe/Amsterdam"},
    "JP": {"Asia/Tokyo"}, "KR": {"Asia/Seoul"}, "CN": {"Asia/Shanghai", "Asia/Urumqi"},
    "TW": {"Asia/Taipei"}, "HK": {"Asia/Hong_Kong"}, "SG": {"Asia/Singapore"},
    "CA": {"America/Toronto", "America/Vancouver", "America/Edmonton",
           "America/Winnipeg", "America/Halifax", "America/St_Johns"},
    "AU": {"Australia/Sydney", "Australia/Melbourne", "Australia/Brisbane",
           "Australia/Perth", "Australia/Adelaide"},
    "BR": {"America/Sao_Paulo"}, "MX": {"America/Mexico_City"},
    "PL": {"Europe/Warsaw"}, "SE": {"Europe/Stockholm"}, "NO": {"Europe/Oslo"},
    "DK": {"Europe/Copenhagen"}, "FI": {"Europe/Helsinki"}, "RU": {"Europe/Moscow"},
}


def valid_ip(ip: str) -> bool:
    m = IP_RE.match(ip)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


class AuditService:
    def __init__(self, db_path: str, resolver: str | None = None, deep: bool = False,
                 require_auth: bool = False):
        self.store = Store(db_path)
        self.resolver = resolver
        self.deep = deep
        self.require_auth = require_auth   # 订阅模式：扫描类接口要 X-API-Token
        self._scan_lock = threading.Lock()   # ip-api 45 req/min，串行化扫描
        self._stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None

    def scan(self, ip: str) -> dict:
        if not valid_ip(ip):
            return {"ok": False, "error": f"非法 IP: {ip}"}
        with self._scan_lock:
            t0 = time.time()
            obs = collect(ip, deep=self.deep, resolver=self.resolver)
            rep = score_report(obs)
            rep.duration_ms = int((time.time() - t0) * 1000)
            sid = self.store.save_scan(rep, json.dumps(obs.to_dict(), ensure_ascii=False),
                                       rep.duration_ms)
        return {"ok": True, "scan_id": sid,
                "report": rep.to_dict(), "text": render_text(rep)}

    # ---- 探针回传的交叉比对（本产品的关键卖点）----

    def cross_check(self, token: str, ip_seen: str) -> dict:
        """把探针采集的环境特征与服务端 IP 维度结论交叉比对。"""
        row = self.store.get_probe(token)
        if not row or not row.get("payload"):
            return {}
        payload = json.loads(row["payload"])
        # 探针会话关联最近一次对该来源 IP 的扫描（只按 IP 关联，不存账号）
        scans = self.store.list_scans(30)
        scan = next((s for s in scans if s["ip"] == ip_seen), None)
        tz_ip, cc = "", ""
        if scan:
            full = self.store.get_scan(scan["id"])
            if full and full["raw"]:
                raw = json.loads(full["raw"])
                tz_ip = raw.get("timezone", "")
                cc = raw.get("country_code", "")

        checks: dict = {}
        # 时区一致性
        tz = payload.get("tz", "")
        checks["tz"] = tz
        if tz_ip and tz:
            checks["tz_mismatch"] = tz != tz_ip
            checks["tz_expected"] = tz_ip
        # 时区偏移 vs IANA 推算（拿不准就标记待查，不硬扣）
        off = payload.get("tz_offset")
        checks["tz_offset_anomaly"] = False
        if off is not None and tz:
            try:
                from zoneinfo import ZoneInfo
                import datetime
                now = datetime.datetime.now(ZoneInfo(tz))
                local_off = int(now.utcoffset().total_seconds() // 60)
                checks["tz_offset_anomaly"] = (local_off + off) % 1440 != 0
            except Exception:
                pass
        # 语言一致性
        lang = (payload.get("lang") or "").lower()
        if cc and lang and cc in COUNTRY_LANG:
            want = COUNTRY_LANG[cc]
            checks["lang"] = lang
            checks["lang_mismatch"] = not (lang == want or lang.startswith(want + "-"))
        # 平台/UA
        checks["platform_ua_mismatch"] = bool(payload.get("platform_ua_mismatch"))
        checks["platform"] = payload.get("platform", "")
        checks["ua_os"] = payload.get("ua_os", "")
        # 字体
        checks["font_mismatch"] = bool(payload.get("font_mismatch"))
        checks["font_detail"] = payload.get("font_detail", "")
        # WebRTC 四态（设计方案 3.5）：leak / restricted / disabled / blocked。
        # 兼容旧探针：没有 webrtc_state 时按 webrtc_public 推断为 leak 或 restricted。
        checks["webrtc_state"] = payload.get("webrtc_state") or (
            "leak" if payload.get("webrtc_public") else "restricted")
        checks["webrtc_ips"] = payload.get("webrtc_ips", [])
        checks["webrtc_public"] = payload.get("webrtc_public", [])
        checks["webrtc_has_host"] = bool(payload.get("webrtc_has_host"))
        checks["webrtc_candidates"] = payload.get("webrtc_candidates", [])
        checks["webrtc_supported"] = payload.get("webrtc_supported", True)
        checks["webrtc_error"] = payload.get("webrtc_error", "")
        checks["webrtc_leak"] = checks["webrtc_state"] == "leak"
        # DNS 泄漏：探针页请求随机子域，服务端日志里比对解析 IP；
        # 简化实现：直接记录 token 子域请求是否存在（DNS 泄漏检测需要权威 DNS，
        # 本地版以 WebRTC + 时区为主，DNS 项标记 manual）
        checks["dns_leak"] = bool(payload.get("dns_leak"))
        # WebGL
        checks["gpu_sw"] = bool(payload.get("gpu_sw"))
        checks["renderer"] = payload.get("renderer", "")
        checks["hc_anomaly"] = bool(payload.get("hc_anomaly"))

        with self._scan_lock:
            conn_scan = self._bind_probe_to_scan(scan["id"] if scan else None, row["id"])
        checks["probe_grade"] = judge_probe(checks)
        checks["linked_scan_id"] = conn_scan
        checks["ip_seen"] = ip_seen
        checks["tz_ip"] = tz_ip
        checks["country_code"] = cc
        return checks

    def _bind_probe_to_scan(self, scan_id: int | None, probe_id: int) -> int | None:
        if scan_id is None:
            return None
        self.store._conn.execute(
            "UPDATE scan SET probe_id=? WHERE id=?", (probe_id, scan_id))
        self.store._conn.commit()
        return scan_id

    # ---- 监控循环 ----

    def start_monitor_loop(self):
        def loop():
            while not self._stop.is_set():
                try:
                    for m in self.store.due_monitors(time.time()):
                        r = self.scan(m["ip"])
                        if not r.get("ok"):
                            continue
                        new = r["report"]["score"]
                        old = m["last_score"]
                        self.store.update_monitor_run(m["id"], new)
                        if old is not None and new < m["alert_score"] \
                                and (old >= m["alert_score"] or new < old):
                            reason = f"score {old} → {new} (阈值 {m['alert_score']})"
                            self.store.add_alert(m["id"], old, new, reason)
                            if m.get("webhook"):
                                self._fire_webhook(m["webhook"], m["ip"], reason, new)
                except Exception:
                    pass                     # 监控循环绝不因单次失败退出
                self._stop.wait(60)
        self._monitor_thread = threading.Thread(target=loop, daemon=True)
        self._monitor_thread.start()

    def _fire_webhook(self, url: str, ip: str, reason: str, score: int):
        try:
            body = json.dumps({"ip": ip, "reason": reason, "score": score,
                               "fired_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}).encode()
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            self.store._conn.execute(
                "UPDATE alert_log SET delivered=1 WHERE id=(SELECT MAX(id) FROM alert_log"
                " WHERE monitor_id=(SELECT id FROM monitor WHERE ip=?))", (ip,))
            self.store._conn.commit()
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    def stop(self):
        self._stop.set()


def _is_loopback(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "")


def make_server(port: int, service: AuditService, bind: str = "127.0.0.1"):
    """创建 HTTP 服务。非回环绑定强制要求 --auth（防被扫成免费扫描器）。"""
    if not _is_loopback(bind) and not service.require_auth:
        raise SystemExit(
            f"拒绝启动：绑定 {bind}（非回环）但未开 --auth。\n"
            "跨机访问必须加 --auth（X-API-Token 鉴权 + 配额），"
            "防止被扫成免费扫描器。")
    return ThreadingHTTPServer((bind, port), make_handler(service))


def make_handler(service: AuditService) -> type:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):   # 安静模式
            pass

        # ---- helpers ----

        def _json(self, obj, code: int = 200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, text: str, code: int = 200):
            body = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 1 << 20:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _auth(self) -> dict | None:
            """订阅模式鉴权：X-API-Token 头 → 客户档案（含配额检查）。
            未启用 require_auth 返回 {}（本地单机模式）；失败返回 None。"""
            if not service.require_auth:
                return {}
            token = self.headers.get("X-API-Token", "")
            cust = service.store.get_customer_by_token(token)
            if not cust:
                return None
            return cust

        # ---- routes ----

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/" or path.startswith("/probe"):
                self._html(PROBE_HTML)
            elif path == "/api/probe/session":
                # GET 也允许建会话：用户在浏览器地址栏就能自愈「会话不存在」，
                # 免 curl；POST 仍保留（程序化调用）
                token = service.store.create_probe_session()
                self._json({"ok": True, "token": token,
                            "url": f"http://{self.headers.get('Host', '127.0.0.1')}/?t={token}"})
            elif path == "/api/health":
                self._json({"ok": True, "service": "ipaudit", "tts": None,
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
            elif path.startswith("/api/scan/"):
                cust = self._auth()
                if cust is None:
                    self._json({"ok": False, "error": "缺少或非法 X-API-Token"}, 401)
                    return
                ip = path.rsplit("/", 1)[1]
                if cust and not service.store.consume_quota(cust["id"]):
                    self._json({"ok": False,
                                "error": f"配额已用尽（{cust['plan']} {cust['scans_used']}/{cust['scan_quota']}）"},
                               429)
                    return
                self._json(service.scan(ip))
            elif re.fullmatch(r"/api/report/\d+\.html", path):
                self._report(int(re.findall(r"\d+", path)[0]), "html")
            elif re.fullmatch(r"/api/report/\d+\.json", path):
                self._report(int(re.findall(r"\d+", path)[0]), "json")
            elif path.startswith("/api/probe/"):
                token = path.rsplit("/", 1)[1]
                checks = service.cross_check(token, self._client_ip())
                if checks:
                    self._json({"ok": True, "checks": checks})
                else:
                    self._json({"ok": False, "error": "会话不存在或未回传"}, 404)
            elif path == "/api/monitor":
                self._json({"ok": True, "monitors": service.store.list_monitors()})
            elif path == "/api/scans":
                self._json({"ok": True, "scans": service.store.list_scans()})
            else:
                self._json({"ok": False, "error": "not found"}, 404)

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/scan":
                cust = self._auth()
                if cust is None:
                    self._json({"ok": False, "error": "缺少或非法 X-API-Token"}, 401)
                    return
                body = self._body()
                ips = body.get("ips") or []
                ips = [i for i in ips if valid_ip(str(i))][:50]
                if not ips:
                    self._json({"ok": False, "error": " ips 为空或全部非法"}, 400)
                    return
                if cust:
                    left = cust["scan_quota"] - cust["scans_used"]
                    if left <= 0:
                        self._json({"ok": False,
                                    "error": f"配额已用尽（{cust['plan']} {cust['scans_used']}/{cust['scan_quota']}）"},
                                   429)
                        return
                    ips = ips[:left]
                out = [service.scan(ip) for ip in ips]
                self._json({"ok": True, "results": out})
            elif path == "/api/customer":
                # 创建订阅客户（运营方自己用，本地调用；公开部署时应再加管理密钥）
                plan = str(self._body().get("plan") or "basic")
                cid, token = service.store.create_customer(plan)
                self._json({"ok": True, "customer_id": cid, "api_token": token})
            elif path == "/api/probe/session":
                token = service.store.create_probe_session()
                self._json({"ok": True, "token": token,
                            "url": f"http://127.0.0.1:{self.server.server_port}/?t={token}"})
            elif path == "/api/probe/submit":
                body = self._body()
                token = str(body.get("token") or "")
                payload = body.get("payload") or {}
                if not token or not payload:
                    self._json({"ok": False, "error": "token/payload 缺失"}, 400)
                    return
                ip_seen = self._client_ip()
                pid = service.store.save_probe(token, ip_seen, payload)
                if pid is None:
                    self._json({"ok": False, "error": "会话不存在，先 POST /api/probe/session"}, 404)
                    return
                checks = service.cross_check(token, ip_seen)
                self._json({"ok": True, "probe_id": pid, "checks": checks})
            elif path == "/api/monitor":
                body = self._body()
                ip = str(body.get("ip") or "")
                if not valid_ip(ip):
                    self._json({"ok": False, "error": "非法 IP"}, 400)
                    return
                mid = service.store.add_monitor(
                    ip, str(body.get("label") or ""),
                    int(body.get("interval_min") or 360),
                    int(body.get("alert_score") or 70),
                    str(body.get("webhook") or ""))
                self._json({"ok": True, "monitor_id": mid})
            else:
                self._json({"ok": False, "error": "not found"}, 404)

        def _report(self, scan_id: int, kind: str):
            row = service.store.get_scan(scan_id)
            if not row:
                self._json({"ok": False, "error": "scan 不存在"}, 404)
                return
            raw = json.loads(row["raw"])
            rep = score_report(_obs_from_raw(raw))
            rep.duration_ms = row["duration_ms"] or 0
            if kind == "html":
                self._html(render_html(rep))
            else:
                self._json(json.loads(render_json(rep)))

    return Handler


def _obs_from_raw(raw: dict):
    """从存储的 Observation JSON 还原对象（重渲染报告用，不重新探测）。"""
    from .dnsbl import DnsblResult
    from .models import Observation, PortFinding
    obs = Observation(ip=raw["ip"], scanned_at=raw["scanned_at"])
    for k, v in raw.items():
        if k == "dnsbl":
            obs.dnsbl = [DnsblResult(**d) for d in v]
        elif k == "port_findings":
            obs.port_findings = [PortFinding(**d) for d in v]
        elif hasattr(obs, k):
            setattr(obs, k, v)
    return obs
