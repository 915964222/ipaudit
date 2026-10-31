"""SQLite 存储。

数据最小化红线（设计方案 1.2 / 4）：probe 表刻意不存账号 ID、店铺名、客户备注，
只有 session_token 和 IP。这就是“只存结论，不存关联”的落地。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    ip_int        INTEGER NOT NULL,
    scanned_at    TEXT NOT NULL,
    score         INTEGER,
    grade         TEXT,
    residence     TEXT,
    asn           INTEGER,
    asn_org       TEXT,
    asn_type      TEXT,
    country       TEXT,
    city          TEXT,
    timezone      TEXT,
    rdns          TEXT,
    raw           TEXT,
    duration_ms   INTEGER,
    probe_id      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scan_ip ON scan(ip);

CREATE TABLE IF NOT EXISTS dnsbl_hit (
    scan_id       INTEGER,
    zone          TEXT,
    return_code   TEXT,
    severity      INTEGER,
    PRIMARY KEY (scan_id, zone)
);

CREATE TABLE IF NOT EXISTS probe (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT UNIQUE,
    created_at    TEXT,
    received_at   TEXT,
    ip_seen       TEXT,
    payload       TEXT,
    tz            TEXT,
    lang          TEXT,
    platform      TEXT,
    webrtc_ips    TEXT,
    dns_leak      INTEGER,
    canvas_hash   TEXT
);

CREATE TABLE IF NOT EXISTS monitor (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    label         TEXT,
    interval_min  INTEGER DEFAULT 360,
    last_run      TEXT,
    last_score    INTEGER,
    alert_score   INTEGER DEFAULT 70,
    webhook       TEXT,
    enabled       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alert_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id    INTEGER,
    fired_at      TEXT,
    old_score     INTEGER,
    new_score     INTEGER,
    reason        TEXT,
    delivered     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS customer (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    api_token     TEXT UNIQUE,           -- 客户身份，仅此一个凭据，不存任何真实身份信息
    plan          TEXT,                  -- basic(200 IP) / pro(2000 IP)
    scan_quota    INTEGER DEFAULT 200,   -- 本计费周期可扫 IP 数
    scans_used    INTEGER DEFAULT 0,
    created_at    TEXT
);
"""


def ip_to_int(ip: str) -> int:
    import ipaddress
    return int(ipaddress.ip_address(ip))


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self):
        self._conn.close()

    # ---- scan ----

    def save_scan(self, rep, obs_raw: str, duration_ms: int, probe_id: int | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scan(ip, ip_int, scanned_at, score, grade, residence, asn,"
                " asn_org, asn_type, country, city, timezone, rdns, raw, duration_ms, probe_id)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rep.ip, ip_to_int(rep.ip), rep.scanned_at, rep.score, rep.grade,
                 rep.residence, rep.raw.get("asn"), rep.raw.get("asn_org", ""),
                 rep.raw.get("asn_type", ""), rep.raw.get("country", ""),
                 rep.raw.get("city", ""), rep.raw.get("timezone", ""),
                 rep.raw.get("rdns"), obs_raw, duration_ms, probe_id))
            sid = cur.lastrowid
            for h in rep.raw.get("dnsbl", []):
                if h.get("status") == "hit":
                    self._conn.execute(
                        "INSERT OR REPLACE INTO dnsbl_hit VALUES(?,?,?,?)",
                        (sid, h["zone"], ",".join(h.get("codes", [])), h.get("severity", 0)))
            self._conn.commit()
            return sid

    def get_scan(self, scan_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM scan WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self, limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, ip, scanned_at, score, grade, residence, country FROM scan"
            " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---- probe ----

    def create_probe_session(self) -> str:
        import secrets
        token = secrets.token_urlsafe(16)
        with self._lock:
            self._conn.execute(
                "INSERT INTO probe(session_token, created_at) VALUES(?,?)",
                (token, time.strftime("%Y-%m-%dT%H:%M:%S%z")))
            self._conn.commit()
        return token

    def save_probe(self, token: str, ip_seen: str, payload: dict) -> int | None:
        row = self._conn.execute(
            "SELECT id FROM probe WHERE session_token=?", (token,)).fetchone()
        if not row:
            return None
        with self._lock:
            self._conn.execute(
                "UPDATE probe SET received_at=?, ip_seen=?, payload=?, tz=?, lang=?,"
                " platform=?, webrtc_ips=?, dns_leak=?, canvas_hash=? WHERE id=?",
                (time.strftime("%Y-%m-%dT%H:%M:%S%z"), ip_seen,
                 json.dumps(payload, ensure_ascii=False),
                 payload.get("tz", ""), payload.get("lang", ""),
                 payload.get("platform", ""),
                 json.dumps(payload.get("webrtc_ips", [])),
                 1 if payload.get("dns_leak") else 0,
                 payload.get("canvas_hash", ""), row["id"]))
            self._conn.commit()
        return row["id"]

    def get_probe(self, token: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM probe WHERE session_token=?", (token,)).fetchone()
        return dict(row) if row else None

    # ---- monitor ----

    def add_monitor(self, ip: str, label: str, interval_min: int,
                    alert_score: int, webhook: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO monitor(ip, label, interval_min, alert_score, webhook)"
                " VALUES(?,?,?,?,?)", (ip, label, interval_min, alert_score, webhook))
            self._conn.commit()
            return cur.lastrowid

    def list_monitors(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM monitor WHERE enabled=1").fetchall()
        return [dict(r) for r in rows]

    def due_monitors(self, now: float) -> list[dict]:
        out = []
        for m in self.list_monitors():
            last = m["last_run"] or ""
            try:
                lt = time.mktime(time.strptime(last[:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                lt = 0
            if now - lt >= m["interval_min"] * 60:
                out.append(m)
        return out

    def update_monitor_run(self, monitor_id: int, score: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE monitor SET last_run=?, last_score=? WHERE id=?",
                (time.strftime("%Y-%m-%dT%H:%M:%S%z"), score, monitor_id))
            self._conn.commit()

    def add_alert(self, monitor_id: int, old: int, new: int, reason: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alert_log(monitor_id, fired_at, old_score, new_score, reason)"
                " VALUES(?,?,?,?,?)",
                (monitor_id, time.strftime("%Y-%m-%dT%H:%M:%S%z"), old, new, reason))
            self._conn.commit()

    # ---- customer（订阅制多客户，P2）----

    def create_customer(self, plan: str = "basic") -> tuple[int, str]:
        import secrets
        plan = plan if plan in ("basic", "pro") else "basic"
        quota = 200 if plan == "basic" else 2000
        token = "ipk_" + secrets.token_urlsafe(24)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO customer(api_token, plan, scan_quota, scans_used, created_at)"
                " VALUES(?,?,?,0,?)",
                (token, plan, quota, time.strftime("%Y-%m-%dT%H:%M:%S%z")))
            self._conn.commit()
            return cur.lastrowid, token

    def get_customer_by_token(self, token: str) -> dict | None:
        if not token or not token.startswith("ipk_"):
            return None
        row = self._conn.execute(
            "SELECT * FROM customer WHERE api_token=?", (token,)).fetchone()
        return dict(row) if row else None

    def consume_quota(self, customer_id: int) -> bool:
        """配额内返回 True 并 +1；超配额返回 False。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT scan_quota, scans_used FROM customer WHERE id=?",
                (customer_id,)).fetchone()
            if not row or row["scans_used"] >= row["scan_quota"]:
                return False
            self._conn.execute(
                "UPDATE customer SET scans_used=scans_used+1 WHERE id=?", (customer_id,))
            self._conn.commit()
            return True
