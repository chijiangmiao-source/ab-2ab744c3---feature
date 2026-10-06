"""冻结结论的 SQLite 持久化（按稳定审计标识重开）。"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id   TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
-- 原始提交输入（Base64）随冻结一并留存，仅供修复建议重放；
-- 与冻结结论分离，按标识重开的结论内容不受影响。
CREATE TABLE IF NOT EXISTS audit_inputs (
    audit_id   TEXT PRIMARY KEY,
    inputs     TEXT NOT NULL
);
"""


class AuditStore:
    def __init__(self, path: str):
        self._path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(SCHEMA)

    def save(self, audit_id: str, verdict: dict,
             inputs: Optional[list] = None) -> bool:
        """冻结结论。返回 True 表示新建，False 表示该标识已冻结。

        inputs 为原始提交输入（含 Base64 数据），仅在新建冻结时一并留存，
        供修复建议按原冻结输入重放；已冻结标识的 inputs 同样不被覆盖。
        """
        payload = json.dumps(verdict, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO audits(audit_id, status, verdict) "
                "VALUES (?, ?, ?)",
                (audit_id, verdict["status"], payload),
            )
            created = cur.rowcount == 1
            if created and inputs is not None:
                self._conn.execute(
                    "INSERT OR IGNORE INTO audit_inputs(audit_id, inputs) "
                    "VALUES (?, ?)",
                    (audit_id,
                     json.dumps(inputs, ensure_ascii=False,
                                separators=(",", ":"))),
                )
            return created

    def get(self, audit_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict FROM audits WHERE audit_id = ?", (audit_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def get_inputs(self, audit_id: str) -> Optional[list]:
        """返回冻结时留存的原始输入；无留存（旧结论）时返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT inputs FROM audit_inputs WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ids(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT audit_id, status, created_at FROM audits "
                "ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
        return [
            {"audit_id": a, "status": s, "created_at": t} for a, s, t in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
