"""冻结结论的 SQLite 持久化（按稳定审计标识重开）。

除裁决结论外，另存提交时的原始输入描述（名称与成组标签，**不含二进制数据**），
供修复建议接口核对「重放输入与原冻结输入一致」。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import List, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id      TEXT PRIMARY KEY,
    status        TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    source_inputs TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
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
        self._conn.execute(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """为早于 source_inputs 列的库补充该列（旧结论视为不可重放）。"""
        cols = {
            r[1]
            for r in self._conn.execute("PRAGMA table_info(audits)").fetchall()
        }
        if "source_inputs" not in cols:
            self._conn.execute(
                "ALTER TABLE audits ADD COLUMN source_inputs TEXT"
            )

    def save(self, audit_id: str, verdict: dict,
             source_inputs: Optional[List[dict]] = None) -> bool:
        """冻结结论。返回 True 表示新建，False 表示该标识已冻结。"""
        payload = json.dumps(verdict, ensure_ascii=False, separators=(",", ":"))
        source = (
            json.dumps(source_inputs, ensure_ascii=False, separators=(",", ":"))
            if source_inputs is not None
            else None
        )
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO audits(audit_id, status, verdict, source_inputs) "
                "VALUES (?, ?, ?, ?)",
                (audit_id, verdict["status"], payload, source),
            )
            return cur.rowcount == 1

    def get(self, audit_id: str) -> Optional[dict]:
        return (self.get_with_source(audit_id) or (None, None))[0]

    def get_with_source(
        self, audit_id: str
    ) -> Optional[Tuple[dict, Optional[List[dict]]]]:
        """返回 (冻结结论, 原输入描述)；旧结论或缺失时原输入描述为 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict, source_inputs FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
        if not row:
            return None
        verdict = json.loads(row[0])
        source = json.loads(row[1]) if row[1] is not None else None
        return verdict, source

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
