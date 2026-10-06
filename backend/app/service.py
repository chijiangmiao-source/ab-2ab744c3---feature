"""审计服务：解码输入、判定 ELF/ar、运行链接裁决，并冻结结论。"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import List, Optional

from .elfparser import (
    AR_MAGIC,
    ELFMAG,
    ParseError,
    parse_ar,
    parse_elf_object,
)
from .linker import InputUnit, LinkError, Resolver

MAX_INPUTS = 12
MAX_TOTAL_BYTES = 16 * 1024 * 1024
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,127}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

class AuditRejected(Exception):
    """审计被拒绝；携带机器码、首触发位置与证据。"""

    def __init__(self, code: str, message: str, location: str,
                 evidence: Optional[dict] = None, http_status: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.location = location
        self.evidence = evidence or {}
        self.http_status = http_status


@dataclass
class InputPayload:
    position: int
    name: str
    blob: bytes
    group: Optional[str] = None


def _decode_b64(position: int, name: str, data: str) -> bytes:
    if not isinstance(data, str) or not data:
        raise AuditRejected(
            "EMPTY_INPUT", f"输入#{position} {name} 的数据为空",
            f"输入#{position} {name}",
        )
    compact = "".join(data.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuditRejected(
            "INVALID_BASE64",
            f"输入#{position} {name} 不是合法 Base64: {exc}",
            f"输入#{position} {name}",
            {"detail": str(exc)},
        )


def validate_request(audit_id: str, raw_inputs: list) -> List[InputPayload]:
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id or ""):
        raise AuditRejected(
            "INVALID_AUDIT_ID",
            "稳定审计标识须为 1-64 位字母数字及 ._-，且以字母数字开头",
            "audit_id",
        )
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise AuditRejected(
            "NO_INPUTS", "至少需要一个链接输入", "inputs", http_status=400
        )
    if len(raw_inputs) > MAX_INPUTS:
        raise AuditRejected(
            "TOO_MANY_INPUTS",
            f"至多 {MAX_INPUTS} 个输入，收到 {len(raw_inputs)} 个",
            f"inputs[{MAX_INPUTS}]",
            {"limit": MAX_INPUTS, "received": len(raw_inputs)},
        )

    payloads: List[InputPayload] = []
    total = 0
    seen_groups: dict = {}
    for i, item in enumerate(raw_inputs, start=1):
        if not isinstance(item, dict):
            raise AuditRejected(
                "MALFORMED_INPUT", f"输入#{i} 必须是对象", f"inputs[{i - 1}]"
            )
        name = item.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise AuditRejected(
                "INVALID_NAME",
                f"输入#{i} 名称不合法（1-128 位文件名字符）",
                f"inputs[{i - 1}].name",
            )
        group = item.get("group")
        if group is not None:
            if not isinstance(group, str) or not GROUP_RE.match(group):
                raise AuditRejected(
                    "INVALID_GROUP",
                    f"输入#{i} 成组标签不合法",
                    f"inputs[{i - 1}].group",
                )
            if group in seen_groups and seen_groups[group] != i - 1:
                # 组成员必须连续出现（对应 --start-group ... --end-group）。
                prev = seen_groups[group]
                if prev != i - 2:
                    raise AuditRejected(
                        "NON_CONTIGUOUS_GROUP",
                        f"成组归档 {group!r} 的成员必须在命令行中连续排列",
                        f"inputs[{i - 1}].group",
                        {"group": group, "first_position": prev + 1},
                    )
            seen_groups[group] = i - 1

        blob = _decode_b64(i, name, item.get("data_b64", ""))
        if not blob:
            raise AuditRejected(
                "EMPTY_INPUT", f"输入#{i} {name} 解码后为 0 字节",
                f"输入#{i} {name}",
            )
        total += len(blob)
        if total > MAX_TOTAL_BYTES:
            raise AuditRejected(
                "PAYLOAD_TOO_LARGE",
                f"输入总字节超过 {MAX_TOTAL_BYTES} 字节上限",
                f"inputs[{i - 1}]",
                {"limit": MAX_TOTAL_BYTES},
                http_status=413,
            )
        payloads.append(InputPayload(i, name, blob, group))

    return payloads


def _sniff(blob: bytes) -> str:
    if blob[:4] == ELFMAG:
        return "elf"
    if blob[:8] == AR_MAGIC:
        return "ar"
    return "unknown"


def _build_units(payloads: List[InputPayload]):
    """把解码后的输入解析为链接单元与输入记录；违例抛 AuditRejected。"""
    units: List[InputUnit] = []
    input_records = []
    for p in payloads:
        kind = _sniff(p.blob)
        record = {
            "position": p.position,
            "name": p.name,
            "group": p.group,
            "bytes": len(p.blob),
            "kind": kind,
        }
        try:
            if kind == "unknown":
                raise AuditRejected(
                    "ILLEGAL_MEMBER",
                    f"输入#{p.position} {p.name} 既非 ELF 也非 ar 归档"
                    f"（头部 {p.blob[:8]!r}）",
                    f"输入#{p.position} {p.name} byte 0",
                    {"magic": p.blob[:8].hex(), "input": record},
                )
            if kind == "elf":
                obj = parse_elf_object(p.blob, f"输入#{p.position} {p.name}")
                record["symbols"] = len(obj.symbols)
                units.append(InputUnit(p.position, p.name, "object", obj=obj,
                                       group=p.group))
            else:
                archive = parse_ar(p.blob, f"输入#{p.position} {p.name}")
                record["members"] = [
                    {"name": m.name, "symbols": len(m.parsed.symbols)}
                    for m in archive.member_order
                ]
                record["index_symbols"] = len(archive.symbol_index)
                units.append(InputUnit(p.position, p.name, "archive",
                                       archive=archive, group=p.group))
        except ParseError as exc:
            raise AuditRejected(
                "CORRUPT_BINARY",
                exc.message,
                exc.where or f"输入#{p.position} {p.name}",
                {"input": record, **exc.evidence},
            )
        input_records.append(record)
    return units, input_records


def audit(audit_id: str, raw_inputs: list) -> dict:
    """执行完整审计；任何违例抛 AuditRejected。返回可冻结的结论字典。"""
    payloads = validate_request(audit_id, raw_inputs)

    def reject_verdict(exc: AuditRejected) -> dict:
        return {
            "audit_id": audit_id,
            "status": "rejected",
            "error": {
                "code": exc.code,
                "message": exc.message,
                "location": exc.location,
                "evidence": exc.evidence,
            },
            "inputs": input_records,
            "extraction_order": getattr(resolver, "extraction_log", []),
            "rounds": getattr(resolver, "round_log", []),
            "resolutions": getattr(resolver, "resolutions", []),
        }

    units: List[InputUnit] = []
    input_records = []
    resolver: Optional[Resolver] = None
    try:
        units, input_records = _build_units(payloads)
        resolver = Resolver(units=units)
        result = resolver.run()
    except AuditRejected as exc:
        return reject_verdict(exc)
    except LinkError as exc:
        return {
            "audit_id": audit_id,
            "status": "rejected",
            "error": {
                "code": exc.code,
                "message": exc.message,
                "location": exc.location,
                "evidence": exc.evidence,
            },
            "inputs": input_records,
            "extraction_order": resolver.extraction_log if resolver else [],
            "rounds": resolver.round_log if resolver else [],
            "resolutions": resolver.resolutions if resolver else [],
        }

    return {
        "audit_id": audit_id,
        "status": "accepted",
        "error": None,
        "inputs": input_records,
        **result,
    }


# --------------------------------------------------------------------------- #
# 修复建议：枚举相邻未分组归档段，按既有成组语义重放裁决
# --------------------------------------------------------------------------- #
FIX_GROUP_BASE = "FIXG"


def _candidate_segments(units: List[InputUnit]):
    """全部候选段：两个及以上连续、未分组的普通归档。

    返回按 (段长, 起始下标) 升序的 [start, end)（0 基下标）区间列表，
    保证最短段优先、等长按起始输入位置稳定选择。
    """
    n = len(units)
    plain = [u.kind == "archive" and not u.group for u in units]
    segments = []
    i = 0
    while i < n:
        if not plain[i]:
            i += 1
            continue
        j = i
        while j + 1 < n and plain[j + 1]:
            j += 1
        # [i, j] 为一段极大的连续未分组归档
        for length in range(2, j - i + 2):
            for start in range(i, j - length + 2):
                segments.append((start, start + length))
        i = j + 1
    segments.sort(key=lambda seg: (seg[1] - seg[0], seg[0]))
    return segments


def _fresh_group_label(units: List[InputUnit]) -> str:
    used = {u.group for u in units if u.group}
    label = FIX_GROUP_BASE
    n = 1
    while label in used:
        n += 1
        label = f"{FIX_GROUP_BASE}{n}"
    return label


def _segment_record(units: List[InputUnit], start: int, end: int) -> dict:
    return {
        "start_position": units[start].position,
        "end_position": units[end - 1].position,
        "length": end - start,
        "archives": [
            {"position": u.position, "name": u.name} for u in units[start:end]
        ],
    }


def suggest_group_fix(audit_id: str, verdict: dict,
                      raw_inputs: Optional[list]) -> dict:
    """基于原冻结输入枚举候选段并重放裁决；不改动任何冻结结论。

    仅接受原拒绝原因为最终未定义（UNDEFINED_SYMBOL）且输入仍可重放的审计。
    返回可使裁决通过的最短段（等长按起始输入位置稳定选择）。
    """
    error = verdict.get("error") or {}
    if verdict.get("status") != "rejected" or error.get("code") != "UNDEFINED_SYMBOL":
        raise AuditRejected(
            "NOT_UNDEFINED_REJECTION",
            "修复建议仅适用于因最终未定义符号（UNDEFINED_SYMBOL）被拒绝的"
            f"冻结审计；该审计状态为 {verdict.get('status')!r}"
            + (f"，拒绝码 {error.get('code')!r}" if error else ""),
            f"audit_id={audit_id}",
            {"status": verdict.get("status"), "code": error.get("code")},
            http_status=409,
        )
    if raw_inputs is None:
        raise AuditRejected(
            "INPUTS_NOT_REPLAYABLE",
            "该冻结结论未留存原始输入字节（功能上线前冻结），无法按原输入重放",
            f"audit_id={audit_id}",
            http_status=409,
        )

    try:
        payloads = validate_request(audit_id, raw_inputs)
        units, _records = _build_units(payloads)
    except AuditRejected as exc:
        raise AuditRejected(
            "INPUTS_NOT_REPLAYABLE",
            f"原冻结输入已无法重放：{exc.message}",
            exc.location,
            {"rejected_code": exc.code},
            http_status=409,
        )

    original_undefined = sorted((error.get("evidence") or {}).get("undefined") or [])
    segments = _candidate_segments(units)
    candidates = []
    duplicate_strong_seen = False

    for start, end in segments:
        label = _fresh_group_label(units)
        trial = [
            InputUnit(u.position, u.name, u.kind, obj=u.obj, archive=u.archive,
                      group=label if start <= idx < end else u.group)
            for idx, u in enumerate(units)
        ]
        resolver = Resolver(units=trial)
        segment = _segment_record(units, start, end)
        try:
            result = resolver.run()
        except LinkError as exc:
            duplicate_strong_seen = (
                duplicate_strong_seen or exc.code == "DUPLICATE_STRONG"
            )
            candidates.append({
                "segment": segment,
                "group": label,
                "outcome": "rejected",
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "location": exc.location,
                },
            })
            continue
        # 首个成功即最短段（候选已按段长、起始位置排序）
        return {
            "audit_id": audit_id,
            "status": "suggested",
            "suggestion": {
                "segment": segment,
                "group": label,
                "resolved_undefined": original_undefined,
                "extraction_order": result["extraction_order"],
                "rounds": result["rounds"],
                "final_undefined": result["final_undefined"],
            },
            "candidates_checked": len(candidates) + 1,
            "frozen_verdict_untouched": True,
        }

    if not segments:
        reason = {
            "code": "NO_CANDIDATE_SEGMENT",
            "message": "输入中不存在两个及以上连续、未分组的 GNU ar 归档，"
                       "没有可成组重放的候选段",
        }
    elif duplicate_strong_seen:
        reason = {
            "code": "DUPLICATE_STRONG_IN_REPLAY",
            "message": "候选段按成组语义重放时出现重复强定义，"
                       "没有可使裁决通过的成组段",
        }
    else:
        reason = {
            "code": "NO_FEASIBLE_SEGMENT",
            "message": "全部候选段重放后仍残留未定义符号，"
                       "没有可使裁决通过的成组段",
        }
    return {
        "audit_id": audit_id,
        "status": "no_suggestion",
        "reason": reason,
        "candidates": candidates,
        "frozen_verdict_untouched": True,
    }
