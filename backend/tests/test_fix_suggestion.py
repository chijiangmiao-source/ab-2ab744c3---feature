"""修复建议测试：候选段枚举、最短段稳定选择、明确原因与冻结结论不可变。"""
from __future__ import annotations

import copy

import pytest

from app.fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar
from app.service import AuditRejected, audit, suggest_group_fix


def _obj(spec: ObjSpec, group=None) -> dict:
    return {
        "name": spec.name + ".o",
        "data_b64": b64(build_elf64_rel(spec)),
        "group": group,
    }


def _ar(name: str, specs, group=None) -> dict:
    return {
        "name": name + ".a",
        "data_b64": b64(build_gnu_ar(name, specs)),
        "group": group,
    }


def _cycle_inputs():
    """main→a；libX: amem(a→c)、bmem(b)；libY: cmem(c→b)。普通顺序残留 b。"""
    return [
        _obj(ObjSpec("main", undefined=["a"])),
        _ar("libX", [ObjSpec("amem", strong=["a"], undefined=["c"]),
                     ObjSpec("bmem", strong=["b"])]),
        _ar("libY", [ObjSpec("cmem", strong=["c"], undefined=["b"])]),
    ]


def _rejected(audit_id: str, inputs) -> dict:
    verdict = audit(audit_id, inputs)
    assert verdict["status"] == "rejected"
    assert verdict["error"]["code"] == "UNDEFINED_SYMBOL"
    return verdict


# --------------------------------------------------------------------------- #
def test_cross_archive_cycle_yields_unique_shortest_segment():
    inputs = _cycle_inputs()
    verdict = _rejected("FIX-CYCLE-1", inputs)
    frozen_before = copy.deepcopy(verdict)

    res = suggest_group_fix("FIX-CYCLE-1", verdict, inputs)

    assert res["status"] == "suggested"
    seg = res["suggestion"]["segment"]
    assert (seg["start_position"], seg["end_position"], seg["length"]) == (2, 3, 2)
    assert [a["name"] for a in seg["archives"]] == ["libX.a", "libY.a"]
    assert res["suggestion"]["resolved_undefined"] == ["b"]
    members = [(e["archive"], e["member"])
               for e in res["suggestion"]["extraction_order"]]
    assert ("libX.a", "amem.o") in members
    assert ("libY.a", "cmem.o") in members
    assert ("libX.a", "bmem.o") in members
    assert res["suggestion"]["final_undefined"] == []
    # 只读：原冻结结论未被改写
    assert verdict == frozen_before


def test_shortest_segment_wins_and_ties_break_by_start_position():
    # 三个连续未分组归档：仅 (libA,libB) 成组可闭合（b 由 libA 后向成员提供）；
    # 更长的 (libA,libB,libC) 也能闭合但不应被选中。
    inputs = [
        _obj(ObjSpec("main", undefined=["a"])),
        _ar("libA", [ObjSpec("amem", strong=["a"], undefined=["c"]),
                     ObjSpec("bmem", strong=["b"])]),
        _ar("libB", [ObjSpec("cmem", strong=["c"], undefined=["b"])]),
        _ar("libC", [ObjSpec("unused", strong=["zz"])]),
    ]
    verdict = _rejected("FIX-SHORT-1", inputs)
    res = suggest_group_fix("FIX-SHORT-1", verdict, inputs)
    assert res["status"] == "suggested"
    seg = res["suggestion"]["segment"]
    assert (seg["start_position"], seg["end_position"]) == (2, 3)
    assert seg["length"] == 2
    assert res["candidates_checked"] == 1


def test_no_feasible_segment_reports_clear_reason():
    inputs = [
        _obj(ObjSpec("main", undefined=["ghost"])),
        _ar("libA", [ObjSpec("pa", strong=["pa"])]),
        _ar("libB", [ObjSpec("pb", strong=["pb"])]),
    ]
    verdict = _rejected("FIX-NONE-1", inputs)
    res = suggest_group_fix("FIX-NONE-1", verdict, inputs)
    assert res["status"] == "no_suggestion"
    assert res["reason"]["code"] == "NO_FEASIBLE_SEGMENT"
    assert res["candidates"][0]["error"]["code"] == "UNDEFINED_SYMBOL"


def test_duplicate_strong_in_candidate_replay_reports_clear_reason():
    # 原始顺序残留 x 未定义；libX+libY 成组后 xmem 被抽取，
    # 其强定义 d 与 libY 已抽取 dmem 的 d 冲突。
    inputs = [
        _obj(ObjSpec("main", undefined=["a"])),
        _ar("libX", [ObjSpec("amem", strong=["a"], undefined=["c"]),
                     ObjSpec("xmem", strong=["x", "d"])]),
        _ar("libY", [ObjSpec("cmem", strong=["c"], undefined=["x", "e"]),
                     ObjSpec("dmem", strong=["e", "d"])]),
    ]
    verdict = _rejected("FIX-DUP-1", inputs)
    assert verdict["error"]["evidence"]["undefined"] == ["x"]

    res = suggest_group_fix("FIX-DUP-1", verdict, inputs)
    assert res["status"] == "no_suggestion"
    assert res["reason"]["code"] == "DUPLICATE_STRONG_IN_REPLAY"
    assert res["candidates"][0]["error"]["code"] == "DUPLICATE_STRONG"


def test_no_candidate_segment_when_archives_not_adjacent_or_grouped():
    inputs = [
        _obj(ObjSpec("main", undefined=["ghost"])),
        _ar("libA", [ObjSpec("pa", strong=["pa"])]),
    ]
    verdict = _rejected("FIX-NOCAND-1", inputs)
    res = suggest_group_fix("FIX-NOCAND-1", verdict, inputs)
    assert res["status"] == "no_suggestion"
    assert res["reason"]["code"] == "NO_CANDIDATE_SEGMENT"
    assert res["candidates"] == []


def test_non_undefined_rejection_is_refused():
    accepted = audit("FIX-ACC-1", [
        _obj(ObjSpec("m", undefined=["fa"])),
        _ar("lib", [ObjSpec("a", strong=["fa"])]),
    ])
    assert accepted["status"] == "accepted"
    with pytest.raises(AuditRejected) as ei:
        suggest_group_fix("FIX-ACC-1", accepted, None)
    assert ei.value.code == "NOT_UNDEFINED_REJECTION"
    assert ei.value.http_status == 409

    dup = audit("FIX-DUPREJ-1", [
        _obj(ObjSpec("x", strong=["d"])),
        _obj(ObjSpec("y", strong=["d"])),
    ])
    assert dup["error"]["code"] == "DUPLICATE_STRONG"
    with pytest.raises(AuditRejected) as ei2:
        suggest_group_fix("FIX-DUPREJ-1", dup, [
            _obj(ObjSpec("x", strong=["d"])),
            _obj(ObjSpec("y", strong=["d"])),
        ])
    assert ei2.value.code == "NOT_UNDEFINED_REJECTION"


def test_missing_replay_inputs_is_refused():
    verdict = _rejected("FIX-NOINPUT-1", _cycle_inputs())
    with pytest.raises(AuditRejected) as ei:
        suggest_group_fix("FIX-NOINPUT-1", verdict, None)
    assert ei.value.code == "INPUTS_NOT_REPLAYABLE"
    assert ei.value.http_status == 409


def test_group_label_does_not_collide_with_existing_labels():
    inputs = [
        _obj(ObjSpec("main", undefined=["a"])),
        _ar("libX", [ObjSpec("amem", strong=["a"], undefined=["c"]),
                     ObjSpec("bmem", strong=["b"])]),
        _ar("libY", [ObjSpec("cmem", strong=["c"], undefined=["b"])]),
        _ar("libZ", [ObjSpec("zmem", strong=["zz"])], group="FIXG"),
    ]
    verdict = _rejected("FIX-LABEL-1", inputs)
    res = suggest_group_fix("FIX-LABEL-1", verdict, inputs)
    assert res["status"] == "suggested"
    assert res["suggestion"]["group"] != "FIXG"
