#!/usr/bin/env python3
"""verify 服务一次性入口：

1. 解析规则测试（pytest，覆盖 ELF/ar 字节级校验）；
2. 前端构建检查（vite build）；
3. 归档闭合 API/HTTP 冒烟（健康端点、提交、拒绝、冻结重开）。

任一步失败即以非零退出码结束，并在最后打印汇总。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import os

BACKEND_URL = os.environ.get("AUDIT_BACKEND_URL", "http://backend:8000").rstrip("/")
ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"

# 每次运行使用唯一标识后缀，避免复跑命中既有冻结结论（409）。
RUN_TAG = os.environ.get("VERIFY_RUN_TAG") or str(int(time.time()))


def _tag(prefix: str) -> str:
    return f"{prefix}-{RUN_TAG}"

results: list[tuple[str, bool, str]] = []


def step(name: str):
    def deco(fn):
        def wrapped():
            print(f"\n=== verify: {name} ===", flush=True)
            try:
                detail = fn() or "通过"
                results.append((name, True, detail))
                print(f"[PASS] {name}: {detail}", flush=True)
            except Exception as exc:  # noqa: BLE001
                results.append((name, False, str(exc)))
                print(f"[FAIL] {name}: {exc}", flush=True)
        return wrapped
    return deco


def run(cmd: list[str], cwd: Path, timeout: int = 300) -> str:
    proc = subprocess.run(
        cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-25:])
        raise AssertionError(
            f"命令 {' '.join(cmd)} 退出码 {proc.returncode}\n{tail}"
        )
    return proc.stdout + proc.stderr


@step("解析规则测试 pytest")
def _parser_tests() -> str:
    out = run([sys.executable, "-m", "pytest", "tests", "-q"], BACKEND)
    line = next((l for l in reversed(out.splitlines()) if "passed" in l), out[-200:])
    return line.strip()


@step("前端构建检查 vite build")
def _frontend_build() -> str:
    if not (FRONTEND / "node_modules").exists():
        run(["npm", "install", "--no-audit", "--no-fund"], FRONTEND, timeout=600)
    out = run(["npm", "run", "build"], FRONTEND, timeout=300)
    line = next((l for l in out.splitlines() if "built in" in l), "构建完成")
    return line.strip()


def _request(method: str, path: str, payload=None, timeout: int = 10):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BACKEND_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _wait_health(deadline_s: int = 60) -> None:
    start = time.time()
    last = ""
    while time.time() - start < deadline_s:
        try:
            status, body = _request("GET", "/health", timeout=3)
            if status == 200 and body.get("status") == "ok":
                return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        time.sleep(1)
    raise AssertionError(f"后端健康端点在 {deadline_s}s 内不可用: {last}")


@step("健康端点 GET /health")
def _health() -> str:
    _wait_health()
    _, body = _request("GET", "/health")
    return f"status={body['status']}"


@step("冒烟：成组循环依赖闭合（accepted）")
def _grouped_cycle() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    demo["audit_id"] = _tag("VERIFY-GROUP")
    status, body = _request("POST", "/api/audits", demo)
    if status != 201 or body["status"] != "accepted":
        raise AssertionError(f"status={status} body={json.dumps(body, ensure_ascii=False)[:600]}")
    members = [(e["archive"], e["member"]) for e in body["extraction_order"]]
    if len(members) != 3:
        raise AssertionError(f"期望抽取 3 个成员，实际 {members}")
    rounds = [r for r in body["rounds"] if r["scope"] == "group"]
    if rounds[-1]["changed"] is not False:
        raise AssertionError("组扫描最终一轮应收敛 changed=false")
    return f"抽取 {[m[1] for m in members]}，{len(rounds)} 轮收敛"


@step("冒烟：不成组循环依赖残留未定义（rejected）")
def _ungrouped_cycle() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    demo["audit_id"] = _tag("VERIFY-NOGROUP")
    for item in demo["inputs"]:
        item["group"] = None
    status, body = _request("POST", "/api/audits", demo)
    if status != 422 or body["status"] != "rejected":
        raise AssertionError(f"status={status} body={json.dumps(body)[:500]}")
    err = body["error"]
    if err["code"] != "UNDEFINED_SYMBOL" or err["evidence"]["undefined"] != ["b"]:
        raise AssertionError(f"期望残留 b 未定义，实际 {err}")
    return f"{err['code']} @ {err['location']}"


@step("冒烟：重复强定义拒绝（DUPLICATE_STRONG）")
def _duplicate_strong() -> str:
    sys.path.insert(0, str(BACKEND))
    from app.fixtures import ObjSpec, b64, build_elf64_rel
    payload = {
        "audit_id": _tag("VERIFY-DUP"),
        "inputs": [
            {"name": "m.o", "data_b64": b64(build_elf64_rel(ObjSpec("m", undefined=["d"])))},
            {"name": "x.o", "data_b64": b64(build_elf64_rel(ObjSpec("x", strong=["d"])))},
            {"name": "y.o", "data_b64": b64(build_elf64_rel(ObjSpec("y", strong=["d"])))},
        ],
    }
    status, body = _request("POST", "/api/audits", payload)
    if status != 422 or body["error"]["code"] != "DUPLICATE_STRONG":
        raise AssertionError(f"status={status} body={json.dumps(body)[:500]}")
    loc = body["error"]["location"]
    if "输入#3" not in loc:
        raise AssertionError(f"首次触发位置应指向输入#3，实际 {loc}")
    return loc


@step("冒烟：损坏归档索引拒绝（CORRUPT_BINARY）")
def _corrupt_index() -> str:
    from app.fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar
    bad = build_gnu_ar("lib", [ObjSpec("a", strong=["fa", "secret"])],
                       defined_index={"fa": "a.o"})
    payload = {
        "audit_id": _tag("VERIFY-BADAR"),
        "inputs": [
            {"name": "m.o", "data_b64": b64(build_elf64_rel(ObjSpec("m", undefined=["fa"])))},
            {"name": "lib.a", "data_b64": b64(bad)},
        ],
    }
    status, body = _request("POST", "/api/audits", payload)
    if status != 422 or body["error"]["code"] != "CORRUPT_BINARY":
        raise AssertionError(f"status={status} body={json.dumps(body)[:500]}")
    return body["error"]["location"]


@step("冒烟：冻结结论按标识重开（GET 409→200）")
def _freeze_reopen() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    fid = _tag("VERIFY-FREEZE"); demo["audit_id"] = fid
    s1, b1 = _request("POST", "/api/audits", demo)
    if s1 != 201:
        raise AssertionError(f"首次提交应 201，实际 {s1}")
    # 篡改输入后重提：不得覆盖冻结结论
    demo["inputs"] = demo["inputs"][:1]
    s2, b2 = _request("POST", "/api/audits", demo)
    if s2 != 409 or b2.get("status") != "accepted":
        raise AssertionError(f"重复标识应 409 返回冻结结论，实际 {s2} {b2.get('status')}")
    s3, b3 = _request("GET", f"/api/audits/{fid}")
    if s3 != 200 or len(b3.get("extraction_order", [])) != 3:
        raise AssertionError("重开冻结结论内容与首次不一致")
    return "201 → 409(冻结) → 200(重开)"


def _post_ungrouped_cycle(prefix: str):
    """跨归档循环、全部去组：原裁决残留 b 未定义。返回 (audit_id, 冻结结论)。"""
    _, demo = _request("GET", "/api/demo/cycle")
    demo["audit_id"] = _tag(prefix)
    for item in demo["inputs"]:
        item["group"] = None
    status, body = _request("POST", "/api/audits", demo)
    if status != 422 or body["error"]["code"] != "UNDEFINED_SYMBOL":
        raise AssertionError(f"前置拒绝构造失败: status={status} {json.dumps(body)[:400]}")
    return demo["audit_id"], body


@step("修复建议：跨归档循环拒绝取得唯一最短段")
def _fix_suggestion_unique() -> str:
    fid, frozen = _post_ungrouped_cycle("VERIFY-FIX")
    status, body = _request("GET", f"/api/audits/{fid}/fix-suggestion")
    if status != 200 or body.get("status") != "suggested":
        raise AssertionError(f"期望唯一建议，实际 status={status} {json.dumps(body, ensure_ascii=False)[:500]}")
    seg = body["suggestion"]["segment"]
    if (seg["start_position"], seg["end_position"], seg["length"]) != (2, 3, 2):
        raise AssertionError(f"段首尾应为 2→3，实际 {seg}")
    if [a["name"] for a in seg["archives"]] != ["libX.a", "libY.a"]:
        raise AssertionError(f"段内归档不符: {seg['archives']}")
    if body["suggestion"]["resolved_undefined"] != ["b"]:
        raise AssertionError(f"消失的未定义集合应为 [b]，实际 {body['suggestion']['resolved_undefined']}")
    if len(body["suggestion"]["extraction_order"]) != 3:
        raise AssertionError("成组重裁应抽取 3 个成员")
    # 只读性：重开原冻结结论，内容与建议前完全一致
    s2, reopened = _request("GET", f"/api/audits/{fid}")
    if s2 != 200 or reopened != frozen:
        raise AssertionError("修复建议改写了原冻结结论")
    return f"段 #2→#3 (libX.a, libY.a)，消失未定义 {body['suggestion']['resolved_undefined']}"


@step("修复建议：无解段与重复强定义均给出明确原因")
def _fix_suggestion_negative() -> str:
    sys.path.insert(0, str(BACKEND))
    from app.fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar

    def obj(spec, group=None):
        return {"name": spec.name + ".o", "data_b64": b64(build_elf64_rel(spec)),
                "group": group}

    def ar(name, specs, group=None):
        return {"name": name + ".a", "data_b64": b64(build_gnu_ar(name, specs)),
                "group": group}

    # 1) 无可行段：ghost 任何归档都不提供
    payload = {"audit_id": _tag("VERIFY-FIXNONE"), "inputs": [
        obj(ObjSpec("m", undefined=["ghost"])),
        ar("libA", [ObjSpec("pa", strong=["pa"])]),
        ar("libB", [ObjSpec("pb", strong=["pb"])]),
    ]}
    s1, b1 = _request("POST", "/api/audits", payload)
    if s1 != 422 or b1["error"]["code"] != "UNDEFINED_SYMBOL":
        raise AssertionError(f"前置拒绝构造失败: {s1} {json.dumps(b1)[:300]}")
    s2, b2 = _request("GET", f"/api/audits/{payload['audit_id']}/fix-suggestion")
    if s2 != 200 or b2.get("status") != "no_suggestion" \
            or b2["reason"]["code"] != "NO_FEASIBLE_SEGMENT":
        raise AssertionError(f"期望 NO_FEASIBLE_SEGMENT，实际 {s2} {json.dumps(b2, ensure_ascii=False)[:400]}")

    # 2) 候选重放触发重复强定义：成组后 xmem 被抽取，d 与 dmem 冲突
    payload = {"audit_id": _tag("VERIFY-FIXDUP"), "inputs": [
        obj(ObjSpec("m", undefined=["a"])),
        ar("libX", [ObjSpec("amem", strong=["a"], undefined=["c"]),
                    ObjSpec("xmem", strong=["x", "d"])]),
        ar("libY", [ObjSpec("cmem", strong=["c"], undefined=["x", "e"]),
                    ObjSpec("dmem", strong=["e", "d"])]),
    ]}
    s3, b3 = _request("POST", "/api/audits", payload)
    if s3 != 422 or b3["error"]["evidence"]["undefined"] != ["x"]:
        raise AssertionError(f"前置拒绝构造失败: {s3} {json.dumps(b3)[:300]}")
    s4, b4 = _request("GET", f"/api/audits/{payload['audit_id']}/fix-suggestion")
    if s4 != 200 or b4.get("status") != "no_suggestion" \
            or b4["reason"]["code"] != "DUPLICATE_STRONG_IN_REPLAY":
        raise AssertionError(f"期望 DUPLICATE_STRONG_IN_REPLAY，实际 {s4} {json.dumps(b4, ensure_ascii=False)[:400]}")
    return "NO_FEASIBLE_SEGMENT 与 DUPLICATE_STRONG_IN_REPLAY 均明确返回"


@step("修复建议：非该类拒绝与既有成功审计保持原状")
def _fix_suggestion_guards() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    fid = _tag("VERIFY-FIXGUARD"); demo["audit_id"] = fid
    s1, accepted = _request("POST", "/api/audits", demo)
    if s1 != 201:
        raise AssertionError(f"前置成功审计构造失败: {s1}")
    # 成功审计不属于最终未定义拒绝：明确拒绝且不改写
    s2, b2 = _request("GET", f"/api/audits/{fid}/fix-suggestion")
    if s2 != 409 or b2.get("reason", {}).get("code") != "NOT_UNDEFINED_REJECTION":
        raise AssertionError(f"期望 409 NOT_UNDEFINED_REJECTION，实际 {s2} {json.dumps(b2, ensure_ascii=False)[:300]}")
    # 未知标识
    s3, b3 = _request("GET", "/api/audits/VERIFY-NO-SUCH-ID/fix-suggestion")
    if s3 != 404:
        raise AssertionError(f"未知标识应 404，实际 {s3}")
    # 既有成功审计重开结果保持原状
    s4, reopened = _request("GET", f"/api/audits/{fid}")
    if s4 != 200 or reopened != accepted:
        raise AssertionError("既有成功审计的重开结果被改写")
    return "成功审计 409 明确拒绝、未知标识 404、重开内容不变"


def main() -> int:
    # 测试与构建不依赖后端，先跑；冒烟前等待健康端点。
    _parser_tests()
    _frontend_build()
    _health()
    _grouped_cycle()
    _ungrouped_cycle()
    _duplicate_strong()
    _corrupt_index()
    _freeze_reopen()
    _fix_suggestion_unique()
    _fix_suggestion_negative()
    _fix_suggestion_guards()

    print("\n================ verify 汇总 ================")
    width = max(len(n) for n, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name.ljust(width)}  {detail}")
        failed += 0 if ok else 1
    print(f"\n合计 {len(results)} 项，失败 {failed} 项")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
