"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. HTTP 冒烟（健康检查 + 五个必测场景）：
   a. ET_REL 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. ET_REL 重叠写入被拒绝（patch_overlap）；
   c. ET_REL PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果；
   d. ET_DYN（PIE）动态重定位 R_X86_64_RELATIVE + R_X86_64_GLOB_DAT 成功，
      逐项返回写入虚拟地址 / 文件偏移 / 所属唯一可执行映射；
   e. ET_DYN 写入目标落在非可执行 PT_LOAD（跨映射）被拒绝
      （target_not_executable），旧成功结论被清除，无部分结果。

任何一步失败立即以非零退出码结束；全部成功退出码为 0。
"""

from __future__ import annotations

import base64
import json
import os
import py_compile
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from elfbuild import build_elf, build_pie  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
TIMEOUT = 5

PIE_BASE = 0x555555554000
PIE_EXT_FOO = 0x7FFFF7A01000
PIE_DATA_VADDR = 0x4000


def step(name: str) -> None:
    print(f"\n=== verify: {name} ===", flush=True)


def fail(msg: str) -> None:
    print(f"verify: FAIL — {msg}", flush=True)
    sys.exit(1)


def check_unit_tests() -> None:
    step("1/3 单元测试")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail(f"单元测试失败（退出码 {proc.returncode}）")
    print("verify: 单元测试全部通过")


def check_build() -> None:
    step("2/3 构建检查（字节编译 + 模块导入）")
    for py in list((ROOT / "app").rglob("*.py")) + [Path(__file__)]:
        try:
            py_compile.compile(str(py), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"字节编译失败 {py}: {exc}")
    proc = subprocess.run(
        [sys.executable, "-c", "import app.server, app.elfaudit; print('import ok')"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail("关键模块导入失败")
    # 静态资源（页面）必须存在
    page = ROOT / "app" / "static" / "index.html"
    if not page.is_file() or page.stat().st_size == 0:
        fail("审计页面 app/static/index.html 缺失或为空")
    print("verify: 构建检查通过")


def http_get(path: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(BASE_URL + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            body = json.loads(raw) if "application/json" in ctype else None
            return resp.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        ctype = exc.headers.get("Content-Type", "")
        body = json.loads(raw) if "application/json" in ctype else None
        return exc.code, body


def http_post(path: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health(attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            status, body = http_get("/healthz")
            if status == 200 and body and body.get("status") == "ok":
                print(f"verify: 健康检查通过 {BASE_URL}/healthz -> {body}")
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    fail(f"服务在 {attempts}s 内未通过健康检查：{BASE_URL}/healthz")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def double_type_elf() -> bytes:
    return build_elf(
        text=bytes(range(48)),
        symbols=[
            ("ext_foo", 0, 0),
            ("memcpy", 0, 0),
            ("local_fn", "text", 0x10),
        ],
        relocs=[
            {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
            {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
            {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
        ],
    )


def overlap_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},  # [0,8)
            {"offset": 4, "sym": 2, "type": 2, "addend": 0},  # [4,8) 重叠
        ],
    )


def pc32_overflow_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("far_away", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},
            {"offset": 8, "sym": 2, "type": 2, "addend": 0},
        ],
    )


def check_http_smoke() -> None:
    step("3/3 HTTP 冒烟")
    wait_for_health()

    # 页面可访问且包含审计台标记
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=TIMEOUT) as resp:
            page = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        page = ""
    if status != 200 or "ELF64" not in page:
        fail(f"审计页面异常：HTTP {status}")
    print("verify: 页面 GET / -> 200")

    # 场景 a：双类型重定位成功
    payload = {
        "audit_id": "verify-double-type",
        "file_base64": b64(double_type_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body = http_post("/api/audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"双类型重定位应成功：HTTP {status} {body}")
    if len(body.get("items", [])) != 3:
        fail(f"应返回 3 个重定位项，实际 {len(body.get('items', []))}")
    types = sorted(it["type_name"] for it in body["items"])
    if types != ["R_X86_64_64", "R_X86_64_PC32", "R_X86_64_PC32"]:
        fail(f"重定位类型集合异常：{types}")
    r64 = next(it for it in body["items"] if it["type_name"] == "R_X86_64_64")
    for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
        if key not in r64:
            fail(f"成功结果缺少字段 {key}")
    if r64["after_hex"] != struct.pack("<Q", 0x500010).hex():
        fail(f"R_X86_64_64 写入值错误：{r64['after_hex']}")
    offsets = [p["offset"] for p in body["patches"]]
    if offsets != sorted(offsets):
        fail("补丁未按偏移排序")
    if len(body.get("conclusion", "")) != 64:
        fail("冻结结论 SHA-256 缺失")
    print(f"verify: 双类型重定位成功，结论 {body['conclusion']}")

    # 冻结结论可凭标识读回
    status, fetched = http_get("/api/result/verify-double-type")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != body["conclusion"]:
        fail("冻结结论无法按标识读回或内容不一致")
    print("verify: 冻结结论读回一致")

    # 场景 b：重叠写入拒绝，且清除旧成功结论（使用同一标识）
    payload_b = {
        "audit_id": "verify-double-type",  # 故意复用：旧 PASS 必须被清除
        "file_base64": b64(overlap_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body_b = http_post("/api/audit", payload_b)
    if status != 200 or body_b.get("ok"):
        fail(f"重叠写入应被拒绝：HTTP {status} {body_b}")
    if body_b["violation"]["code"] != "patch_overlap":
        fail(f"违约代码应为 patch_overlap：{body_b['violation']}")
    if body_b["violation"].get("entry_index") != 1:
        fail("未定位到首个违约项（entry_index 应为 1）")
    if "conclusion" in body_b:
        fail("拒绝响应中不得携带旧冻结结论")
    status, again = http_get("/api/result/verify-double-type")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧成功结论未被清除")
    print("verify: 重叠写入已拒绝，首个违约项 entry_index=1，旧成功结论已清除")

    # 场景 c：PC32 溢出拒绝，无部分结果
    payload_c = {
        "audit_id": "verify-pc32-overflow",
        "file_base64": b64(pc32_overflow_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "far_away": 0x7F0000000000},
    }
    status, body_c = http_post("/api/audit", payload_c)
    if status != 200 or body_c.get("ok"):
        fail(f"PC32 溢出应被拒绝：HTTP {status} {body_c}")
    if body_c["violation"]["code"] != "pc32_overflow":
        fail(f"违约代码应为 pc32_overflow：{body_c['violation']}")
    if body_c["violation"].get("entry_index") != 1:
        fail("PC32 溢出未定位到首个违约项（entry_index 应为 1）")
    status, stored = http_get("/api/result/verify-pc32-overflow")
    if status != 200 or stored.get("ok"):
        fail("溢出记录不应包含成功结论/部分补丁")
    print("verify: PC32 有符号 32 位溢出已拒绝，未生成部分结果")

    # 场景 d：ET_DYN（PIE）RELATIVE + GLOB_DAT 成功
    pie = build_pie(
        code=bytes(range(64)),
        dynsyms=[("ext_foo", 0, 0)],
        dyn_relocs=[
            {"offset": 0x200, "sym": 0, "type": 8, "addend": 0x3000},
            {"offset": 0x208, "sym": 1, "type": 6, "addend": 0x10},
        ],
    )
    payload_d = {
        "audit_id": "verify-pie-dynamic",
        "file_base64": b64(pie),
        "load_base": PIE_BASE,
        "symbols": {"ext_foo": PIE_EXT_FOO},
    }
    status, body_d = http_post("/api/audit", payload_d)
    if status != 200 or not body_d.get("ok"):
        fail(f"PIE 动态重定位应成功：HTTP {status} {body_d}")
    if body_d.get("elf_type") != "ET_DYN":
        fail(f"响应 elf_type 应为 ET_DYN：{body_d.get('elf_type')}")
    if len(body_d.get("items", [])) != 2:
        fail(f"PIE 应返回 2 个动态重定位项，实际 {len(body_d.get('items', []))}")
    types = sorted(it["type_name"] for it in body_d["items"])
    if types != ["R_X86_64_GLOB_DAT", "R_X86_64_RELATIVE"]:
        fail(f"动态重定位类型集合异常：{types}")
    by_type = {it["type_name"]: it for it in body_d["items"]}
    rel = by_type["R_X86_64_RELATIVE"]
    glob = by_type["R_X86_64_GLOB_DAT"]
    # RELATIVE: B + A
    if rel["after_hex"] != struct.pack("<Q", PIE_BASE + 0x3000).hex():
        fail(f"RELATIVE 写入值错误：{rel['after_hex']}")
    # GLOB_DAT: S + A
    if glob["after_hex"] != struct.pack("<Q", PIE_EXT_FOO + 0x10).hex():
        fail(f"GLOB_DAT 写入值错误：{glob['after_hex']}")
    # 稳定展示：写入虚拟地址 / 文件偏移 / 所属唯一可执行映射
    for it, vaddr in ((rel, 0x200), (glob, 0x208)):
        if int(it["vaddr"], 16) != vaddr:
            fail(f"{it['type_name']} vaddr 应为 0x{vaddr:x}，实际 {it['vaddr']}")
        if it["file_offset"] != vaddr:
            fail(f"{it['type_name']} file_offset 应为 0x{vaddr:x}，实际 {it['file_offset_hex']}")
        if it["mapping"] != body_d["exec_image"]["index"]:
            fail(f"{it['type_name']} 未落入唯一可执行映射")
        if int(it["P"], 16) != PIE_BASE + vaddr:
            fail(f"{it['type_name']} 运行地址 P 应为 {PIE_BASE + vaddr:#x}，实际 {it['P']}")
    if not body_d["exec_image"]["flags_str"].endswith("X"):
        fail("exec_image 必须带 PF_X")
    exec_indexes = [m["index"] for m in body_d["mappings"] if m["executable"]]
    if exec_indexes != [body_d["exec_image"]["index"]]:
        fail(f"可执行 PT_LOAD 必须唯一：{exec_indexes}")
    vaddrs = [p["vaddr"] for p in body_d["patches"]]
    if vaddrs != sorted(vaddrs):
        fail("动态补丁未按写入虚拟地址排序")
    if len(body_d.get("conclusion", "")) != 64:
        fail("冻结结论 SHA-256 缺失")
    print(f"verify: PIE RELATIVE + GLOB_DAT 成功，结论 {body_d['conclusion']}")

    status, fetched = http_get("/api/result/verify-pie-dynamic")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != body_d["conclusion"]:
        fail("PIE 冻结结论无法按标识读回或内容不一致")
    print("verify: PIE 冻结结论读回一致")

    # 场景 e：跨映射目标（RW PT_LOAD）拒绝，并清除旧 PIE 成功结论
    pie_bad = build_pie(
        dynsyms=[("ext_foo", 0, 0)],
        dyn_relocs=[{"offset": PIE_DATA_VADDR, "sym": 1, "type": 6, "addend": 0}],
    )
    payload_e = {
        "audit_id": "verify-pie-dynamic",  # 故意复用：旧 PASS 必须被清除
        "file_base64": b64(pie_bad),
        "load_base": PIE_BASE,
        "symbols": {"ext_foo": PIE_EXT_FOO},
    }
    status, body_e = http_post("/api/audit", payload_e)
    if status != 200 or body_e.get("ok"):
        fail(f"跨映射写入应被拒绝：HTTP {status} {body_e}")
    if body_e["violation"]["code"] != "target_not_executable":
        fail(f"违约代码应为 target_not_executable：{body_e['violation']}")
    if body_e["violation"].get("entry_index") != 0:
        fail("未定位到首个违约项（entry_index 应为 0）")
    if "conclusion" in body_e:
        fail("拒绝响应中不得携带旧冻结结论")
    status, again = http_get("/api/result/verify-pie-dynamic")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧 PIE 成功结论未被清除")
    print("verify: PIE 跨映射目标已拒绝（target_not_executable），旧成功结论已清除")


def main() -> None:
    print(f"verify: 目标服务 {BASE_URL}")
    check_unit_tests()
    check_build()
    check_http_smoke()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
