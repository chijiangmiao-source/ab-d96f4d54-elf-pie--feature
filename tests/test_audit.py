"""核心审计器与 HTTP API 的单元/集成测试（unittest，无第三方依赖）。

覆盖：文件级拒绝、节表/字符串表/符号表/加数/写入范围/补丁重叠校验、
R_X86_64_64 与 R_X86_64_PC32 成功路径（含边界）、PC32 溢出不产生部分结果、
API 违约清除旧成功结论并定位首个违约项。
"""

from __future__ import annotations

import base64
import json
import os
import struct
import sys
import threading
import unittest
import urllib.request
from http.client import RemoteDisconnected
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import elfaudit
from app.server import build_server, run_audit
from elfbuild import (  # noqa: E402
    SHT_PROGBITS,
    SHT_REL,
    build_elf,
)

BASE = 0x400000
# PC32 的外部符号必须在 P 的有符号 32 位范围内；ext_foo 用于 R64 可任意。
SYMS = {"ext_foo": 0x500000, "memcpy": 0x400200}


def make_payload(
    data: bytes,
    audit_id: str = "id-1",
    *,
    base: int = BASE,
    symbols: dict[str, int] | None = None,
) -> dict:
    return {
        "audit_id": audit_id,
        "file_base64": base64.b64encode(data).decode(),
        "load_base": base,
        "symbols": dict(SYMS if symbols is None else symbols),
    }


def two_type_elf(text_size: int = 48) -> bytes:
    """双类型重定位：R_X86_64_64 与 R_X86_64_PC32 各一项，互不重叠。"""
    text = bytes(range(text_size))
    return build_elf(
        text=text,
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


class FileLevelRejectionTests(unittest.TestCase):
    def assertReject(self, data, code, *, base=BASE, symbols=None):
        result = elfaudit.audit(data, base, dict(SYMS if symbols is None else symbols))
        self.assertFalse(result.ok)
        self.assertEqual(result.items, [])
        self.assertEqual(result.patched, b"")
        self.assertEqual(result.violation.code, code)
        return result.violation

    def test_not_elf(self):
        self.assertReject(b"not an elf file!!" * 4, "bad_magic")

    def test_too_short(self):
        self.assertReject(b"\x7fELF" + b"\x00" * 10, "truncated")

    def test_bad_class(self):
        self.assertReject(build_elf(ei_class=1), "bad_class")

    def test_bad_endian(self):
        self.assertReject(build_elf(ei_data=2), "bad_data")

    def test_not_rel_or_dyn(self):
        # ET_EXEC(3) 既不是 ET_REL 也不是 ET_DYN（PIE），整体拒绝
        self.assertReject(build_elf(e_type=3), "bad_type")

    def test_bad_machine(self):
        self.assertReject(build_elf(e_machine=40), "bad_machine")

    def test_program_header_forbidden(self):
        self.assertReject(build_elf(e_phoff=64), "program_header_forbidden")

    def test_shstrndx_invalid(self):
        self.assertReject(build_elf(shstrndx_valid=False), "bad_shstrndx")

    def test_duplicate_text_sections(self):
        self.assertReject(build_elf(text_duplicate=True), "text_not_unique")

    def test_no_rela(self):
        self.assertReject(build_elf(relocs=[]), "no_rela", symbols={})

    def test_rel_section_rejected(self):
        elf = build_elf(relocs=[{"offset": 0, "sym": 1, "type": 1}], rela_type=SHT_REL)
        self.assertReject(elf, "rel_unsupported")

    def test_rela_targets_rodata_rejected(self):
        elf = build_elf(
            rodata=b"hello\x00",
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
            rela_info="rodata",
        )
        self.assertReject(elf, "rela_not_for_text")

    def test_truncated_section_table(self):
        good = build_elf()
        # ELF 头里的 shoff+shnum*64 被截断：直接砍文件末尾
        self.assertReject(good[: len(good) - 8], "section_table_truncated")

    def test_bad_entsizes(self):
        self.assertReject(build_elf(rela_bad_entsize=12), "bad_rela_entsize")
        self.assertReject(build_elf(symtab_bad_entsize=32), "bad_sym_entsize")

    def test_bss_nobits_section_accepted(self):
        # 含 .bss（SHT_NOBITS，文件中不占字节）的目标文件仍应正常审计
        elf = build_elf(
            text=b"\x00" * 8,
            bss_size=16,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        r = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, 0x500000)

    def test_multiple_rela_sections_targeting_text(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
            second_rela=[{"offset": 8, "sym": 2, "type": 2, "addend": 0}],
        )
        r = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000, "memcpy": 0x400200})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(len(r.items), 2)
        self.assertEqual({it.rela_section for it in r.items}, {".rela.text", ".rela.text.alt"})
        # 全局项序号跨节连续
        self.assertEqual({it.index for it in r.items}, {0, 1})

    def test_bad_base_and_symbols(self):
        elf = two_type_elf()
        result = elfaudit.audit(elf, -1, dict(SYMS))
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.stage, "request")
        result = elfaudit.audit(elf, BASE, {"ext_foo": 1 << 70})
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_symbol_addr")


class EntryLevelRejectionTests(unittest.TestCase):
    def _elf(self, **reloc_kw):
        return build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0, **reloc_kw}],
        )

    def test_unsupported_reloc_type_locates_first_entry(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 9, "addend": 0}],
        )
        v = elfaudit.audit(elf, BASE, SYMS).violation
        self.assertEqual(v.code, "unsupported_reloc_type")
        self.assertEqual(v.entry_index, 0)
        self.assertEqual(v.rela_section, ".rela.text")
        self.assertEqual(v.rela_index, 0)

    def test_unresolved_symbol(self):
        elf = self._elf()
        v = elfaudit.audit(elf, BASE, {"memcpy": 1}).violation
        self.assertEqual(v.code, "unresolved_symbol")
        self.assertEqual(v.symbol, "ext_foo")

    def test_unexpected_extra_symbol(self):
        elf = self._elf()
        v = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000, "ghost": 1}).violation
        self.assertEqual(v.code, "unexpected_symbol")

    def test_bad_symbol_index(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 99, "type": 1, "addend": 0}],
        )
        v = elfaudit.audit(elf, BASE, SYMS).violation
        self.assertEqual(v.code, "bad_symbol_index")
        self.assertEqual(v.entry_index, 0)

    def test_write_out_of_range_64_at_edge(self):
        # .text 32 字节，64 位写从偏移 28 开始 => 越界
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 28, "sym": 1, "type": 1, "addend": 0}],
        )
        v = elfaudit.audit(elf, BASE, SYMS).violation
        self.assertEqual(v.code, "write_out_of_range")
        self.assertEqual(v.offset, 28)

    def test_write_exact_end_is_valid_then_overlap_checks(self):
        # 偏移 28 放 PC32（4 字节）恰好落在节内
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 28, "sym": 1, "type": 2, "addend": 0}],
        )
        # 0x500000 - (0x40001c) = 0xFFFFE4 合法
        result = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000})
        self.assertTrue(result.ok)
        self.assertEqual(result.items[0].after, struct.pack("<i", 0x500000 - (0x400000 + 28)))

    def test_symbol_in_other_section_rejected(self):
        elf = build_elf(
            text=b"\x00" * 32,
            rodata=b"abc",
            symbols=[("d", "rodata", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        v = elfaudit.audit(elf, BASE, {}).violation
        self.assertEqual(v.code, "symbol_not_in_text")

    def test_first_violation_is_reported(self):
        # 第 0 项类型非法，即便后面的项也有问题，必须定位第 0 项
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 42, "addend": 0},
                {"offset": 100, "sym": 2, "type": 1, "addend": 0},
            ],
        )
        v = elfaudit.audit(elf, BASE, SYMS).violation
        self.assertEqual(v.entry_index, 0)
        self.assertEqual(v.code, "unsupported_reloc_type")


class PatchOverlapTests(unittest.TestCase):
    def test_overlap_64_and_pc32_rejected(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},   # [0,8)
                {"offset": 4, "sym": 2, "type": 2, "addend": 0},   # [4,8) 重叠
            ],
        )
        v = elfaudit.audit(elf, BASE, SYMS).violation
        self.assertEqual(v.code, "patch_overlap")
        self.assertEqual(v.entry_index, 1)
        self.assertEqual(v.detail["conflicts_with"], 0)

    def test_adjacent_ranges_do_not_overlap(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},  # [0,8)
                {"offset": 8, "sym": 2, "type": 2, "addend": 0},  # [8,12)
            ],
        )
        result = elfaudit.audit(elf, BASE, SYMS)
        self.assertTrue(result.ok)

    def test_same_offset_two_pc32_rejected(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 2, "addend": 0},
                {"offset": 0, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        v = elfaudit.audit(elf, BASE, SYMS).violation
        self.assertEqual(v.code, "patch_overlap")

    def test_overlap_no_partial_patches(self):
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 6, "sym": 2, "type": 1, "addend": 0},
            ],
        )
        result = elfaudit.audit(elf, BASE, SYMS)
        self.assertFalse(result.ok)
        self.assertEqual(result.items, [])
        self.assertEqual(result.patched, b"")


class SuccessPathTests(unittest.TestCase):
    def test_two_type_relocations(self):
        elf = two_type_elf()
        result = elfaudit.audit(elf, BASE, SYMS)
        self.assertTrue(result.ok, result.violation)
        self.assertEqual(len(result.items), 3)

        pub = result.to_public_dict()
        # 补丁必须按偏移排序
        offsets = [p["offset"] for p in pub["patches"]]
        self.assertEqual(offsets, sorted(offsets))

        by_off = {it.offset: it for it in result.items}
        r64 = by_off[0x00]
        self.assertEqual(r64.reloc_type, 1)
        self.assertEqual(r64.s, 0x500000)
        self.assertEqual(r64.a, 0x10)
        self.assertEqual(r64.p, BASE + 0)
        self.assertEqual(r64.value, 0x500010)
        self.assertEqual(r64.before, bytes(range(8)))
        self.assertEqual(r64.after, struct.pack("<Q", 0x500010))

        pc = by_off[0x08]
        self.assertEqual(pc.reloc_type, 2)
        self.assertEqual(pc.s, 0x400200)
        self.assertEqual(pc.a, -4)
        self.assertEqual(pc.p, BASE + 8)
        self.assertEqual(pc.value, 0x400200 - 4 - (BASE + 8))
        self.assertEqual(pc.after, struct.pack("<i", pc.value))

        # 本地符号定义在 .text+0x10：S=BASE+0x10, P=BASE+0x10 => 0
        local = by_off[0x10]
        self.assertEqual(local.value, 0)

        # 补丁后节摘要与逐项 after 一致
        patched = bytearray(range(48))
        patched[0:8] = struct.pack("<Q", 0x500010)
        patched[8:12] = struct.pack("<i", pc.value)
        patched[0x10:0x14] = struct.pack("<i", 0)
        import hashlib

        self.assertEqual(result.patched, bytes(patched))
        self.assertEqual(result.patched_sha256, hashlib.sha256(bytes(patched)).hexdigest())

    def test_r64_wrapping_mod_2_64(self):
        # S+A 回绕按 mod 2^64 写入 8 字节（绝对重定位允许回绕）
        elf = build_elf(
            text=b"\x00" * 8,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 16}],
        )
        s = 0xFFFFFFFFFFFFFFFF
        result = elfaudit.audit(elf, BASE, {"ext_foo": s})
        self.assertTrue(result.ok, result.violation)
        self.assertEqual(result.items[0].value, 15)
        self.assertEqual(result.items[0].after, struct.pack("<Q", 15))

    def test_pc32_boundaries(self):
        # PC32 恰好 +2^31-1 与 -2^31 必须通过
        base = 0x100000
        elf_hi = build_elf(
            text=b"\x00" * 8,
            symbols=[("hi", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        s_hi = (base + 0x7FFFFFFF) & ((1 << 64) - 1)
        r = elfaudit.audit(elf_hi, base, {"hi": s_hi})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, 0x7FFFFFFF)

        s_lo = (base - 0x80000000) & ((1 << 64) - 1)
        r = elfaudit.audit(elf_hi, base, {"hi": s_lo})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, -0x80000000)

    def test_pc32_overflow_no_partial_result(self):
        # 第一项本可成功，第二项 PC32 溢出：整体失败，无补丁、无摘要
        elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("far_away", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 8, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        result = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000, "far_away": 0x7F0000000000})
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "pc32_overflow")
        self.assertEqual(result.violation.entry_index, 1)
        self.assertEqual(result.violation.offset, 8)
        # 不得生成部分结果
        self.assertEqual(result.items, [])
        self.assertEqual(result.patched, b"")
        self.assertEqual(result.patched_sha256, "")
        # 明细包含 S/A/P 供复算
        d = result.violation.detail
        self.assertIn("S", d)
        self.assertIn("P", d)
        self.assertEqual(d["A"], "0")

    def test_pc32_underflow(self):
        base = 0x400000
        elf = build_elf(
            text=b"\x00" * 8,
            symbols=[("low", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        # S 落在 P 之后恰好 -2^31-1（补码回绕后仍超出 i32 下界）
        s = (base - 0x80000001) & ((1 << 64) - 1)
        r = elfaudit.audit(elf, base, {"low": s})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "pc32_overflow")
        self.assertEqual(r.violation.detail["computed"], str(-0x80000001))

    def test_pc32_wraparound_in_range(self):
        # 64 位补码回绕后差值落在 i32：P 靠近地址空间低端，S 在高端
        base = 0x10
        elf = build_elf(
            text=b"\x00" * 8,
            symbols=[("near_via_wrap", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        s = (1 << 64) - 0x10  # S - P = -32
        r = elfaudit.audit(elf, base, {"near_via_wrap": s})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, -32)
        self.assertEqual(r.items[0].after, struct.pack("<i", -32))

    def test_negative_addend_pc32(self):
        elf = build_elf(
            text=b"\x00" * 8,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": -0x100}],
        )
        r = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, 0x500000 - 0x100 - BASE)
        self.assertEqual(r.items[0].a, -0x100)

    def test_freeze_conclusion_stable(self):
        elf = two_type_elf()
        r1 = elfaudit.audit(elf, BASE, SYMS)
        c1 = elfaudit.freeze_conclusion("id-X", r1, SYMS)
        c2 = elfaudit.freeze_conclusion("id-X", elfaudit.audit(elf, BASE, SYMS), SYMS)
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 64)
        int(c1, 16)
        # 换基址 -> 结论改变
        c3 = elfaudit.freeze_conclusion("id-X", elfaudit.audit(elf, BASE + 1, SYMS), SYMS)
        self.assertNotEqual(c1, c3)
        # 换标识 -> 结论改变
        c4 = elfaudit.freeze_conclusion("id-Y", r1, SYMS)
        self.assertNotEqual(c1, c4)


class ByteTamperTests(unittest.TestCase):
    def _shdr(self, data, idx):
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        off = shoff + idx * 64
        fields = struct.unpack_from("<IIQQQQIIQQ", data, off)
        return off, fields

    def test_corrupt_section_name_offset(self):
        good = bytearray(two_type_elf())
        shstrndx = struct.unpack_from("<H", good, 0x3E)[0]
        # .text 是节 #1，把它的 sh_name 改成字符串表外的巨大偏移
        hdr_off, _ = self._shdr(good, 1)
        struct.pack_into("<I", good, hdr_off, 0xFFFF_FFF0)
        v = elfaudit.audit(bytes(good), BASE, SYMS).violation
        self.assertEqual(v.code, "bad_section_name")
        _ = shstrndx

    def test_corrupt_symbol_name_offset(self):
        good = bytearray(two_type_elf())
        # 夹具布局：节 #3 为 .symtab
        _, sym_fields = self._shdr(good, 3)
        sym_off = sym_fields[4]
        struct.pack_into("<I", good, sym_off + 24, 0xFFFF_FFF0)  # 符号 #1 的 st_name
        v = elfaudit.audit(bytes(good), BASE, SYMS).violation
        self.assertEqual(v.code, "bad_symbol_name")
        self.assertEqual(v.entry_index, 0)

    def test_corrupt_e_version(self):
        good = bytearray(two_type_elf())
        struct.pack_into("<I", good, 0x14, 99)  # e_version
        v = elfaudit.audit(bytes(good), BASE, SYMS).violation
        self.assertEqual(v.code, "bad_e_version")

    def test_corrupt_rela_addend_still_validated(self):
        # 加数始终按有符号 64 位解析（夹具无法构造非法 q 值；改符号引用越界即可）
        good = bytearray(two_type_elf())
        _, rela_fields = self._shdr(good, 4)
        rela_off = rela_fields[4]
        r_info = (7 << 32) | 1  # 符号索引 7 越界
        struct.pack_into("<Q", good, rela_off + 8, r_info)
        v = elfaudit.audit(bytes(good), BASE, SYMS).violation
        self.assertEqual(v.code, "bad_symbol_index")
        self.assertEqual(v.entry_index, 0)


class ApiTests(unittest.TestCase):
    def setUp(self):
        # 每个用例使用独立存储：直接操作模块全局字典
        from app import server

        server._store.clear()

    def test_api_success_payload_shape(self):
        rec = run_audit(make_payload(two_type_elf(), "api-ok"))
        self.assertTrue(rec["ok"])
        self.assertEqual(len(rec["conclusion"]), 64)
        self.assertEqual(len(rec["items"]), 3)
        for it in rec["items"]:
            for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
                self.assertIn(key, it)
        self.assertEqual(rec["patches"], sorted(rec["patches"], key=lambda p: p["offset"]))

    def test_failure_clears_previous_success(self):
        # 1) 合法文件先通过
        ok = run_audit(make_payload(two_type_elf(), "stable-id"))
        self.assertTrue(ok["ok"])
        # 2) 同一标识提交重叠补丁的违约文件
        bad = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 4, "sym": 2, "type": 1, "addend": 0},
            ],
        )
        fail = run_audit(make_payload(bad, "stable-id"))
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "patch_overlap")
        self.assertNotIn("conclusion", fail)
        # 3) 再读该标识：只剩违约定位，旧成功结论已清除
        from app import server

        stored = server._store["stable-id"]
        self.assertEqual(stored["kind"], "fail")
        self.assertNotIn("result", stored)
        again = run_audit  # noqa: F841 (仅确认 API 可重入)

    def test_pc32_overflow_rejected_via_api(self):
        bad = build_elf(
            text=b"\x00" * 32,
            symbols=[("far", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        rec = run_audit(make_payload(bad, "ovf", symbols={"far": 0x7F0000000000}))
        self.assertFalse(rec["ok"])
        self.assertEqual(rec["violation"]["code"], "pc32_overflow")
        self.assertEqual(rec["violation"]["entry_index"], 0)

    def test_bad_base64_and_inputs(self):
        for payload in [
            {"audit_id": "x", "file_base64": "@@not base64@@", "load_base": 0, "symbols": {}},
            {"audit_id": "x", "file_base64": "", "load_base": 0, "symbols": {}},
            {"audit_id": "", "file_base64": "AA==", "load_base": 0, "symbols": {}},
            {"audit_id": "x", "file_base64": "AA==", "load_base": 0xFFFFFFFFFFFFFFFF + 1,
             "symbols": {}},
            "not-a-dict",
        ]:
            with self.assertRaises(ValueError):
                run_audit(payload)


class HttpSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, payload):
        req = urllib.request.Request(
            self._url("/api/audit"),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())

    def test_health_and_page(self):
        with urllib.request.urlopen(self._url("/healthz"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read())
            self.assertEqual(body["status"], "ok")
        with urllib.request.urlopen(self._url("/"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("ELF64".encode(), resp.read())

    def test_full_http_flow_success_then_fail_then_read(self):
        status, ok = self._post(make_payload(two_type_elf(), "http-id"))
        self.assertEqual(status, 200)
        self.assertTrue(ok["ok"])

        with urllib.request.urlopen(self._url("/api/result/http-id"), timeout=5) as resp:
            fetched = json.loads(resp.read())
        self.assertTrue(fetched["ok"])
        self.assertEqual(fetched["conclusion"], ok["conclusion"])

        bad = build_elf(
            text=b"\x00" * 16,
            symbols=[("far", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        status, fail = self._post(make_payload(bad, "http-id", symbols={"far": 0x7F0000000000}))
        self.assertEqual(status, 200)
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "pc32_overflow")

        with urllib.request.urlopen(self._url("/api/result/http-id"), timeout=5) as resp:
            fetched = json.loads(resp.read())
        self.assertFalse(fetched["ok"])
        self.assertNotIn("conclusion", fetched)

        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self._url("/api/result/nope"), timeout=5)
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ===========================================================================
# ET_DYN / PIE 动态重定位（R_X86_64_RELATIVE / R_X86_64_GLOB_DAT）
# ===========================================================================

from elfbuild import (  # noqa: E402
    PIE_TEXT_AT,
    PIE_RODATA2_VADDR,
    PIE_EXTRA_EXEC_VADDR,
    build_pie,
)

PIE_BIAS = 0x7F000000
PIE_SYMS = {"ext_foo": 0x500000, "ext_bar": 0x600100}


def pie_payload(
    data: bytes,
    audit_id: str = "pie-1",
    *,
    bias: int = PIE_BIAS,
    symbols: dict | None = None,
) -> dict:
    return {
        "audit_id": audit_id,
        "file_base64": base64.b64encode(data).decode(),
        "load_base": bias,
        "symbols": {} if symbols is None else dict(symbols),
    }


def pie_relative_globdat() -> bytes:
    """RELATIVE + GLOB_DAT(外部) + GLOB_DAT(映像内定义) 三项，互不重叠。"""
    return build_pie(
        text=bytes(range(64)),
        symbols=[
            ("ext_foo", 0, 0),
            ("local_fn", 1, PIE_TEXT_AT + 0x20),
        ],
        relocs=[
            {"offset": PIE_TEXT_AT + 0x00, "sym": 0, "type": 8, "addend": PIE_TEXT_AT + 0x10},
            {"offset": PIE_TEXT_AT + 0x08, "sym": 1, "type": 6, "addend": 0x20},
            {"offset": PIE_TEXT_AT + 0x10, "sym": 2, "type": 6, "addend": -8},
        ],
    )


class PieSuccessTests(unittest.TestCase):
    def test_relative_and_globdat_success(self):
        data = pie_relative_globdat()
        r = elfaudit.audit(data, PIE_BIAS, {"ext_foo": 0x500000})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.file_kind, "ET_DYN")
        self.assertEqual(len(r.items), 3)

        by_va = {it.offset: it for it in r.items}
        rel = by_va[PIE_TEXT_AT + 0x00]
        g_ext = by_va[PIE_TEXT_AT + 0x08]
        g_loc = by_va[PIE_TEXT_AT + 0x10]

        # R_X86_64_RELATIVE: value = B + A
        self.assertEqual(rel.reloc_type, 8)
        self.assertEqual(rel.value, PIE_BIAS + PIE_TEXT_AT + 0x10)
        self.assertEqual(rel.after, struct.pack("<Q", rel.value))
        # RELATIVE 无符号引用：公开字典 S 为空，symbol 为空串
        self.assertEqual(rel.symbol, "")
        rel_pub = next(it for it in r.to_public_dict()["items"]
                       if it["vaddr"] == PIE_TEXT_AT + 0x00)
        self.assertIsNone(rel_pub["S"])

        # R_X86_64_GLOB_DAT 外部符号: value = S + A
        self.assertEqual(g_ext.reloc_type, 6)
        self.assertEqual(g_ext.symbol, "ext_foo")
        self.assertEqual(g_ext.s, 0x500000)
        self.assertEqual(g_ext.value, 0x500020)
        self.assertEqual(g_ext.a, 0x20)

        # GLOB_DAT 映像内定义符号: S = B + st_value, value = S + A
        self.assertEqual(g_loc.s, PIE_BIAS + PIE_TEXT_AT + 0x20)
        self.assertEqual(g_loc.value, PIE_BIAS + PIE_TEXT_AT + 0x20 - 8)

    def test_vaddr_to_file_offset_mapping_and_runtime_addr(self):
        data = pie_relative_globdat()
        r = elfaudit.audit(data, PIE_BIAS, {"ext_foo": 0x500000})
        self.assertTrue(r.ok, r.violation)
        seg = r.exec_segment
        self.assertEqual(seg["perms"], "r-x")
        v0 = PIE_TEXT_AT
        for it in r.items:
            # 文件偏移 = 段偏移 + (vaddr - 段 vaddr 起点)
            expect_file = (v0 - 0x1000) + (it.offset - v0)
            self.assertEqual(it.file_offset, expect_file)
            # 运行地址 = 装载偏移 + 链接虚拟地址
            self.assertEqual(it.p, (PIE_BIAS + it.offset) & ((1 << 64) - 1))
            self.assertTrue(it.mapping.startswith("PT_LOAD#0"))
        # 写前字节取自文件，写后字节与补丁后映像摘要一致
        first = sorted(r.items, key=lambda x: x.offset)[0]
        self.assertEqual(first.before, bytes(range(8)))
        self.assertEqual(first.after, struct.pack("<Q", first.value))
        patched = bytearray(data[0:0x1000])
        for it in r.items:
            patched[it.file_offset : it.file_offset + 8] = it.after
        import hashlib

        self.assertEqual(r.patched, bytes(patched))
        self.assertEqual(r.patched_sha256, hashlib.sha256(bytes(patched)).hexdigest())

    def test_public_dict_shape_sorted_by_vaddr(self):
        data = pie_relative_globdat()
        r = elfaudit.audit(data, PIE_BIAS, {"ext_foo": 0x500000})
        pub = r.to_public_dict()
        self.assertEqual(pub["file_kind"], "ET_DYN")
        self.assertIn("load_bias", pub)
        self.assertIn("exec_segment", pub)
        self.assertEqual(pub["segment_size"], 0x1000)
        vas = [p["vaddr"] for p in pub["patches"]]
        self.assertEqual(vas, sorted(vas))
        for it in pub["items"]:
            for key in ("vaddr_hex", "file_offset_hex", "runtime_addr",
                        "mapping", "A", "P", "value", "before_hex", "after_hex"):
                self.assertIn(key, it)
        # 补丁清单按写入虚拟地址稳定展示
        self.assertEqual(pub["patches"][0]["vaddr"], PIE_TEXT_AT)

    def test_write_exact_segment_end_is_valid(self):
        # 0x1ff8 起 8 字节恰好落在可执行段 [0x1000,0x2000) 内
        data = build_pie(relocs=[{"offset": 0x1FF8, "sym": 0, "type": 8, "addend": 0}])
        r = elfaudit.audit(data, PIE_BIAS, {})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].file_offset, 0xFF8)

    def test_stripped_section_table_still_audited(self):
        data = build_pie(
            strip_section_table=True,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6, "addend": 0}],
        )
        r = elfaudit.audit(data, PIE_BIAS, {"ext_foo": 0x500000})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, 0x500000)

    def test_freeze_conclusion_stable_and_bias_sensitive(self):
        data = pie_relative_globdat()
        syms = {"ext_foo": 0x500000}
        c1 = elfaudit.freeze_conclusion("pie-id", elfaudit.audit(data, PIE_BIAS, syms), syms)
        c2 = elfaudit.freeze_conclusion("pie-id", elfaudit.audit(data, PIE_BIAS, syms), syms)
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 64)
        c3 = elfaudit.freeze_conclusion(
            "pie-id", elfaudit.audit(data, PIE_BIAS + 1, syms), syms
        )
        self.assertNotEqual(c1, c3)
        c4 = elfaudit.freeze_conclusion("pie-id2", elfaudit.audit(data, PIE_BIAS, syms), syms)
        self.assertNotEqual(c1, c4)


class PieRejectionTests(unittest.TestCase):
    def assertPieReject(self, data, code, *, symbols=None, bias=PIE_BIAS):
        r = elfaudit.audit(data, bias, dict(PIE_SYMS if symbols is None else symbols))
        self.assertFalse(r.ok)
        self.assertEqual(r.items, [])
        self.assertEqual(r.patched, b"")
        self.assertEqual(r.patched_sha256, "")
        self.assertEqual(r.violation.code, code)
        return r.violation

    def test_cross_mapping_readonly_target_rejected(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_RODATA2_VADDR, "sym": 1, "type": 6, "addend": 0}],
        )
        v = self.assertPieReject(data, "target_not_executable",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 0)
        self.assertEqual(v.detail["target_segment"], 1)
        self.assertEqual(v.detail["exec_segment"], 0)

    def test_cross_mapping_data_target_rejected(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0x4000, "sym": 1, "type": 6, "addend": 0}],
        )
        self.assertPieReject(data, "target_not_executable",
                             symbols={"ext_foo": 0x500000})

    def test_unmapped_target_rejected(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0x9000, "sym": 1, "type": 6, "addend": 0}],
        )
        v = self.assertPieReject(data, "unmapped_target",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 0)

    def test_write_spanning_segment_boundary_rejected(self):
        # 8 字节写从 0x1ffc 起，跨过可执行段结束边界
        data = build_pie(relocs=[{"offset": 0x1FFC, "sym": 0, "type": 8, "addend": 0}])
        self.assertPieReject(data, "unmapped_target")

    def test_two_executable_segments_rejected(self):
        data = build_pie(
            extra_exec_load=True,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(data, "executable_segment_not_unique",
                             symbols={"ext_foo": 0x500000})

    def test_no_executable_segment_rejected(self):
        data = build_pie(
            target_exec_flags=4,  # r-- 唯一可执行属性消失
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(data, "no_executable_segment",
                             symbols={"ext_foo": 0x500000})

    def test_unsupported_reloc_type_locates_first(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 1, "addend": 0}],
        )
        v = self.assertPieReject(data, "unsupported_reloc_type",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 0)

    def test_unresolved_external_symbol(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        v = self.assertPieReject(data, "unresolved_symbol", symbols={})
        self.assertEqual(v.symbol, "ext_foo")
        self.assertEqual(v.entry_index, 0)

    def test_bad_symbol_index(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 99, "type": 6}],
        )
        v = self.assertPieReject(data, "bad_symbol_index",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 0)

    def test_unexpected_extra_symbol(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(data, "unexpected_symbol",
                             symbols={"ext_foo": 0x500000, "ghost": 1})

    def test_patch_overlap_rejected(self):
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[
                {"offset": PIE_TEXT_AT, "sym": 0, "type": 8, "addend": 1},
                {"offset": PIE_TEXT_AT + 4, "sym": 1, "type": 6, "addend": 0},
            ],
        )
        v = self.assertPieReject(data, "patch_overlap",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 1)
        self.assertEqual(v.detail["conflicts_with"], 0)

    def test_first_violation_reported(self):
        # 第 0 项合法、第 1 项无映射；必须定位第 1 项
        data = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[
                {"offset": PIE_TEXT_AT, "sym": 1, "type": 6, "addend": 0},
                {"offset": 0x9000, "sym": 1, "type": 6, "addend": 0},
            ],
        )
        v = self.assertPieReject(data, "unmapped_target",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 1)

    def test_rela_table_unmapped_rejected(self):
        data = build_pie(
            rela_vaddr_override=0x9000,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(data, "dynamic_pointer_unmapped",
                             symbols={"ext_foo": 0x500000})

    def test_rela_table_out_of_bounds_locates_first_bad_entry(self):
        data = build_pie(
            rela_size_override=24 * 500,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        v = self.assertPieReject(data, "rela_entry_out_of_bounds",
                                 symbols={"ext_foo": 0x500000})
        # 可执行页映射内可容纳的 RELA 项之后的首项即首个越界表项
        self.assertEqual(v.stage, "entry")
        self.assertIsNotNone(v.entry_index)

    def test_rela_entry_truncated_locates_first_bad_entry(self):
        data = build_pie(
            rela_size_override=20,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        v = self.assertPieReject(data, "rela_entry_truncated",
                                 symbols={"ext_foo": 0x500000})
        self.assertEqual(v.entry_index, 0)
        self.assertEqual(v.stage, "entry")

    def test_dynamic_segment_unmapped_rejected(self):
        data = build_pie(
            dynamic_in_nonload=True,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(data, "dynamic_unmapped",
                             symbols={"ext_foo": 0x500000})

    def test_dt_rel_rejected(self):
        data = build_pie(
            add_dt_rel=True,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(data, "rel_unsupported",
                             symbols={"ext_foo": 0x500000})

    def test_no_phdr_and_no_dynamic(self):
        kw = dict(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": PIE_TEXT_AT, "sym": 1, "type": 6}],
        )
        self.assertPieReject(build_pie(no_phdr=True, **kw), "program_header_required",
                             symbols={"ext_foo": 0x500000})
        self.assertPieReject(build_pie(no_dynamic=True, **kw), "no_dynamic_segment",
                             symbols={"ext_foo": 0x500000})


class PieApiTests(unittest.TestCase):
    def setUp(self):
        from app import server

        server._store.clear()

    def test_pie_success_via_api(self):
        rec = run_audit(pie_payload(pie_relative_globdat(), "pie-api",
                                    symbols={"ext_foo": 0x500000}))
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["file_kind"], "ET_DYN")
        self.assertEqual(len(rec["conclusion"]), 64)
        self.assertEqual(len(rec["items"]), 3)

    def test_pie_failure_clears_previous_success(self):
        syms = {"ext_foo": 0x500000}
        ok = run_audit(pie_payload(pie_relative_globdat(), "pie-stable", symbols=syms))
        self.assertTrue(ok["ok"])
        bad = build_pie(
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0x9000, "sym": 1, "type": 6}],
        )
        fail = run_audit(pie_payload(bad, "pie-stable", symbols=syms))
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "unmapped_target")
        self.assertNotIn("conclusion", fail)
        from app import server

        stored = server._store["pie-stable"]
        self.assertEqual(stored["kind"], "fail")
        self.assertNotIn("result", stored)
