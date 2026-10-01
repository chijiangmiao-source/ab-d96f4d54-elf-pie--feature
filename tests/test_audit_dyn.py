"""ET_DYN（PIE 映像）动态重定位审计的单元/集成测试。

覆盖：

* R_X86_64_RELATIVE / R_X86_64_GLOB_DAT 成功路径（B+A、S+A、vaddr↔文件偏移）；
* 补丁仅允许落入唯一可执行 PT_LOAD：跨映射目标 / BSS / 无映射拒绝；
* 动态表边界、条目完整性、符号引用、加数、不支持类型、补丁重叠；
* 冻结结论稳定性与 API 清除旧成功结论。
"""

from __future__ import annotations

import base64
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import elfaudit
from app.server import run_audit
from elfbuild import (  # noqa: E402
    DT_RELA,
    DT_STRTAB,
    DT_SYMTAB,
    PIE_DATA_VADDR,
    build_pie,
)

BASE = 0x555555554000  # 典型 PIE 装载偏移
EXT_FOO = 0x7FFFF7A01000


def pie_two_kinds(code_size: int = 64) -> bytes:
    """两项动态重定位：RELATIVE 写 0x200，GLOB_DAT(ext_foo) 写 0x208。"""
    code = bytes(range(code_size))
    return build_pie(
        code=code,
        dynsyms=[("ext_foo", 0, 0)],
        dyn_relocs=[
            {"offset": 0x200, "sym": 0, "type": 8, "addend": 0x3000},
            {"offset": 0x208, "sym": 1, "type": 6, "addend": 0x10},
        ],
    )


class DynSuccessTests(unittest.TestCase):
    def test_relative_and_globdat_success(self):
        elf = pie_two_kinds()
        r = elfaudit.audit(elf, BASE, {"ext_foo": EXT_FOO})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.elf_type, "ET_DYN")
        self.assertEqual(len(r.items), 2)

        pub = r.to_public_dict()
        self.assertEqual(pub["elf_type"], "ET_DYN")
        self.assertEqual(len(pub["mappings"]), 2)
        self.assertTrue(any(m["executable"] for m in pub["mappings"]))
        # 唯一可执行映射：段 #0，vaddr=0，文件偏移 0
        img = pub["exec_image"]
        self.assertEqual(img["index"], 0)
        self.assertTrue(img["flags_str"].endswith("X"))
        self.assertEqual(img["vaddr"], "0x0000000000000000")
        self.assertEqual(img["file_offset"], "0x0")

        rel, glob = sorted(r.items, key=lambda it: it.index)
        # RELATIVE: B + A
        self.assertEqual(rel.reloc_type, 8)
        self.assertEqual(rel.symbol, "")
        self.assertEqual(rel.symbol_index, 0)
        self.assertEqual(rel.s, BASE)
        self.assertEqual(rel.a, 0x3000)
        self.assertEqual(rel.p, BASE + 0x200)
        self.assertEqual(rel.value, BASE + 0x3000)
        self.assertEqual(rel.offset, 0x200)  # 稳定展示：写入虚拟地址
        self.assertEqual(rel.file_offset, 0x200)  # vaddr↔文件偏移对应
        self.assertEqual(rel.mapping_index, 0)
        self.assertEqual(rel.before, bytes(range(8)))
        self.assertEqual(rel.after, struct.pack("<Q", BASE + 0x3000))

        # GLOB_DAT: S + A
        self.assertEqual(glob.reloc_type, 6)
        self.assertEqual(glob.symbol, "ext_foo")
        self.assertEqual(glob.symbol_index, 1)
        self.assertEqual(glob.s, EXT_FOO)
        self.assertEqual(glob.a, 0x10)
        self.assertEqual(glob.value, EXT_FOO + 0x10)
        self.assertEqual(glob.after, struct.pack("<Q", EXT_FOO + 0x10))
        self.assertEqual(glob.file_offset, 0x208)

        # 补丁后可执行映像摘要（映像从文件偏移 0 开始，含 ELF 头/程序头）
        elf = pie_two_kinds()
        seg_size = r.image["file_size"]
        patched = bytearray(elf[:seg_size])
        patched[0x200:0x208] = struct.pack("<Q", BASE + 0x3000)
        patched[0x208:0x210] = struct.pack("<Q", EXT_FOO + 0x10)
        self.assertEqual(r.patched, bytes(patched))
        self.assertEqual(r.text_size, r.image["file_size"])

        # 公共补丁清单按写入虚拟地址排序
        offsets = [p["vaddr"] for p in pub["patches"]]
        self.assertEqual(offsets, sorted(offsets))

    def test_globdat_defined_pie_symbol(self):
        # PIE 内部已定义动态符号（st_shndx 非保留）：S = B + st_value
        elf = build_pie(
            dynsyms=[("pie_fn", 1, 0x210)],
            dyn_relocs=[{"offset": 0x200, "sym": 1, "type": 6, "addend": 0}],
        )
        r = elfaudit.audit(elf, BASE, {})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, BASE + 0x210)

    def test_relative_wraps_mod_2_64(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 8, "addend": 16}],
        )
        r = elfaudit.audit(elf, 0xFFFFFFFFFFFFFFFF, {})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].value, 15)  # (B + A) mod 2^64

    def test_dynamic_patches_sorted_by_vaddr(self):
        elf = build_pie(
            dynsyms=[("a", 0, 0), ("b", 0, 0)],
            dyn_relocs=[
                {"offset": 0x210, "sym": 2, "type": 6, "addend": 0},
                {"offset": 0x200, "sym": 0, "type": 8, "addend": 0},
                {"offset": 0x208, "sym": 1, "type": 6, "addend": 0},
            ],
        )
        r = elfaudit.audit(elf, BASE, {"a": 0x1000, "b": 0x2000})
        self.assertTrue(r.ok, r.violation)
        pub = r.to_public_dict()
        self.assertEqual([p["vaddr"] for p in pub["patches"]], [0x200, 0x208, 0x210])

    def test_freeze_conclusion_stable(self):
        elf = pie_two_kinds()
        c1 = elfaudit.freeze_conclusion("pie-1", elfaudit.audit(elf, BASE, {"ext_foo": EXT_FOO}),
                                        {"ext_foo": EXT_FOO})
        c2 = elfaudit.freeze_conclusion("pie-1", elfaudit.audit(elf, BASE, {"ext_foo": EXT_FOO}),
                                        {"ext_foo": EXT_FOO})
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 64)
        c3 = elfaudit.freeze_conclusion("pie-1", elfaudit.audit(elf, BASE + 0x1000, {"ext_foo": EXT_FOO}),
                                        {"ext_foo": EXT_FOO})
        self.assertNotEqual(c1, c3)
        c4 = elfaudit.freeze_conclusion("pie-2", elfaudit.audit(elf, BASE, {"ext_foo": EXT_FOO}),
                                        {"ext_foo": EXT_FOO})
        self.assertNotEqual(c1, c4)

    def test_nonzero_load_base_with_segment_offset(self):
        # 可执行段从文件中部开始且 vaddr 非 0 时，仍能正确换算文件偏移
        elf = build_pie()  # 夹具本身 vaddr==offset==0；验证正常换算字段
        r = elfaudit.audit(
            build_pie(dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 8, "addend": 7}]),
            0x100000,
            {},
        )
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].p, 0x100000 + 0x200)
        self.assertEqual(r.items[0].file_offset, 0x200)
        self.assertEqual(r.items[0].value, 0x100007)


class DynRejectionTests(unittest.TestCase):
    def assertReject(self, elf, code, *, base=BASE, symbols=None, entry_index=None):
        r = elfaudit.audit(elf, base, dict(symbols or {}))
        self.assertFalse(r.ok)
        self.assertEqual(r.items, [])
        self.assertEqual(r.patched, b"")
        self.assertEqual(r.patched_sha256, "")
        self.assertEqual(r.violation.code, code)
        if entry_index is not None:
            self.assertEqual(r.violation.entry_index, entry_index)
        return r.violation

    def test_target_in_data_mapping_rejected(self):
        # 跨映射：写入目标落在 RW PT_LOAD，必须拒绝且定位首项
        elf = build_pie(
            dynsyms=[("ext_foo", 0, 0)],
            dyn_relocs=[
                {"offset": 0x200, "sym": 0, "type": 8, "addend": 0},
                {"offset": PIE_DATA_VADDR, "sym": 1, "type": 6, "addend": 0},
            ],
        )
        v = self.assertReject(elf, "target_not_executable", symbols={"ext_foo": EXT_FOO},
                              entry_index=1)
        self.assertEqual(v.offset, PIE_DATA_VADDR)
        self.assertNotEqual(v.detail["mapping"], v.detail["exec_mapping"])

    def test_target_in_bss_rejected(self):
        # data filesz 32 字节，bss 紧随其后：0x4020 仅 memsz 支撑，无文件字节
        elf = build_pie(
            data=b"\x00" * 32,
            bss_size=16,
            dyn_relocs=[{"offset": PIE_DATA_VADDR + 32, "sym": 0, "type": 8, "addend": 0}],
        )
        self.assertReject(elf, "target_no_file_backing", entry_index=0)

    def test_target_completely_unmapped(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x9000, "sym": 0, "type": 8, "addend": 0}],
        )
        self.assertReject(elf, "target_unmapped", entry_index=0)

    def test_target_spanning_mapping_end_rejected(self):
        # 写入 8 字节但只剩 4 字节到数据段 filesz 末端：整个区间无完整文件支撑
        elf = build_pie(
            data=b"\x00" * 32,
            dyn_relocs=[{"offset": PIE_DATA_VADDR + 28, "sym": 0, "type": 8, "addend": 0}],
        )
        v = self.assertReject(elf, "target_unmapped", entry_index=0)
        self.assertEqual(v.offset, PIE_DATA_VADDR + 28)

    def test_unsupported_dynamic_reloc_type(self):
        elf = build_pie(
            dynsyms=[("ext_foo", 0, 0)],
            dyn_relocs=[{"offset": 0x200, "sym": 1, "type": 9, "addend": 0}],
        )
        v = self.assertReject(elf, "unsupported_reloc_type", symbols={"ext_foo": EXT_FOO},
                              entry_index=0)
        self.assertEqual(v.reloc_type, 9)

    def test_first_violation_located(self):
        # 第 0 项目标跨映射，第 1 项类型也非法：必须报第 0 项
        elf = build_pie(
            dynsyms=[("ext_foo", 0, 0), ("bad", 0, 0)],
            dyn_relocs=[
                {"offset": PIE_DATA_VADDR, "sym": 1, "type": 6, "addend": 0},
                {"offset": 0x200, "sym": 2, "type": 42, "addend": 0},
            ],
        )
        v = self.assertReject(elf, "target_not_executable",
                              symbols={"ext_foo": EXT_FOO, "bad": 1}, entry_index=0)

    def test_unresolved_dynamic_symbol(self):
        elf = build_pie(
            dynsyms=[("ext_foo", 0, 0)],
            dyn_relocs=[{"offset": 0x200, "sym": 1, "type": 6, "addend": 0}],
        )
        v = self.assertReject(elf, "unresolved_symbol", symbols={}, entry_index=0)
        self.assertEqual(v.symbol, "ext_foo")

    def test_unexpected_extra_symbol(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 8, "addend": 0}],
        )
        self.assertReject(elf, "unexpected_symbol", symbols={"ghost": 1})

    def test_bad_dynsym_index(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 99, "type": 6, "addend": 0}],
        )
        self.assertReject(elf, "dynsym_out_of_bounds", symbols={"x": 1}, entry_index=0)

    def test_relative_with_nonzero_symbol(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 3, "type": 8, "addend": 0}],
        )
        self.assertReject(elf, "bad_relative_symbol", entry_index=0)

    def test_globdat_symbol_index_zero(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 6, "addend": 0}],
        )
        self.assertReject(elf, "bad_symbol_index", entry_index=0)

    def test_reserved_shndx_rejected(self):
        elf = build_pie(
            dynsyms=[("weird", 0xFFF1, 0)],
            dyn_relocs=[{"offset": 0x200, "sym": 1, "type": 6, "addend": 0}],
        )
        self.assertReject(elf, "unsupported_symbol_section", symbols={}, entry_index=0)

    def test_dynamic_patch_overlap(self):
        elf = build_pie(
            dyn_relocs=[
                {"offset": 0x200, "sym": 0, "type": 8, "addend": 0},
                {"offset": 0x204, "sym": 0, "type": 8, "addend": 0},
            ],
        )
        v = self.assertReject(elf, "patch_overlap", entry_index=1)
        self.assertEqual(v.detail["conflicts_with"], 0)

    def test_dynamic_adjacent_ok(self):
        elf = build_pie(
            dyn_relocs=[
                {"offset": 0x200, "sym": 0, "type": 8, "addend": 0},
                {"offset": 0x208, "sym": 0, "type": 8, "addend": 0},
            ],
        )
        r = elfaudit.audit(elf, BASE, {})
        self.assertTrue(r.ok, r.violation)


class DynStructureRejectionTests(unittest.TestCase):
    def test_no_executable_load(self):
        self.assertRejectCode(build_pie(no_exec=True), "no_executable_load")

    def test_multiple_executable_loads(self):
        self.assertRejectCode(build_pie(data_executable=True), "multiple_executable_loads")

    def test_multiple_dynamic_segments(self):
        self.assertRejectCode(build_pie(second_dynamic=True), "multiple_dynamic")

    def test_missing_dynamic_tag(self):
        self.assertRejectCode(build_pie(omit_tags=(DT_RELA,)), "missing_dynamic_tag")

    def test_dynamic_not_terminated(self):
        self.assertRejectCode(build_pie(dynamic_terminated=False), "dynamic_not_terminated")

    def test_bad_relaent(self):
        self.assertRejectCode(build_pie(relaent=0), "bad_dyn_relaent")

    def test_bad_syment(self):
        self.assertRejectCode(build_pie(syment=0), "bad_dyn_syment")

    def test_bad_relasz(self):
        self.assertRejectCode(build_pie(relasz_override=7), "bad_dyn_relasz")

    def test_empty_relasz(self):
        self.assertRejectCode(
            build_pie(relasz_override=0, dyn_relocs=[]), "bad_dyn_relasz"
        )

    def test_rela_table_unmapped(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 8, "addend": 0}],
            tag_overrides={DT_RELA: 0x9000},
        )
        self.assertRejectCode(elf, "dynamic_table_unmapped")

    def test_symtab_unmapped(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 8, "addend": 0}],
            tag_overrides={DT_SYMTAB: 0x9000},
        )
        self.assertRejectCode(elf, "dynamic_table_unmapped")

    def test_strtab_unmapped(self):
        elf = build_pie(
            dyn_relocs=[{"offset": 0x200, "sym": 0, "type": 8, "addend": 0}],
            tag_overrides={DT_STRTAB: 0x9000},
        )
        self.assertRejectCode(elf, "dynamic_table_unmapped")

    def assertRejectCode(self, elf: bytes, code: str):
        r = elfaudit.audit(elf, BASE, {})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, code, r.violation)


class DynApiTests(unittest.TestCase):
    def setUp(self):
        from app import server

        server._store.clear()

    def _payload(self, data: bytes, audit_id: str = "pie-id", symbols=None):
        return {
            "audit_id": audit_id,
            "file_base64": base64.b64encode(data).decode(),
            "load_base": BASE,
            "symbols": dict(symbols if symbols is not None else {"ext_foo": EXT_FOO}),
        }

    def test_pie_success_payload_shape(self):
        rec = run_audit(self._payload(pie_two_kinds()))
        self.assertTrue(rec["ok"], rec)
        self.assertEqual(rec["elf_type"], "ET_DYN")
        self.assertEqual(len(rec["conclusion"]), 64)
        self.assertEqual(len(rec["items"]), 2)
        for it in rec["items"]:
            for key in ("vaddr", "file_offset", "file_offset_hex", "mapping",
                        "S", "A", "P", "value", "before_hex", "after_hex"):
                self.assertIn(key, it)
        self.assertIn("patched_image_hex", rec)
        self.assertNotIn("patched_text_hex", rec)
        self.assertEqual(rec["patches"], sorted(rec["patches"], key=lambda p: p["vaddr"]))

    def test_failure_clears_previous_pie_success(self):
        ok = run_audit(self._payload(pie_two_kinds(), "pie-stable"))
        self.assertTrue(ok["ok"])
        # 跨映射目标的违约 PIE
        bad = build_pie(
            dynsyms=[("ext_foo", 0, 0)],
            dyn_relocs=[{"offset": PIE_DATA_VADDR, "sym": 1, "type": 6, "addend": 0}],
        )
        fail = run_audit(self._payload(bad, "pie-stable"))
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "target_not_executable")
        self.assertEqual(fail["violation"]["entry_index"], 0)
        self.assertNotIn("conclusion", fail)
        from app import server

        stored = server._store["pie-stable"]
        self.assertEqual(stored["kind"], "fail")
        self.assertNotIn("result", stored)


if __name__ == "__main__":
    unittest.main(verbosity=2)
