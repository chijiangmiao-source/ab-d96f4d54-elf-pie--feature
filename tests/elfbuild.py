"""测试夹具：在内存中手工构造 ELF64 小端文件，不依赖外部工具链。

* ``build_elf`` 构造 ET_REL 可重定位目标文件；
* ``build_pie`` 构造 ET_DYN 位置无关可执行映像（程序头 + PT_DYNAMIC +
  DT_RELA），用于动态重定位（R_X86_64_RELATIVE / R_X86_64_GLOB_DAT）审计。
"""

from __future__ import annotations

import struct

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_DYNAMIC = 6

ET_REL = 1
ET_DYN = 2
EM_X86_64 = 62

PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
PF_R = 4

DT_NULL = 0
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18

SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4

R_X86_64_64 = 1
R_X86_64_PC32 = 2
R_X86_64_GLOB_DAT = 6
R_X86_64_RELATIVE = 8

STB_GLOBAL = 1
STT_NOTYPE = 0
STT_SECTION = 3

PAGE = 0x1000
# build_pie 的固定布局常量（测试直接引用）
PIE_TEXT_VADDR = 0x1000
PIE_RODATA_VADDR = 0x2000
PIE_RODATA_VADDR_EXTRA_EXEC = 0x3000


def _align(pos: int, align: int) -> int:
    if align <= 1:
        return pos
    return (pos + align - 1) // align * align


def _strtab(strings: list[bytes]) -> tuple[bytes, dict[int, int]]:
    blob = b"\x00"
    offsets: dict[int, int] = {}
    for i, s in enumerate(strings):
        offsets[i] = len(blob)
        blob += s + b"\x00"
    return blob, offsets


def build_elf(
    *,
    text: bytes = b"\x90" * 32,
    symbols: list[tuple[str, str | int, int]] | None = None,
    relocs: list[dict] | None = None,
    text_duplicate: bool = False,
    rodata: bytes | None = None,
    bss_size: int | None = None,
    rela_info: int | str | None = None,
    rela_type: int = SHT_RELA,
    second_rela: list[dict] | None = None,
    rela_bad_entsize: int | None = None,
    symtab_bad_entsize: int | None = None,
    e_type: int = ET_REL,
    e_machine: int = EM_X86_64,
    ei_class: int = 2,
    ei_data: int = 1,
    e_phoff: int = 0,
    shstrndx_valid: bool = True,
) -> bytes:
    """构造一个最小化 ET_REL。

    symbols 每项为 ``(名称, 所属节, st_value)``；所属节为 0 表示 SHN_UNDEF，
    ``"text"`` / ``"rodata"`` 表示对应节索引。
    relocs 每项为 ``{"offset","sym","type","addend"}``，sym 为 1 基符号序号
    （0 号为保留空符号）。
    """
    symbols = symbols or []
    relocs = relocs or []

    # ---- 节的逻辑布局：0=null, 1=.text[, 2=.text2], [.rodata], .strtab, .symtab, .rela.text, .shstrtab
    logical: list[dict] = []
    logical.append({"name": "", "type": 0})
    text_idx = len(logical)
    logical.append({"name": ".text", "type": SHT_PROGBITS, "data": text, "align": 16})
    if text_duplicate:
        logical.append({"name": ".text", "type": SHT_PROGBITS, "data": b"\xc3", "align": 16})
    rodata_idx: int | None = None
    if rodata is not None:
        rodata_idx = len(logical)
        logical.append({"name": ".rodata", "type": SHT_PROGBITS, "data": rodata, "align": 1})
    if bss_size is not None:
        logical.append({"name": ".bss", "type": 8, "data": b"", "size_override": bss_size, "align": 16})
    strtab_idx = len(logical)
    logical.append({"name": ".strtab", "type": SHT_STRTAB, "data": b"", "align": 1})
    symtab_idx = len(logical)
    logical.append({"name": ".symtab", "type": SHT_SYMTAB, "data": b"", "align": 8})
    rela_idx = len(logical)
    logical.append({"name": ".rela.text", "type": rela_type, "data": b"", "align": 8})
    rela2_idx: int | None = None
    if second_rela is not None:
        rela2_idx = len(logical)
        logical.append({"name": ".rela.text.alt", "type": rela_type, "data": b"", "align": 8})
    shstr_idx = len(logical)
    logical.append({"name": ".shstrtab", "type": SHT_STRTAB, "data": b"", "align": 1})

    def resolve_shndx(desc: str | int) -> int:
        if isinstance(desc, int):
            return desc
        return {"text": text_idx, "rodata": rodata_idx}[desc]  # type: ignore[index]

    # ---- 字符串表 / 符号表
    str_names = [s[0].encode("latin-1") for s in symbols]
    strtab_blob, str_offsets = _strtab(str_names)
    logical[strtab_idx]["data"] = strtab_blob

    sym_blob = b"\x00" * 24
    for i, (_name, sec_desc, value) in enumerate(symbols):
        info = (STB_GLOBAL << 4) | STT_NOTYPE
        shndx = resolve_shndx(sec_desc)
        sym_blob += struct.pack("<IBBHQQ", str_offsets[i], info, 0, shndx, value, 0)
    logical[symtab_idx]["data"] = sym_blob

    # ---- RELA / REL
    def encode_rela(relocs: list[dict]) -> bytes:
        blob = b""
        for r in relocs:
            r_info = (r["sym"] << 32) | (r["type"] & 0xFFFFFFFF)
            if rela_type == SHT_RELA:
                blob += struct.pack("<QQq", r["offset"], r_info, r.get("addend", 0))
            else:
                blob += struct.pack("<QQ", r["offset"], r_info)
        return blob

    logical[rela_idx]["data"] = encode_rela(relocs)
    if second_rela is not None:
        logical[rela2_idx]["data"] = encode_rela(second_rela)

    # ---- 节名字符串表
    shstr_blob = b"\x00"
    sh_name_offsets: dict[int, int] = {}
    for i, sec in enumerate(logical):
        sh_name_offsets[i] = 0
        if sec["name"]:
            sh_name_offsets[i] = len(shstr_blob)
            shstr_blob += sec["name"].encode() + b"\x00"
    logical[shstr_idx]["data"] = shstr_blob

    # ---- ELF 头 + 数据布局
    pos = 64
    for sec in logical[1:]:
        pos = _align(pos, sec.get("align", 1))
        sec["offset"] = pos
        sec["size"] = sec.get("size_override", len(sec["data"]))
        if sec["type"] != 8:  # SHT_NOBITS 不占文件空间
            pos += sec["size"]
    shoff = _align(pos, 8)

    # ---- 链接字段
    target = text_idx if rela_info is None else (resolve_shndx(rela_info) if isinstance(rela_info, str) else rela_info)
    logical[symtab_idx]["link"] = strtab_idx
    logical[symtab_idx]["info"] = 1  # 仅 null 符号（#0）为局部符号
    logical[symtab_idx]["entsize"] = symtab_bad_entsize if symtab_bad_entsize is not None else 24
    logical[rela_idx]["link"] = symtab_idx
    logical[rela_idx]["info"] = target
    logical[rela_idx]["entsize"] = (
        rela_bad_entsize if rela_bad_entsize is not None else (24 if rela_type == SHT_RELA else 16)
    )
    if second_rela is not None:
        logical[rela2_idx]["link"] = symtab_idx
        logical[rela2_idx]["info"] = target
        logical[rela2_idx]["entsize"] = 24 if rela_type == SHT_RELA else 16

    out = bytearray(shoff + len(logical) * 64)

    # ELF 头
    ei_ident = bytearray(16)
    ei_ident[0:4] = b"\x7fELF"
    ei_ident[4] = ei_class
    ei_ident[5] = ei_data
    ei_ident[6] = 1
    if ei_data == 2:  # 构造大端样本时使用大端打包
        ehdr = struct.pack(
            ">16sHHIQQQIHHHHHH",
            bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64, len(logical),
            shstr_idx if shstrndx_valid else 0xFFFF,
        )
    else:
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64, len(logical),
            shstr_idx if shstrndx_valid else 0xFFFF,
        )
    out[0:64] = ehdr

    for sec in logical[1:]:
        out[sec["offset"] : sec["offset"] + sec["size"]] = sec["data"]

    # 节头（构造大端样本时使用大端打包）
    for i, sec in enumerate(logical):
        if i == 0:
            continue
        shdr = struct.pack(
            (">IIQQQQIIQQ" if ei_data == 2 else "<IIQQQQIIQQ"),
            sh_name_offsets[i],
            sec["type"],
            0,
            0,
            sec["offset"],
            sec["size"],
            sec.get("link", 0),
            sec.get("info", 0),
            1,
            sec.get("entsize", 0),
        )
        out[shoff + i * 64 : shoff + (i + 1) * 64] = shdr

    return bytes(out)


# ---------------------------------------------------------------------------
# ET_DYN / PIE 构造器
# ---------------------------------------------------------------------------


def _align_up(pos: int, align: int) -> int:
    if align <= 1:
        return pos
    return (pos + align - 1) // align * align


# build_pie 的固定布局（测试直接引用）
PIE_EXEC_VADDR = 0x1000
PIE_TEXT_AT = 0x1200       # .text 链接虚拟地址（文件偏移 0x200）
PIE_TEXT_FILE_OFF = 0x0200
PIE_RODATA2_VADDR = 0x2000
PIE_DATA_VADDR = 0x4000
PIE_EXTRA_EXEC_VADDR = 0x3000


def build_pie(
    *,
    text: bytes = b"\x00" * 64,
    relocs: list[dict] | None = None,
    symbols: list[tuple[str, int, int]] | None = None,
    extra_exec_load: bool = False,
    strip_section_table: bool = False,
    rela_vaddr_override: int | None = None,
    rela_size_override: int | None = None,
    strsz_override: int | None = None,
    no_phdr: bool = False,
    no_dynamic: bool = False,
    dynamic_in_nonload: bool = False,
    no_rela_tag: bool = False,
    relaent_override: int | None = None,
    add_dt_rel: bool = False,
    target_exec_flags: int | None = None,
    rodata_flags: int = PF_R,
    max_text_bytes: int = 0x800,
) -> bytes:
    """构造最小化 PIE（ET_DYN）映像，不依赖链接器。

    文件共 4 页，每页一个 PT_LOAD（可选）：

    * 文件页 0：映射到 vaddr 0x1000，r-x（唯一可执行映射）。ELF 头/程序头/
      .text(0x1200)/.dynsym/.dynstr/.rela.dyn/.dynamic 都在此页，
      文件偏移 = vaddr - 0x1000；
    * 文件页 1：vaddr 0x2000，r--（跨映射目标用）；
    * 文件页 2：vaddr 0x4000，rw-（跨映射目标用）；
    * 文件页 3：vaddr 0x3000，r-x（仅 extra_exec_load 时存在，用于
      “可执行映射不唯一”拒绝）。

    relocs 每项：``{"offset": vaddr, "sym": 1 基动态符号序号(RELATIVE 用 0),
    "type": 6|8, "addend": int}``。
    symbols 每项：``(名称, st_shndx, st_value)``，shndx=0 表示 SHN_UNDEF。
    """
    assert len(text) <= max_text_bytes
    relocs = relocs or []
    symbols = symbols or []

    # ---- .dynstr / .dynsym / .rela.dyn -----------------------------------
    dynstr = b"\x00"
    name_off: dict[str, int] = {}
    for name, _shndx, _val in symbols:
        nb = name.encode("latin-1")
        name_off[name] = len(dynstr)
        dynstr += nb + b"\x00"

    dynsym = b"\x00" * 24
    for name, shndx, value in symbols:
        dynsym += struct.pack(
            "<IBBHQQ", name_off[name], (STB_GLOBAL << 4) | STT_NOTYPE, 0,
            shndx, value, 0,
        )

    rela_blob = b""
    for r in relocs:
        r_info = (r.get("sym", 0) << 32) | (r["type"] & 0xFFFFFFFF)
        rela_blob += struct.pack("<QQq", r["offset"], r_info, r.get("addend", 0))

    # ---- 段清单（决定程序头数量，需在布局 .text 之前确定） ---------------
    exec_flags = target_exec_flags if target_exec_flags is not None else (PF_R | PF_X)
    segments: list[dict] = [
        dict(p_type=PT_LOAD, p_flags=exec_flags, p_offset=0,
             p_vaddr=PIE_EXEC_VADDR, p_filesz=PAGE, p_memsz=PAGE, p_align=PAGE),
        dict(p_type=PT_LOAD, p_flags=rodata_flags, p_offset=PAGE,
             p_vaddr=PIE_RODATA2_VADDR, p_filesz=PAGE, p_memsz=PAGE, p_align=PAGE),
        dict(p_type=PT_LOAD, p_flags=PF_R | PF_W, p_offset=PAGE * 2,
             p_vaddr=PIE_DATA_VADDR, p_filesz=PAGE, p_memsz=PAGE, p_align=PAGE),
    ]
    if extra_exec_load:
        segments.append(
            dict(p_type=PT_LOAD, p_flags=PF_R | PF_X, p_offset=PAGE * 3,
                 p_vaddr=PIE_EXTRA_EXEC_VADDR, p_filesz=PAGE, p_memsz=PAGE,
                 p_align=PAGE)
        )

    # ---- 第一页内布局：程序头预留后是 .text，再依次排各表 ----------------
    phnum = len(segments) + (0 if no_dynamic else 1)
    ph_end = _align_up(64 + phnum * 56, 16)
    assert ph_end <= PIE_TEXT_FILE_OFF, "程序头表侵入固定 .text 位置"

    pos = PIE_TEXT_FILE_OFF + len(text)
    pos = _align_up(pos, 8)
    dynsym_off = pos
    pos += len(dynsym)
    pos = _align_up(pos, 8)
    dynstr_off = pos
    pos += len(dynstr)
    pos = _align_up(pos, 8)
    rela_off = pos
    pos += len(rela_blob)
    pos = _align_up(pos, 8)
    dyn_off = pos

    def va(file_off: int) -> int:
        return PIE_EXEC_VADDR + file_off

    tags: list[tuple[int, int]] = []
    if not no_rela_tag:
        tags.append((DT_RELA, rela_vaddr_override if rela_vaddr_override is not None else va(rela_off)))
        tags.append((DT_RELASZ, rela_size_override if rela_size_override is not None else len(rela_blob)))
        tags.append((DT_RELAENT, relaent_override if relaent_override is not None else 24))
    tags += [
        (DT_SYMTAB, va(dynsym_off)),
        (DT_STRTAB, va(dynstr_off)),
        (DT_STRSZ, strsz_override if strsz_override is not None else len(dynstr)),
        (DT_SYMENT, 24),
    ]
    if add_dt_rel:
        tags += [(DT_REL, PIE_RODATA2_VADDR), (DT_RELSZ, 24)]
    tags.append((DT_NULL, 0))
    dyn_blob = b"".join(struct.pack("<qQ", t, v) for t, v in tags)
    assert dyn_off + len(dyn_blob) <= PAGE, "第一页装不下动态表"

    if not no_dynamic:
        if dynamic_in_nonload:
            segments.append(
                dict(p_type=PT_DYNAMIC, p_flags=PF_R | PF_W, p_offset=PAGE * 5,
                     p_vaddr=0x9000, p_filesz=16, p_memsz=16, p_align=8)
            )
        else:
            segments.append(
                dict(p_type=PT_DYNAMIC, p_flags=PF_R | PF_W, p_offset=dyn_off,
                     p_vaddr=va(dyn_off), p_filesz=len(dyn_blob),
                     p_memsz=len(dyn_blob), p_align=8)
            )

    # ---- 组装 4 页 -------------------------------------------------------
    pages = [bytearray(PAGE) for _ in range(4)]
    pages[0][PIE_TEXT_FILE_OFF : PIE_TEXT_FILE_OFF + len(text)] = text
    pages[0][dynsym_off : dynsym_off + len(dynsym)] = dynsym
    pages[0][dynstr_off : dynstr_off + len(dynstr)] = dynstr
    pages[0][rela_off : rela_off + len(rela_blob)] = rela_blob
    if not dynamic_in_nonload:
        pages[0][dyn_off : dyn_off + len(dyn_blob)] = dyn_blob
    pages[1][:] = bytes((i * 7) & 0xFF for i in range(PAGE))
    pages[2][:] = bytes((i * 13 + 1) & 0xFF for i in range(PAGE))
    pages[3][:] = b"\xcc" * PAGE
    blob = b"".join(bytes(p) for p in pages)

    # ---- 程序头 ----------------------------------------------------------
    phoff = 64
    for i, seg in enumerate(segments):
        ph = struct.pack(
            "<IIQQQQQQ",
            seg["p_type"], seg["p_flags"], seg["p_offset"], seg["p_vaddr"],
            seg["p_vaddr"], seg["p_filesz"], seg["p_memsz"], seg["p_align"],
        )
        # 程序头写在尚未定稿的 blob 页 0 上
        blob = blob[: phoff + i * 56] + ph + blob[phoff + (i + 1) * 56 :]

    # ---- 节表（可裁剪；动态加载本身不依赖节表） --------------------------
    shoff = 0
    shnum = 0
    shstrndx = 0
    if not strip_section_table:
        sec_names = [b".dynsym", b".dynstr", b".rela.dyn", b".dynamic", b".shstrtab"]
        shstr = b"\x00"
        sh_name = []
        for nm_ in sec_names:
            sh_name.append(len(shstr))
            shstr += nm_ + b"\x00"
        shstr_off = len(blob)
        blob += shstr
        shdrs = b""
        shdrs += struct.pack("<IIQQQQIIQQ", sh_name[0], SHT_DYNSYM, SHF_ALLOC,
                             va(dynsym_off), dynsym_off, len(dynsym), 2, 0, 8, 24)
        shdrs += struct.pack("<IIQQQQIIQQ", sh_name[1], SHT_STRTAB, SHF_ALLOC,
                             va(dynstr_off), dynstr_off, len(dynstr), 0, 0, 1, 0)
        shdrs += struct.pack("<IIQQQQIIQQ", sh_name[2], SHT_RELA, SHF_ALLOC,
                             va(rela_off), rela_off, len(rela_blob), 1, 0, 8, 24)
        shdrs += struct.pack("<IIQQQQIIQQ", sh_name[3], SHT_DYNAMIC,
                             SHF_WRITE | SHF_ALLOC, va(dyn_off), dyn_off,
                             len(dyn_blob), 0, 0, 8, 16)
        shdrs += struct.pack("<IIQQQQIIQQ", sh_name[4], SHT_STRTAB, 0,
                             0, shstr_off, len(shstr), 0, 0, 1, 0)
        shoff = len(blob)
        blob += b"\x00" * 64
        blob += shdrs
        shnum = 6
        shstrndx = 5

    # ---- ELF 头 ----------------------------------------------------------
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8,
        ET_DYN, EM_X86_64, 1, 0,
        0 if no_phdr else phoff,
        shoff, 0, 64,
        0 if no_phdr else 56,
        0 if no_phdr else phnum,
        64, shnum, shstrndx,
    )
    return ehdr + blob[64:]
