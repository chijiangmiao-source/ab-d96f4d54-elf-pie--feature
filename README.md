# ELF64 重定位载荷审计服务

面向载荷发布前审查的 **ELF64 小端 x86-64 重定位审计** 服务，同时支持供应商交付的两种形态：

* **ET_REL 可重定位目标文件（.o）**：外部符号重定位审计；
* **ET_DYN 已链接位置无关可执行映像（PIE）**：从 `PT_DYNAMIC` 的 RELA 表审计动态重定位。

审查员提交稳定审计标识、Base64 文件、代码装载基址（PIE 为装载偏移 B）与被引用外部符号地址后，可读取冻结结论、重定位后的代码摘要及按写入位置排序的字节补丁；任何违约都会定位到**首个违约位置**并清除该标识下旧的成功结论，**绝不生成部分结果**。

纯 Python 3.11 标准库实现，无第三方依赖。

## ET_REL 审计规则（逐项强校验）

文件必须同时满足：

1. ELF64（`EI_CLASS=2`）、小端（`EI_DATA=1`）、`ET_REL`、`EM_X86_64`，无程序头；
2. 节表/节名字符串表合法，存在**唯一** `.text`（`SHT_PROGBITS`）；
3. 存在唯一 `SHT_SYMTAB` 及其 `SHT_STRTAB`，表项尺寸/`sh_info` 合法；
4. 所有重定位节必须是指向该 `.text` 的 **SHT_RELA**（拒绝 `SHT_REL`、拒绝指向其他节）；
5. 仅处理 `R_X86_64_64`（写 8 字节）与 `R_X86_64_PC32`（写 4 字节有符号）；
6. 逐项校验：符号索引与字符串表、加数、写入范围不得越出 `.text` 节边界；
7. 所有补丁区间两两不得重叠；
8. `R_X86_64_PC32` 的 `S + A − P` 经 64 位补码回绕后必须落在有符号 32 位范围 `[-2^31, 2^31−1]`，越界即整体拒绝。

计算（AMD64 psABI）：

| 类型 | S（符号地址） | 写入值 |
|---|---|---|
| `R_X86_64_64` | 外部符号=用户提供地址；`.text` 内定义符号=基址+st_value | `(S + A) mod 2^64` |
| `R_X86_64_PC32` | 同上 | `(S + A − P) mod 2^64`，按有符号解读，必须 ∈ i32；P = 基址 + 节内偏移 |

## ET_DYN / PIE 审计规则（逐项强校验）

文件必须同时满足：

1. ELF64、小端、`ET_DYN`、`EM_X86_64`，携带合法程序头表（`e_phentsize=56`）；
2. 至少一个 `PT_LOAD`，且存在**唯一**带 `PF_X` 的可执行 `PT_LOAD` 映射（0 个或多个均拒绝）；
3. 存在唯一 `PT_DYNAMIC`，其虚拟区间完整落在某个 `PT_LOAD` 内；从中解析
   `DT_RELA` / `DT_RELASZ` / `DT_RELAENT=24`、`DT_SYMTAB` / `DT_STRTAB` /
   `DT_STRSZ` / `DT_SYMENT=24`（缺项、无映射、越界均拒绝；出现 `DT_REL` 即拒绝）；
4. RELA / STRTAB / SYMTAB 表区间必须经 **vaddr→文件偏移** 映射完整落在某个
   `PT_LOAD` 内；动态符号表尺寸优先取唯一 `SHT_DYNSYM` 节，节表被裁剪时用相邻
   动态表地址夹逼上界；
5. 仅处理 `R_X86_64_RELATIVE`(8) 与 `R_X86_64_GLOB_DAT`(6)，各写 8 字节；其他类型定位首项拒绝；
6. **每条重定位的写入虚拟地址（8 字节完整区间）必须落在唯一可执行 PT_LOAD 内**，
   落在其他 r--/rw- 映射、无映射地址或跨映射边界一律定位首项拒绝；
7. 逐项校验：RELA 条目完整性（`DT_RELASZ` 非 24 整数倍时定位首个被截断表项
   `rela_entry_truncated`）、符号索引/符号名、加数 i64 范围、目标范围；
8. 所有补丁区间两两不得重叠。

计算（B = 审查员给出的装载偏移；P = B + r_offset）：

| 类型 | S（符号地址） | 写入值 |
|---|---|---|
| `R_X86_64_RELATIVE` | —（无符号引用） | `(B + A) mod 2^64` |
| `R_X86_64_GLOB_DAT` | `SHN_UNDEF` 外部符号=用户提供地址；映像内定义符号=`B + st_value` | `(S + A) mod 2^64` |

结果按**写入虚拟地址**稳定排序，逐项给出链接虚拟地址、换算出的文件偏移、
运行地址（B+VA）、所属可执行映射、S/A/P/计算值与写入前后字节；补丁前后对
可执行映射的文件映像分别计算 SHA-256，并对全部输入与补丁结果计算 64 字符
冻结结论。

两种形态的流程均为两阶段：先做全部结构性/范围性检查（失败即报告首个违约项），
再检查补丁重叠，全部通过后才一次性落补丁。

## HTTP 接口

- `GET /` — 审计页面
- `GET /healthz` — 健康状态（含已冻结通过/拒绝计数）
- `POST /api/audit` — 提交审计（JSON）
- `GET /api/result/<audit_id>` — 凭稳定标识读回冻结结论或首个违约定位

提交示例：

```json
{
  "audit_id": "payload-2026-09-29-001",
  "file_base64": "<Base64 编码的 .o 或 PIE 映像>",
  "load_base": "0x400000",
  "symbols": {"ext_foo": "0x500000", "memcpy": "0x400200"}
}
```

`load_base` 与符号地址接受十进制或 `0x` 十六进制字符串；ET_REL 下为代码
装载基址，ET_DYN(PIE) 下为装载偏移 B（运行基址与链接基址之差）。成功响应
以 `file_kind`（`ET_REL` / `ET_DYN`）区分形态：ET_REL 逐项给出
`S / A / P / value / before_hex / after_hex` 与 `.text` 补丁前后 SHA-256；
ET_DYN 逐项给出 `vaddr / file_offset / runtime_addr / mapping / A / P /
value / before_hex / after_hex` 与唯一可执行映射补丁前后 SHA-256。补丁均按
写入位置（ET_REL 为节内偏移、ET_DYN 为写入虚拟地址）排序，并给出 64 字符
冻结结论（对全部输入与补丁结果做规范化哈希，可独立复算）。违约响应给出
`stage / code / message / entry_index / rela_section / rela_index /
offset / type / symbol`，服务端同步清除该标识下旧成功记录。

## 本地运行（无需 Docker）

```bash
python3 -m app.server                      # 默认 0.0.0.0:8080
HOST=127.0.0.1 PORT=9090 python3 -m app.server
python3 -m unittest discover -s tests -v   # 73 项测试
```

## 容器运行（宿主端口可配置）

```bash
docker compose up --build                  # 默认宿主端口 8080
HOST_PORT=9090 docker compose up --build   # 自定义宿主端口
```

## 验收组件 verify（一次运行，退出码结束）

`verify` 服务在同一次运行中依次核对：

1. **测试**：`python3 -m unittest discover` 全量（73 项）；
2. **构建**：全部源码字节编译 + 关键模块导入 + 页面存在；
3. **HTTP 冒烟**：健康检查、页面、
   - ET_REL 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   - ET_REL 重叠写入拒绝（`patch_overlap`，定位 `entry_index=1`，旧成功结论被清除）；
   - ET_REL PC32 有符号 32 位溢出拒绝（`pc32_overflow`），无部分结果；
   - **ET_DYN(PIE) `R_X86_64_RELATIVE` + `R_X86_64_GLOB_DAT` 动态重定位成功**，
     逐项核对写入虚拟地址↔文件偏移↔运行地址（B+VA）映射、计算值与冻结结论读回；
   - **ET_DYN 跨映射目标拒绝**（补丁写入 r-- 非可执行 PT_LOAD，
     `target_not_executable`，定位首项并清除旧成功结论）。

```bash
# 以 verify 的退出码作为整条命令退出码
docker compose --profile verify up --build --abort-on-container-exit --exit-code-from verify
echo $?    # 0 表示验收通过
```

或不使用 Docker：

```bash
HOST=127.0.0.1 PORT=8080 python3 -m app.server &
BASE_URL=http://127.0.0.1:8080 python3 scripts/verify.py
```

## 目录结构

```
app/elfaudit.py        ELF 解析 / ET_REL 与 ET_DYN 校验 / 重定位计算 / 冻结结论核心
app/server.py          页面、审计 API、健康检查
app/static/index.html  审计页面（按偏移/写入虚拟地址两种视图）
tests/elfbuild.py      内存构造 ELF64 ET_REL 与 ET_DYN(PIE) 的测试夹具
tests/test_audit.py    73 项单元/集成/HTTP 测试
scripts/verify.py      Compose verify 验收脚本
Dockerfile / docker-compose.yml
```
