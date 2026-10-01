# ELF64 重定位载荷审计服务

面向载荷发布前审查的 **ELF64 小端 x86-64 重定位审计** 服务，同时支持可重定位目标文件（ET_REL）与供应商已链接的 **位置无关可执行映像（ET_DYN / PIE）**。审查员提交稳定审计标识、Base64 文件、代码装载基址与被引用外部符号地址后，可读取冻结结论、重定位后的代码摘要及按位置排序的字节补丁；任何违约都会定位到**首个违约位置**并清除该标识下旧的成功结论，**绝不生成部分结果（不返回前缀补丁）**。

纯 Python 3.11 标准库实现，无第三方依赖。

## 审计规则（逐项强校验）

### ET_REL 可重定位目标文件

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

### ET_DYN 位置无关可执行映像（PIE）

文件必须同时满足：

1. ELF64（`EI_CLASS=2`）、小端（`EI_DATA=1`）、`ET_DYN`、`EM_X86_64`，程序头表合法；
2. 存在 `PT_LOAD`，且其中**恰好一个**带 `PF_X`（唯一允许落入补丁的可执行映射）；`PT_DYNAMIC` 唯一且完整在文件内、以 `DT_NULL` 结束；
3. `PT_DYNAMIC` 必须提供 `DT_RELA / DT_RELASZ / DT_RELAENT / DT_SYMTAB / DT_STRTAB / DT_STRSZ / DT_SYMENT`，`DT_RELAENT=24`、`DT_SYMENT=24`、`DT_RELASZ` 为 24 的非零整数倍；
4. RELA / dynsym / dynstr 各表虚拟地址区间经 PT_LOAD 虚拟地址→文件偏移换算后，必须完整落在某个 PT_LOAD 的**文件映像（filesz）**内；
5. 仅处理 `R_X86_64_RELATIVE`（符号索引必须为 0，写 8 字节 `B + A`，B=装载偏移）与 `R_X86_64_GLOB_DAT`（写 8 字节 `S + A`；`SHN_UNDEF` 符号必须由用户提供地址，PIE 内定义符号取 `B + st_value`）；
6. 逐项核验：动态表边界、条目完整性、符号引用（dynsym/dynstr 越界、名称缺失）、加数、**写入目标区间必须完整落在唯一可执行 PT_LOAD 的文件映像内**；落入其他 PT_LOAD（如 RW 数据映射）、仅 memsz 支撑的零填区（.bss）或完全无映射一律拒绝；
7. 所有补丁区间（按文件偏移，等价于按虚拟地址）两两不得重叠。

页面按**写入虚拟地址**稳定展示每个补丁，并同时给出换算后的文件偏移、所属 PT_LOAD、运行地址 `P = B + vaddr`、计算值与写入前后字节，便于审查员复算文件位置与运行地址的对应关系。

两类流程均为两阶段：先做全部结构性/范围性检查（失败即报告首个违约项），再检查补丁重叠，全部通过后才一次性落补丁。

## HTTP 接口

- `GET /` — 审计页面
- `GET /healthz` — 健康状态（含已冻结通过/拒绝计数）
- `POST /api/audit` — 提交审计（JSON）
- `GET /api/result/<audit_id>` — 凭稳定标识读回冻结结论或首个违约定位

提交示例：

```json
{
  "audit_id": "payload-2026-09-29-001",
  "file_base64": "<Base64 编码的 .o>",
  "load_base": "0x400000",
  "symbols": {"ext_foo": "0x500000", "memcpy": "0x400200"}
}
```

`load_base` 与符号地址接受十进制或 `0x` 十六进制字符串。ET_REL 下 `load_base` 为代码装载基址；ET_DYN 下为 PIE 装载偏移（B，通常为运行期随机基址）。成功响应逐项给出 `S / A / P / value / before_hex / after_hex` 与补丁前后摘要（ET_REL 为 `.text`，ET_DYN 为唯一可执行 PT_LOAD 映像的 SHA-256）、按位置排序的 `patches`（ET_REL 按节偏移；ET_DYN 按写入虚拟地址，含文件偏移与所属映射）以及 64 字符的冻结结论（对全部输入与补丁结果做规范化哈希，可独立复算）。违约响应给出 `stage / code / message / entry_index / rela_section / rela_index / offset / type / symbol`，服务端同步清除该标识下旧成功记录。

## 本地运行（无需 Docker）

```bash
python3 -m app.server                      # 默认 0.0.0.0:8080
HOST=127.0.0.1 PORT=9090 python3 -m app.server
python3 -m unittest discover -s tests -v   # 81 项测试
```

## 容器运行（宿主端口可配置）

```bash
docker compose up --build                  # 默认宿主端口 8080
HOST_PORT=9090 docker compose up --build   # 自定义宿主端口
```

## 验收组件 verify（一次运行，退出码结束）

`verify` 服务在同一次运行中依次核对：

1. **测试**：`python -m unittest discover` 全量（81 项）；
2. **构建**：全部源码字节编译 + 关键模块导入 + 页面存在；
3. **HTTP 冒烟**：健康检查、页面、
   - ET_REL 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   - ET_REL 重叠写入拒绝（`patch_overlap`，定位 `entry_index=1`，旧成功结论被清除）；
   - ET_REL PC32 有符号 32 位溢出拒绝（`pc32_overflow`），无部分结果；
   - ET_DYN 相对（`R_X86_64_RELATIVE`）与全局（`R_X86_64_GLOB_DAT`）动态重定位成功，逐项给出写入虚拟地址/文件偏移/所属唯一可执行映射；
   - ET_DYN 跨映射目标拒绝（`target_not_executable`，定位首项，旧成功结论被清除）。

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
app/elfaudit.py        ELF 解析 / 校验 / 重定位计算 / 冻结结论核心
app/server.py          页面、审计 API、健康检查
app/static/index.html  审计页面
tests/elfbuild.py      内存构造 ELF64 ET_REL / ET_DYN 的测试夹具
tests/test_audit.py    ET_REL 单元/集成/HTTP 测试（47 项）
tests/test_audit_dyn.py ET_DYN 动态重定位测试（34 项）
scripts/verify.py      Compose verify 验收脚本
Dockerfile / docker-compose.yml
```
