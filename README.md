# 机载维护镜像 · 链接闭合审计（Link Closure Audit）

离线装载前，对**按命令行顺序**给出的至多 12 个 Base64 编码的 **ELF64 ET_REL
小端 x86-64 可重定位对象**或 **GNU ar 静态归档（无压缩成员）**做原始字节校验与
左至右链接闭包裁决：循环依赖遗漏、两个强定义被静默选一、损坏归档索引、
最终未定义符号、非法成员等一律拒绝，并给出**首次触发位置、抽取成员顺序与
每轮未定义集合**证据。结论按稳定审计标识冻结，可随时按标识重开。

## 目录

```
backend/            FastAPI 服务（无第三方 ELF/ar 库，全部手写字节解析）
  app/elfparser.py  ELF64/ET_REL + GNU ar 解析与严格校验
  app/linker.py     左至右链接裁决（强/弱/COMMON、归档索引抽取、成组反复扫描）
  app/service.py    输入校验 + 审计编排（拒绝结论也冻结）
  app/storage.py    SQLite 冻结结论
  app/fixtures.py   纯字节合成 x86-64 ET_REL / GNU ar（演示与测试固件）
  tests/            解析规则与链接裁决测试（50 例）
frontend/           Vite 原生 JS 页面（真实 API，无框架）
verify/             一次性验证服务入口
docker-compose.yml  backend + frontend + verify
Dockerfile.verify   verify 服务镜像
```

## 链接语义（与 GNU ld 行为对齐，已用本机 binutils 实验验证）

| 情形 | 规则 |
| --- | --- |
| ET_REL 对象 | 命令行位置整体装入 |
| 普通归档 | 经过时**按 GNU 符号索引**抽取成员；同一归档内反复扫描至本归档不再新增成员 |
| 成组输入 | 相同 `group` 标签且**连续**的输入，按顺序整组反复扫描，直到一轮无新增（未定义集合不再变化） |
| 强定义 | 每个外部符号至多一个强定义；第二个强定义首次出现即拒绝 |
| 弱定义 | 仅占位；强定义后到则覆盖弱定义，弱定义后到则静默忽略 |
| COMMON | 暂定定义，可合并；遇强定义被满足 |
| 弱未定义引用 | 不抽取归档成员；最终残留只报告、不判错 |
| 归档索引 | ranlib 允许同一符号出现在多个成员项中（抽取首个命中）；但每条 (符号,成员) 对必须真实存在，每个成员定义的全局/弱符号必须被索引覆盖 |

> 已用 GNU ld 验证的边界：归档内后向成员自动抽取；跨归档真循环普通顺序失败、
> `--start-group` 成功；弱引用不抽取；非 ALLOC 调试节符号仍按索引抽取；
> 两个成员都被抽取时重复强定义仍报错。

## 严格字节校验（拒绝点均带首次位置）

- ELF：魔数、EI_CLASS=64、EI_DATA=LSB、ET_REL、EM_X86_64、EV_CURRENT；
  节头表边界、e_shstrndx、节数据边界、.symtab 的 sh_link/sh_info/entsize、
  st_name 字符串下标、局部/全局排序、SHN_XINDEX 等。
- ar：`!<arch>\n` 魔数、成员头 60 字节与 `` `\n `` 结束标记、十进制/八进制字段、
  成员数据与对齐填充边界、GNU `//` 名称表（唯一性、`/\n` 终止、UTF-8）、
  `/` 符号索引（大端计数、偏移项数与名称数一致、偏移必须指向普通成员头、
  与成员 .symtab 交叉核对）。拒绝 thin archive（`!<thin>`）、BSD `#1/`、
  `/SYM64/`、`__.SYMDEF` 及压缩成员。

## HTTP API

| 方法/路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查 |
| `POST /api/audits` | 提交 `{audit_id, audit_type:"link_closure", inputs:[{name,data_b64,group?}]}` |
| `GET /api/audits/{audit_id}` | 按标识重开冻结结论 |
| `GET /api/audits/{audit_id}/fix-suggestion` | 修复建议：仅基于原冻结输入枚举相邻未分组归档段重裁（只读） |
| `GET /api/audits` | 列出冻结标识 |
| `GET /api/demo/cycle` | 页面示例：成组后闭合的跨归档循环 |

- 通过：`201`，`status:"accepted"`；
- 二进制/链接规则拒绝：`422`，`status:"rejected"`，结论**同样冻结**；
- 请求级错误（Base64、标识、数量>12、组不连续）：`400/413/422`，不冻结；
- 重复提交同一标识：`409` 且返回既有冻结结论（`frozen:true`），不被覆盖。

裁决证据字段：`extraction_order`（序号、归档、成员、命中索引符号、抽取前后
未定义集合、是否触发错误）、`rounds`（归档逐趟/组逐轮的抽取与未定义集合）、
`resolutions`、`definitions`、`weak_unresolved`；拒绝时 `error.location`
为首触发位置，`error.evidence` 含冲突双方或未定义集合。

## 修复建议（相邻归档成组）

详情页对拒绝结论提供「分析相邻归档成组修复建议」入口，对应
`GET /api/audits/{audit_id}/fix-suggestion`（只读，不改写任何冻结结论）：

- 仅接受原拒绝原因为最终未定义（`UNDEFINED_SYMBOL`）且原始输入仍随冻结
  留存、可重放的审计；否则返回 `409` 与明确原因
  （`NOT_UNDEFINED_REJECTION` / `INPUTS_NOT_REPLAYABLE`）。
- 仅基于原冻结输入，枚举全部「两个及以上连续、未分组 GNU ar 归档」候选段，
  将该段按既有成组语义（`--start-group` 反复扫描至收敛）重新裁决。
- 返回可使裁决通过的**最短段**（等长按起始输入位置稳定选择）：段首尾位置、
  段内归档名、建议组标签、成组重裁后的抽取顺序/轮次，以及消失的未定义集合。
- 无可行段时返回 `200` + `status:"no_suggestion"` 与明确原因
  （`NO_CANDIDATE_SEGMENT` 无候选段、`NO_FEASIBLE_SEGMENT` 重放仍残留未定义、
  `DUPLICATE_STRONG_IN_REPLAY` 候选重放出现重复强定义），并附各候选段重放结果。
- 原始提交输入随冻结一并留存在独立表 `audit_inputs`（功能上线前冻结的结论
  无留存，按 `INPUTS_NOT_REPLAYABLE` 处理）；按标识重开的结论内容不受影响。

## 本地运行

```bash
# 后端
cd backend
pip install -r requirements.txt
AUDIT_DB=/tmp/audits.db uvicorn app.main:app --port 8000

# 前端（开发服务器，/api 与 /health 代理到 8000）
cd frontend
npm install && npm run dev
# 生产构建：npm run build（dist/ 可由任意静态服务器托管，代理 /api → backend）
```

## Compose

```bash
docker compose up --build
# backend  :8000 （/health）
# frontend :8080 （nginx 托管 dist 并代理 /api、/health）
# verify   一次性运行：解析规则测试 + 前端构建检查 + 归档闭合 API/HTTP 冒烟
```

## verify 服务

`verify` 在一次运行中顺序执行：

1. `pytest` 解析规则测试（ELF/ar 边界、名称表、符号表、索引损坏）；
2. `vite build` 前端构建检查；
3. 等待 `backend` 健康端点；
4. HTTP 冒烟：成组循环闭合（accepted）、不成组残留未定义（rejected）、
   重复强定义（DUPLICATE_STRONG，首触发位置）、损坏索引（CORRUPT_BINARY）、
   冻结与按标识重开（201 → 409 → 200）；
5. 修复建议：跨归档循环拒绝取得唯一最短段（段 #2→#3、消失未定义集合、
   重裁抽取顺序，且原冻结结论不变）、无解段与候选重放重复强定义的明确原因、
   非该类拒绝（含既有成功审计）409 且重开内容保持原状。

全部通过退出码 `0`，任一失败非零。单独复跑：

```bash
docker compose run --rm verify
```

本机无 Docker 时可直接等价运行：

```bash
AUDIT_BACKEND_URL=http://127.0.0.1:8000 WORKSPACE_ROOT=$PWD python3 verify/run_verify.py
```
