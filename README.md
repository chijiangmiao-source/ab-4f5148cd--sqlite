# 星载归档库快照导入复核

导入维护快照前，复核员需确认**指定表根**下的 B-tree 页面、溢出负载（overflow）
与空闲链（freelist）互不共用页面，避免后续写入损坏仍可读取的遥测记录。

本服务接收不超过 **512KiB** 的 Base64 SQLite 快照与表根页号，通过 API 与页面
展示：裁决、逐页归属、引用来源、行键范围与首个原始字节错误。

## 复核规则

**快照准入**（否则拒绝）：

- `SQLite format 3` 魔数（仅 SQLite 3）
- 页大小 512–4096 字节且为 2 的幂
- 每页保留字节为 0
- 非自动清理模式（头部 52/64 偏移均为 0）
- 文件大小为页大小整数倍

**解析范围**：数据库头部、表内部页（0x05）、表叶页（0x0d）、变长整数、
本地/溢出负载切分、溢出页链、空闲页干链（trunk chain）。

**结构校验**：

- 单元边界与指针数组（越界指针、指针数组溢出、内容区非法均拒绝）
- 子树行键严格递增（叶内递增；内部分隔键 ≥ 左子树最大键且 < 右子树最小键）
- 溢出链恰好覆盖声明负载（页数精确、末页 next=0，截断/超长均拒绝）
- 页面唯一归属：活页重复归属、B-tree 成环（祖先回指）、活页进入空闲链均拒绝
- 空闲链页数须与头部声明一致

**首个违规证据**：审计按确定顺序（头部 → B-tree 中序 → 溢出链 → 空闲链）
在首个违规处停止，稳定报告 `page`（页面号）、`offset`（绝对文件偏移）与
`bytes_hex`（该处原始字节）。每次提交都会原子替换服务端保存的结论——
失败的复核会清除旧的成功结论（`GET /api/audit/last` 可验证）。

## 运行

```bash
# 本地（无依赖，Python 3.11+）
python -m app.server            # http://127.0.0.1:8080
python -m unittest discover -v  # 代码测试
python scripts/smoke.py         # 针对运行中服务的 API/HTTP 冒烟

# Docker Compose：构建检查 + 代码测试 + API/HTTP 冒烟，verify 完成后退出
docker compose up --build --exit-code-from verify --abort-on-container-exit
echo $?   # 0 = 全部通过；非 0 = 存在失败
docker compose down
```

`verify` 服务：镜像构建阶段即运行单元测试（构建检查），启动后等待 `web`
健康检查通过，再次运行覆盖页面所有权场景的代码测试，随后执行
`scripts/smoke.py`（提交合法与违规快照、请求 `/health`、核对拒绝证据、
确认页面与接口展示同一首个违规证据），最后以退出码报告结果。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康端点，`{"status":"ok"}` |
| GET | `/` | 复核表单页面（JS 走 `/api/audit`，表单 POST 由服务端渲染同一证据） |
| POST | `/` | 表单提交（`snapshot_b64`, `root_page`），HTML 裁决页 |
| POST | `/api/audit` | JSON 提交；200 接受 / 422 拒绝 |
| GET | `/api/audit/last` | 最近一次裁决（首次提交前 404） |

`POST /api/audit` 请求体：

```json
{"snapshot_b64": "U1FMaXRl...", "root_page": 2}
```

响应（拒绝示例）：

```json
{
  "verdict": "rejected",
  "root_page": 2,
  "page_size": 1024,
  "page_count": 12,
  "error": {
    "code": "PAGE_OWNERSHIP_CONFLICT",
    "message": "page 6 is already owned as overflow (...) and cannot also be ...",
    "page": 6,
    "offset": 4609,
    "bytes_hex": "00000007...",
    "detail": {"first_kind": "overflow", "first_referenced_by": "...", "...": "..."}
  },
  "pages": [
    {"page": 2, "kind": "btree_root", "referenced_by": "requested table root",
     "reference_offset": null, "rowid_range": [1, 12]}
  ],
  "summary": {"btree_pages": 5, "overflow_pages": 2, "overflow_chains": 1,
              "freelist_pages": 3, "freelist_declared": 3,
              "rowid_min": 1, "rowid_max": 12}
}
```

## 错误码

| 代码 | 含义 |
| --- | --- |
| `HEADER_TOO_SHORT` / `BAD_MAGIC` | 头部过短 / 非 SQLite 3 |
| `PAGE_SIZE_UNSUPPORTED` | 页大小越出 512–4096 或非 2 的幂 |
| `RESERVED_BYTES_PRESENT` | 存在保留字节 |
| `AUTO_VACUUM_ENABLED` | 自动清理/增量清理模式 |
| `TRUNCATED_PAGE` | 文件大小非页整数倍 |
| `ROOT_PAGE_OUT_OF_RANGE` | 根页越界 |
| `NOT_A_TABLE_BTREE_PAGE` | 根/子页非表 B-tree 页 |
| `CELL_POINTER_ARRAY_OVERFLOW` / `CONTENT_AREA_INVALID` / `CELL_POINTER_OUT_OF_BOUNDS` | 指针数组与单元边界 |
| `TRUNCATED_CELL` | 截断单元（varint/负载越页） |
| `ROWID_NOT_INCREASING` | 叶内行键未严格递增 |
| `KEY_BOUND_CONFLICT` | 分隔键与子树键范围冲突 |
| `CHILD_PAGE_OUT_OF_RANGE` | 子页号越界 |
| `OVERFLOW_PAGE_OUT_OF_RANGE` / `OVERFLOW_CHAIN_TRUNCATED` / `OVERFLOW_CHAIN_OVERRUN` | 溢出链越界/截断/超长 |
| `PAGE_OWNERSHIP_CONFLICT` | 活页重复归属（含共享溢出页、祖先回指成环） |
| `LIVE_PAGE_ON_FREELIST` | 活页进入空闲链 |
| `FREELIST_DUPLICATE` / `FREELIST_PAGE_OUT_OF_RANGE` / `FREELIST_TRUNK_LEAF_COUNT` / `FREELIST_COUNT_MISMATCH` | 空闲链完整性 |
| `BASE64_INVALID` / `SNAPSHOT_TOO_LARGE` / `ROOT_PAGE_INVALID` / `SNAPSHOT_MISSING` | 提交载荷问题 |

## 验收场景（`app/fixtures.py` + `scripts/smoke.py`）

合法快照：三级表 B-tree（根 2 → 内部页 11 → 叶 3/4，根右子叶 5），
rowid 7 携带 2500 字节 BLOB，恰好溢出到 6、7 两页；空闲干页 8 带叶 9、10。
违规快照逐一构造：共享溢出页、祖先回指、键界越界、活页进入空闲干链、
截断单元、根页越界、溢出链截断/超长、空闲链计数不符及各类头部违规；
每个场景断言接口与页面展示同一首个违规证据（错误码、页面号、偏移一致）。

## 布局

```
app/sqlite_audit.py   解析与审计核心（纯标准库）
app/fixtures.py       确定性快照构造器与验收场景
app/server.py         HTTP 服务（API + 页面 + 健康端点）
tests/                单元测试（审计器 + 服务）
scripts/smoke.py      API/HTTP 冒烟（verify 服务调用）
Dockerfile            构建检查：构建期运行单元测试
docker-compose.yml    web + verify（退出码报告结果）
```
