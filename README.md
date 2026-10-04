# 星载归档库 · 维护快照导入前审查服务

在把维护快照导入归档库之前，审查员必须确认**指定表根**下的三类页面互不共用：

* 表 B-tree 页面（内部页 `0x05` / 叶页 `0x0d`）
* 行的溢出负载页（overflow chain）
* 空闲页干链（free-page trunk chain）及其悬挂的空闲叶页

任何“活页重复归属 / 成环 / 回指祖先 / 进入空闲链 / 溢出链长度不符 /
行键越界”都会被拒绝，并给出**稳定的首个违规证据**（违规码、页号、页内偏移、
首个原始字节）。

仅接受满足以下条件的快照：

| 策略 | 要求 |
| --- | --- |
| 文件格式 | SQLite 3（魔数 `SQLite format 3\0`） |
| 页大小 | 512、1024、2048 或 4096 字节 |
| 保留字节 | 每页 0 字节 |
| 自动清理 | 关闭（非 auto-vacuum / 非 incremental-vacuum） |
| 提交大小 | 解码后 ≤ 512 KiB 的 Base64 |

## 它做了什么

`app/verifier.py` **不依赖 SQLite 库**解析镜像，而是按
[文件格式文档](https://www.sqlite.org/fileformat2.html)逐字节：

* 校验 100 字节文件头（魔数、页大小、保留字节、auto-vacuum 标志、页数、
  空闲链表头、根页范围）；
* 递归遍历表内部页 / 叶页：8/12 字节 B-tree 页头、单元指针数组、
  变长整数（varint）、叶页单元 `payload-length / rowid / record`；
* 按官方 *payload locality* 公式（`U=页大小, X=U-35, M=((U-12)*32/255)-23,
  K=M+((P-M) mod (U-4))`）拆分本地负载与溢出负载；
* 逐跳跟随溢出页，校验每页 `next` 指针、链是否**恰好**覆盖声明负载
  （提前终止、多余续页、成环、越界、与活页/空闲页共用均拒绝）；
* 解析空闲页干链（trunk 的 `next` + 叶子指针数组）并与活页/溢出页做
  归属交集检查；
* 校验单元边界：指针去重、指针必须落在单元内容区、单元不得相互重叠、
  指针数组不得侵入单元内容区；
* 校验行键：叶页 rowid 严格递增；内部页分隔键严格递增；利用“分隔键 =
  左子树最大 rowid”的不变量向下传播子树 `[low, high]` 边界，任何越界
  行键都定位到该 rowid varint 的页内偏移；
* 每个被触及的页面记录**唯一归属角色、引用来源页与引用位置**；
* 拒绝是一次性的：`first_violation` 永远是本次提交遇到的第一个违规点，
  每次提交生成新的 submission id，不会复用旧的成功结论。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 审查页面（提交表单、逐页归属表、溢出链、行键范围、首个违规） |
| GET | `/api/health` | 健康端点 |
| POST | `/api/verify` | 提交 `{"snapshot": "<base64>", "root_page": <int>}` |
| GET | `/api/submission/<id>` | 按提交编号取回裁决 JSON |
| GET | `/view/<id>` | 预载某次提交的审查页面（含**无 JS** 的服务端证据块） |

成功返回 HTTP 200；策略性拒绝返回 422；请求格式错误返回 400；
超过 512 KiB 返回 413。

## 运行

仅依赖 Python 3.11 标准库，无需安装第三方包。

```bash
# 直接运行服务
python3 -m app.server --host 0.0.0.0 --port 8080

# 运行全部检查（构建检查 + 单元测试 + API/HTTP 冒烟），按退出码报告
python3 verify.py
echo $?
```

Docker / Compose：

```bash
docker compose up --build web            # 启动审查服务：http://localhost:8080
docker compose up --build verify         # 一次性验收门，结束即退出，用退出码报告
```

`verify` 服务在容器间对 `web` 的健康端点与提交接口做真实 HTTP 冒烟，
环境变量 `STARBORNE_BASE_URL` 指向被测服务（未设置时冒烟脚本会在本机临时
起服务）。

## 验收场景映射

| 场景 | 构造 | 期望首个违规（示例，随镜像布局变化） |
| --- | --- | --- |
| 合法多级表页 + 跨页 BLOB | `build_valid_snapshot()`：1400 行、3 条 9000B BLOB 及 600B 负载 | ACCEPTED，行键 `1…1400`，归属唯一，溢出链恰好覆盖 |
| 共享溢出页 | 让第二个溢出单元的指针指向第一个单元的溢出页 | `OVERFLOW_SHARED`，定位在**引用方**叶页的溢出指针偏移 |
| 祖先回指 | 内部页 right-most 指针指向自身 | `BTREE_ANCESTOR_BACKPOINTER`，定位内部页 right-most 字段 |
| 键界越界 | 将有界叶页最后一个 rowid 等长改写为超过分隔键 | `KEY_RANGE_CONFLICT`，定位该 rowid varint |
| 活页进入空闲干链 | 文件头空闲链表头指向一个活叶页 | `LIVE_PAGE_ON_FREELIST`，定位 page 1 offset 32 |

四类拒绝均通过 `tests/test_verifier.py` 与 `verify.py` 断言：
**直接校验结果 == `/api/verify` JSON == `/view/<id>` 页面（含原始 HTML
中的服务端证据标记）**。

## 目录

```
app/
  verifier.py          字节级 B-tree / 溢出 / 空闲链校验器
  snapshot_builder.py  用真实 sqlite3 造合法镜像 + 手术式破坏
  server.py            标准库 HTTP 服务（API + 提交留档）
  web/index.html       审查页面（零外部资源，内嵌 JSON + SSR 证据块）
tests/test_verifier.py 33 个测试：策略头、归属、结构破坏、HTTP 冒烟
verify.py              构建检查 + 测试 + API/HTTP 冒烟的一次性验收门
```
