# 公开审计承诺的最小缺口见证 —— 实现说明

仅依赖 Python 3.12 标准库（`hashlib` / `hmac` / `json` / `dataclasses` /
`tempfile` / `itertools` / `random` / `time`），原生 Windows 可直接运行，
无第三方依赖。

## 1. 文件

| 文件 | 角色 |
| --- | --- |
| `core.py` | 生成器（`Service`）、分块审计器（`Auditor`）、朴素全量审计器（`NaiveAuditor`）、只追加日志（`LedgerJournal`）、最短边界证书构建器（`build_certificate`）与独立复核器（`verify_certificate`）、历史重放（`replay_prefix`） |
| `smoke_test.py` | 手工小账本冒烟，覆盖四态结论主路径 |
| `audit_exhaustive.py` | 小账本穷举：版本排列、撤回子集、引用重复、分叉、三类否定、缺段、检查点、前缀重放、JSONL 往返、封存篡改 |
| `audit_large.py` | 80000 合成行 + 三处远隔缺段：区间访问计数证明、与朴素实现全量一致性、冲突/锚定证书、历史重放、落盘重载 |
| `run_all.py` | 依次运行上述三套测试 |

运行：

```
python sealed_ledger/smoke_test.py
python sealed_ledger/audit_exhaustive.py
python sealed_ledger/audit_large.py
rem 或一键
python sealed_ledger/run_all.py
```

## 2. 信任模型与签名原语

* 每条记录按"类型自描述长度前缀编码"（`enc`）做规范化，再用域分离标签
  （`ann-v1` / `rev-v1` / `cp-v1` / `seal-v1` / `genesis-v1` / `row-v1`）
  做 SHA-256 与 HMAC-SHA256，杜绝跨结构摘要混用。
* 演练用 HMAC 充当数字签名：服务密钥签 `Ann/Rev/Seal`，独立检查点权威
  密钥签 `Cp`，复核器持验证密钥、以 `hmac.compare_digest` 常数时间验签。
  签名/验签接口相互独立，真实部署把 HMAC 换成 Ed25519 即可，协议其余部分
  不变（3.12 标准库不含非对称签名原语，故演练采用 HMAC）。

## 3. 记录与绑定语义

* `Ann(ledger, seq, version, body_hash, parent_digest, sig)`：版本化段公告。
  身份摘要 `digest()` 只由内容决定，与投递顺序/次数无关；`parent_digest`
  把段绑定到父公告链接摘要（`seq=0` 绑定公开创世锚），形成父摘要链。
* `Rev(..., revokes, sig)`：版本撤回，`revokes` 精确绑定被撤公告身份摘要；
  撤回自身也签名、也只追加。撤回集以聚合摘要 `rev_root` 绑定进检查点与
  封存承诺。
* `Cp(water, root, rev_root, sig)`：可信检查点，权威对水位处的规范根与
  当时撤回聚合签名；锚之后的公告以检查点 `root` 为新虚拟创世，证书只需
  覆盖锚后窗口（历史由权威背书）。
* `Seal(water, root, rev_root, anchor_cp_digest, parent_seal_digest, sig)`：
  封存承诺，同时绑定链根、窗口撤回根、检查点锚摘要与父封存承诺，形成
  封存链。任何字段被改都会验签失败或聚合失配。

## 4. 缺段规则（"不能用后到有签名的段盖过缺段"）

* 水位定义为从锚出发、按父摘要可连续解析到达的最长前缀长度，即最早缺段
  所在 seq。乱序先到的远隔段即使签名合法，也因父链无法解析而不推进水位。
* `Auditor.can_seal(w)` 要求 `w <= watermark()`；`issue_seal` 对超水位请求
  抛 `PermissionError`。缺段补齐后水位才继续前进，并停在下一个缺段处。
* 分块实现中每块独立维护"块内连续可达水位"，块间只通过边界根缓存
  `boundary_roots` 以 O(1) 传递链接集合；撤回/替换使某块失效时只清除其
  边界根并把下游块标脏（无块访问事件），查询期惰性重算。

## 5. 最短边界证书与四态结论

对同一水位的两个分支声称，`build_certificate` 选取最近检查点（否则创世
锚），只在边界窗口 `[anchor_water, claim_seq]` 内取证，并剪枝到支撑结论
所必需的最少记录：

| 结论 | 触发条件 |
| --- | --- |
| `CONFLICT` | 两个存活声称各自锚定重放得到不同根（冲突被证实） |
| `NO_CONFLICT` | 重放只得到单根（同一公告/引用重复不构成冲突） |
| `NEGATED` | 声称全部被签名记录否定，逐声称标注 `BAD-SIG` / `REVOKED` / `UNRESOLVABLE`（父摘要断裂） |
| `UNPROVEN` | 窗口内存在缺段或无存活声称，既不能证明也不能否定 |

否定优先于未证；`UNPROVEN` 与 `NEGATED` 严格区分。证书元素按
`(类型, 摘要)` 确定性排序，故与投递顺序无关、逐字节可复现。

### 独立复核器 `verify_certificate`

只凭证书与验证密钥：①逐条验签（坏签名公告仅在被声明为 `BAD-SIG` 否定
证据时允许）；②核对锚；③用证书内记录独立重放，结论、原因、逐声称
`claim_outcomes` 必须逐字一致；④有封存承诺时核对水位、链根、窗口撤回根、
锚摘要、父封存链；⑤**最小性检验**：
- 常规路径 `verify_certificate` 采用 O(k) 结构化检验——独立重算"必要
  记录闭包"（每条公告必须是被评估声称或其到锚的支撑祖先；每条撤回必须
  指向被评估声称，或在有封存时落在窗口内参与撤回根聚合），任何冗余都
  判失败；
- 小账本另用 `verify_minimality_peel` 做 O(k²) 强剥离检验：逐条移除证书
  记录，任一次移除后结论仍成立即判非最小。
检查点锚定证书的历史撤回由 `Cp.rev_root` 背书，封存 `rev_root` 仅覆盖
锚后窗口，因此短证书即可独立复核。

## 6. 旧水位重建

全部记录只追加进 `LedgerJournal`（JSONL）。`replay_prefix(records[:n])`
确定性重放任意前缀，`rebuild_historical_certificate` 用"当时的记录"重建
证书，与当时在线输出逐字节相同；穷举测试对每个 journal 前缀、多个旧水位
逐一比对，并同时用朴素实现交叉验证结论。

## 7. 分块局部性（大规模测试如何取证）

`Auditor.access_events` 记录每次块触达（`ann/rev/recompute/cp` 为摄入
路径，`read/seal` 为查询路径）。幂等判断先于计数，重复投递零访问。
`audit_large.py` 对 80000 行、块大小 4096、三处远隔缺段逐记录断言：

* 每条公告摄入触达块集合恰好为 `{seq // block_size}`，无块间级联；
* 单段补齐、单段撤销、替换版本的摄入路径同样只触达相关单块；
* 全量水位、撤回集、抽样证书结论、封存根与 `NaiveAuditor`（无分块、每次
  全量重扫的对照预言机）完全一致。

## 8. 已知边界

* HMAC 是对称演练签名，不提供非对称不可否认性；生产替换为 Ed25519。
* 分块引擎的块锚只识别块边界检查点；任意水位检查点由证书层与朴素实现
  完整支持（边界检查点不影响任何安全结论，只影响块引擎的锚点选择）。
