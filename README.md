# 公开审计承诺的最小缺口见证

获确认的题面位于 task/PROMPT.txt。使用原生 Windows 和 Python 3.12 标准库，
输入与验证均使用本地合成数据，无第三方依赖。

## 交付内容（`sealed_ledger/`）

- `core.py` —— 生成器 `Service`、分块审计器 `Auditor`、朴素全量对照实现
  `NaiveAuditor`、只追加日志 `LedgerJournal`、最短边界证书构建器
  `build_certificate`、独立复核器 `verify_certificate`（含逐条剥离的
  最小性检验）、历史前缀重放 `replay_prefix`。
- `smoke_test.py` —— 四态结论（CONFLICT / NO_CONFLICT / NEGATED /
  UNPROVEN）主路径冒烟。
- `audit_exhaustive.py` —— 小账本穷举：版本排列、撤回子集、引用重复、
  分叉冲突、三类否定（坏签名/撤回/父摘要断裂）、缺段封存规则、检查点
  锚定、每个 journal 前缀的旧水位证书逐字节重建、JSONL 往返。
- `audit_large.py` —— 80000 合成行、三处远隔缺段：用块访问计数证明
  单段补齐/撤销/替换只触达相关单块，并与朴素全量实现的水位、根、
  证书结论逐项对齐。
- `DESIGN.md` —— 信任模型、绑定语义、四态判定、最小性检验、分块局部性
  与已知边界的完整说明。

## 运行

```
python sealed_ledger/smoke_test.py
python sealed_ledger/audit_exhaustive.py
python sealed_ledger/audit_large.py
python sealed_ledger/run_all.py
```
