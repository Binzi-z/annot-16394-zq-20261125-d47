# -*- coding: utf-8 -*-
"""冒烟测试：手工串一条小账本，验证主路径与四态证书。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    Keys, Service, Auditor, NaiveAuditor,
    build_certificate, verify_certificate, replay_prefix,
    synthetic_row_hash, CONFLICT, NO_CONFLICT, NEGATED, UNPROVEN,
)

LEDGER = "drill-ledger-001"
keys = Keys.generate(b"smoke-seed")
svc = Service(LEDGER, keys)

# 服务端先造好 0..7 的诚实链，审计员侧扣留 seq5 制造缺段
made = {seq: svc.emit(seq, synthetic_row_hash(LEDGER, seq, f"body{seq}".encode()))
        for seq in range(8)}

aud = Auditor(LEDGER, keys, block_size=4)
for seq in (0, 1, 2, 3, 4):
    aud.ingest(made[seq])
assert aud.watermark() == 5, aud.watermark()
print("watermark 顺序发布 =", aud.watermark())

# 缺段：seq6 乱序先到（孤立父摘要），不能盖过缺段 5
a6 = svc.emit_fork(6, synthetic_row_hash(LEDGER, 6, b"late"), b"\xdd" * 32)
aud.ingest(a6)
assert aud.watermark() == 5, aud.watermark()
print("缺段后水位停在 =", aud.watermark(), "(后到签名段不能盖过缺段)")

# 超水位封存必须被拒
try:
    aud.issue_seal(svc, 6)
    raise AssertionError("应当拒绝超水位封存")
except PermissionError as e:
    print("超水位封存被拒:", str(e)[:36], "...")

# 水位 4 处封存（最早缺段之前可封存）
seal4 = aud.issue_seal(svc, 4)
ok, msg = verify_certificate(build_certificate(aud, 3), keys)
assert ok, msg
print("水位4封存 + 证书复核:", msg)

# 补齐 seq5（诚实版本，父链可接 seq4）
aud.reset_access()
aud.ingest(made[5])
assert aud.watermark() == 6, aud.watermark()
touched = aud.ingest_touched_bids()
print("补齐单段触达块 =", touched, "(应只含 seq5 所在块)")
assert touched == {5 // 4}, touched

# seq6 的诚实版本送达后水位到 7
aud.ingest(made[6])
assert aud.watermark() == 7

# 同水位两分支冲突：seq=7 诚实公告 vs 分叉公告
a7a = made[7]
a7b = svc.emit_fork(7, synthetic_row_hash(LEDGER, 7, b"branch-B"),
                    made[6].link_digest())
aud.ingest(a7a)
aud.ingest(a7b)
cert = build_certificate(aud, 7, [a7a, a7b])
ok, msg = verify_certificate(cert, keys)
print("分叉证书 verdict =", cert.verdict, "| 复核:", msg)
assert cert.verdict == CONFLICT and ok, (cert.verdict, msg)

# 撤回其中一个分支 -> 剩单根 = 无冲突
rev = svc.revoke(7, a7b.version)
aud.ingest(rev)
cert2 = build_certificate(aud, 7, [a7a, a7b])
ok2, msg2 = verify_certificate(cert2, keys)
print("撤回一分支后 verdict =", cert2.verdict, "| 复核:", msg2)
assert cert2.verdict == NO_CONFLICT and ok2, (cert2.verdict, msg2)

# 坏签名公告 -> 已否定
bad = svc.tamper_ann(a7a, body_hash=synthetic_row_hash(LEDGER, 7, b"tampered"))
aud.ingest(bad)
cert3 = build_certificate(aud, 7, [bad])
ok3, msg3 = verify_certificate(cert3, keys)
print("坏签名证书 verdict =", cert3.verdict, "| 复核:", msg3)
assert cert3.verdict == NEGATED and ok3, (cert3.verdict, msg3)

# 缺段见证证书（未证）
cert4 = build_certificate(aud, 99)
ok4, msg4 = verify_certificate(cert4, keys)
print("缺段见证 verdict =", cert4.verdict, cert4.reason, "| 复核:", msg4)
assert cert4.verdict == UNPROVEN and ok4, (cert4.verdict, msg4)

# 朴素实现互校 + 前缀重放
naive = NaiveAuditor(LEDGER, keys)
for rec in [*made.values(), a6, a7b, rev, bad, seal4]:
    naive.ingest(rec)
assert naive.watermark() == aud.watermark(), (naive.watermark(), aud.watermark())
prefix = [made[s] for s in range(6)]
assert replay_prefix(prefix, LEDGER, keys, 4).watermark() == 6
print("朴素实现水位一致 =", naive.watermark())
print("SMOKE OK")
