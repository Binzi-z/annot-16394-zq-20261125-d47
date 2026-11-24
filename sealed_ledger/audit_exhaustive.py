# -*- coding: utf-8 -*-
"""
小账本穷举测试（纯标准库）。

覆盖题面要求的全部小账本情形：
  1. 版本排列：同一 seq 多版本（替换）的全部投递排列/代表性乱序；
  2. 撤回组合：版本撤回集合的全部子集；
  3. 引用重复：公告/撤回/检查点重复投递的幂等性与证书逐字节稳定；
  4. 分叉同水位：CONFLICT / NO_CONFLICT 最短边界证书 + 独立复核 + 最小性；
  5. 否定路径：坏签名公告（BAD-SIG）、撤回（REVOKED）、父摘要断裂
     （UNRESOLVABLE）三类已否定，与未证（UNPROVEN）严格区分；
  6. 缺段规则：后到签名段不能盖过缺段；超水位封存被拒；
  7. 检查点锚定：锚后新虚拟创世、窗口作用域撤回根；
  8. 每个 journal 前缀重放：分块/朴素两实现水位一致，旧水位证书可按当时
     记录逐字节重建；
  9. JSONL 落盘重载一致；
 10. 封存承诺链（父封存摘要）与全部证书的独立复核结论。
"""
import itertools
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    Keys, Service, Auditor, NaiveAuditor, LedgerJournal,
    build_certificate, verify_certificate, verify_minimality_peel,
    rebuild_historical_certificate,
    replay_roots, merkle_root, revocation_root, make_checkpoint,
    synthetic_row_hash, genesis_anchor,
    CONFLICT, NO_CONFLICT, NEGATED, UNPROVEN,
)

LEDGER = "exhaustive-drill"
B = 4
KEYS = Keys.generate(b"exhaustive-seed")
STATS = {"checks": 0, "certs": 0, "verdicts": set()}


def check(cond, label):
    STATS["checks"] += 1
    if not cond:
        raise AssertionError("断言失败: " + label)


def fresh_pair(block_size=B):
    return (Auditor(LEDGER, KEYS, block_size), NaiveAuditor(LEDGER, KEYS))


def feed_both(records, block_size=B):
    aud, naive = fresh_pair(block_size)
    for rec in records:
        aud.ingest(rec)
        naive.ingest(rec)
    return aud, naive


def body(seq, tag=b""):
    return synthetic_row_hash(LEDGER, seq, b"body-" + str(seq).encode() + tag)


def expect_cert(cert, verdict):
    ok, msg = verify_certificate(cert, KEYS)
    check(ok, f"证书复核失败: {msg}")
    check(cert.verdict == verdict,
          f"verdict 期望 {verdict} 实际 {cert.verdict} ({cert.reason})")
    # 小账本证书很小：额外执行 O(k^2) 强剥离检验，证明每条记录都不可删
    ok, msg = verify_minimality_peel(cert, KEYS)
    check(ok, f"强剥离最小性检验失败: {msg}")
    STATS["certs"] += 1
    STATS["verdicts"].add(verdict)


# ---------------------------------------------------------------------------
# 1. 版本排列：N=2、每 seq 两个版本，4 条公告的全部 24 种投递排列
# ---------------------------------------------------------------------------

def test_version_permutations():
    svc = Service(LEDGER, KEYS)
    a00 = svc.emit(0, body(0, b"v0"))
    a01 = svc.emit(0, body(0, b"v1"))           # 替换版本
    a10 = svc.emit(1, body(1, b"v0"))
    a11 = svc.emit(1, body(1, b"v1"))
    base = [a00, a01, a10, a11]

    digests = set()
    for order in itertools.permutations(base):
        aud, naive = feed_both(list(order))
        check(aud.watermark() == naive.watermark() == 2, "全排列后水位=2")
        # 状态与投递顺序无关
        digests.add(aud.state_digest())
        # 每个 seq 最新两个版本同时在场 -> 同 seq 两版本即两个声称
        cert = build_certificate(aud, 1)
        expect_cert(cert, CONFLICT)
    check(len(digests) == 1, "状态与投递顺序无关")


# ---------------------------------------------------------------------------
# 2. 撤回组合：seq1 两个版本，撤回子集 2^2 全部枚举
# ---------------------------------------------------------------------------

def test_revocation_subsets():
    svc = Service(LEDGER, KEYS)
    a0 = svc.emit(0, body(0))
    a10 = svc.emit(1, body(1, b"a"))
    a11 = svc.emit(1, body(1, b"b"))
    versions = [a10, a11]

    for mask in range(4):
        recs = [a0, a10, a11]
        revoked = []
        for bit, ann in enumerate(versions):
            if mask & (1 << bit):
                rev = svc.revoke(1, ann.version)
                recs.append(rev)
                revoked.append(ann)
        aud, naive = feed_both(recs)
        check(aud.watermark() == naive.watermark(), "撤回后两实现水位一致")
        if mask == 3:
            # 两个版本全撤 -> seq1 无存活声称 -> 水位停在 1
            check(aud.watermark() == 1, "全撤后水位停在缺段处")
            cert = build_certificate(aud, 1, versions)
            expect_cert(cert, NEGATED)
            check(set(cert.claim_outcomes.values()) == {"REVOKED"}, "逐声称=REVOKED")
        else:
            check(aud.watermark() == 2, "有存活版本时水位前进")
            cert = build_certificate(aud, 1, versions)
            # 一声称存活一声称撤回 -> 单存活根 -> 无冲突
            expect_cert(cert, NO_CONFLICT if mask else CONFLICT)
        # 撤回根进入封存承诺并可独立复核
        seal = aud.issue_seal(svc, aud.watermark())
        scert = build_certificate(aud, aud.watermark() - 1)
        check(scert.seal is not None and scert.seal.water == seal.water,
              "封存承诺附在证书上")
        expect_cert(scert, scert.verdict)


# ---------------------------------------------------------------------------
# 3. 引用重复：每条记录重复 0..3 次的确定性随机序列
# ---------------------------------------------------------------------------

def test_duplicate_delivery():
    svc = Service(LEDGER, KEYS)
    recs = [svc.emit(i, body(i)) for i in range(6)]
    recs.append(svc.revoke(5, recs[5].version))
    rng = random.Random(20261125)
    baseline, _ = feed_both(recs)
    base_digest = baseline.state_digest()
    base_cert = build_certificate(baseline, 4).canonical_json()

    inflated = []
    for rec in recs:
        inflated.extend([rec] * (1 + rng.randint(0, 3)))
    rng.shuffle(inflated)
    aud, naive = feed_both(inflated)
    check(aud.state_digest() == base_digest, "重复投递状态幂等")
    check(naive.watermark() == aud.watermark() == 5, "撤回造成缺段水位=5")
    check(build_certificate(aud, 4).canonical_json() == base_cert,
          "重复投递下证书逐字节稳定")
    # 重复撤回/重复检查点同样幂等
    cp, _ = make_checkpoint(svc, aud, 4)
    before = aud.state_digest()
    for _ in range(3):
        aud.ingest(cp)
    check(aud.state_digest() == before, "重复检查点幂等")


# ---------------------------------------------------------------------------
# 4. 分叉同水位：冲突 / 无冲突 / 撤回解冲突
# ---------------------------------------------------------------------------

def test_fork_conflict():
    svc = Service(LEDGER, KEYS)
    a0 = svc.emit(0, body(0))
    a1 = svc.emit(1, body(1))
    fork = svc.emit_fork(1, body(1, b"fork"), a0.link_digest())
    aud, naive = feed_both([a0, a1, fork])
    check(aud.watermark() == naive.watermark() == 2, "分叉不影响连续水位")

    cert = build_certificate(aud, 1, [a1, fork])
    expect_cert(cert, CONFLICT)
    check(len(cert.records) == 3, "冲突证书最短：锚链两条+两声称共3公告")

    # 同一公告声称两次 -> 无冲突（引用重复不构成冲突）
    same = build_certificate(aud, 1, [a1, a1])
    expect_cert(same, NO_CONFLICT)

    # 撤回分叉 -> 解冲突
    rev = svc.revoke(1, fork.version)
    aud.ingest(rev)
    naive.ingest(rev)
    resolved = build_certificate(aud, 1, [a1, fork])
    expect_cert(resolved, NO_CONFLICT)
    check(aud.watermark() == naive.watermark(), "解冲突后水位一致")


# ---------------------------------------------------------------------------
# 5. 否定路径三分类 + 未证区分
# ---------------------------------------------------------------------------

def test_negation_paths():
    svc = Service(LEDGER, KEYS)
    a0 = svc.emit(0, body(0))
    a1 = svc.emit(1, body(1))

    # 5a. 坏签名公告
    bad = svc.tamper_ann(a1, body_hash=body(1, b"tampered"))
    aud, _ = feed_both([a0, bad])
    cert = build_certificate(aud, 1, [bad])
    expect_cert(cert, NEGATED)
    check(cert.claim_outcomes[bad.digest().hex()] == "BAD-SIG", "BAD-SIG 分类")
    check(aud.watermark() == 1, "坏签名段不推进水位")

    # 5b. 合法但被撤回
    aud2, _ = fresh_pair()
    rev = svc.revoke(1, a1.version)
    aud2.ingest(a0)
    aud2.ingest(a1)
    aud2.ingest(rev)
    cert2 = build_certificate(aud2, 1, [a1])
    expect_cert(cert2, NEGATED)
    check(cert2.claim_outcomes[a1.digest().hex()] == "REVOKED", "REVOKED 分类")

    # 5c. 父摘要断裂（引用一个窗口内不存在的父链接）
    orphan = svc.emit_fork(1, body(1, b"orphan"), b"\xaa" * 32)
    aud3, _ = fresh_pair()
    aud3.ingest(a0)
    aud3.ingest(orphan)
    cert3 = build_certificate(aud3, 1, [orphan])
    expect_cert(cert3, NEGATED)
    check(cert3.claim_outcomes[orphan.digest().hex()] == "UNRESOLVABLE",
          "UNRESOLVABLE 分类")

    # 5d. 未证：根本没有声称 / 缺段
    aud4, _ = fresh_pair()
    aud4.ingest(a0)
    cert4 = build_certificate(aud4, 1)
    expect_cert(cert4, UNPROVEN)
    check(cert4.reason.startswith("gap-at-"), "缺段原因标注位置")
    cert5 = build_certificate(aud4, 7)
    expect_cert(cert5, UNPROVEN)

    # 5e. 异质否定：一声称坏签名、一声称被撤回，逐声称原因都要保留
    aud6, _ = fresh_pair()
    aud6.ingest(a0)
    aud6.ingest(a1)
    aud6.ingest(rev)
    mixed = build_certificate(aud6, 1, [bad, a1])
    expect_cert(mixed, NEGATED)
    outcomes = mixed.claim_outcomes
    check(outcomes[bad.digest().hex()] == "BAD-SIG", "异质: BAD-SIG")
    check(outcomes[a1.digest().hex()] == "REVOKED", "异质: REVOKED")


# ---------------------------------------------------------------------------
# 6. 缺段不可盖过 + 封存规则
# ---------------------------------------------------------------------------

def test_gap_and_seals():
    svc = Service(LEDGER, KEYS)
    present = [svc.emit(i, body(i)) for i in (0, 1, 2)]      # 缺 seq3
    # 服务端先把后续段全部造好（保持服务侧链完整），但扣留 seq3 不投递；
    # 远隔段以"无法解析的父摘要"送达，模拟乱序补来的孤立段。
    withheld = svc.emit(3, body(3))
    late_ok = [svc.emit(i, body(i)) for i in (4, 5, 6)]
    far = [svc.emit_fork(i, body(i), b"\xbb" * 32) for i in (20, 21)]
    aud, naive = fresh_pair()
    for rec in present + late_ok + far:
        aud.ingest(rec)
        naive.ingest(rec)
    check(aud.watermark() == naive.watermark() == 3, "水位停在最早缺段 3")

    # 超水位封存一律拒绝（哪怕高 seq 段签名完整）
    for w in (4, 7, 22):
        try:
            aud.issue_seal(svc, w)
            raise AssertionError("超水位封存应被拒绝")
        except PermissionError:
            pass
    # 缺段之前各水位都可封存，且形成父封存链
    prev_digest = b"\x00" * 32
    for w in (1, 2, 3):
        seal = aud.issue_seal(svc, w)
        check(seal.parent_seal_digest == prev_digest, "父封存摘要链接")
        prev_digest = seal.digest()
    # 补齐缺段 -> 水位前进；但 20/21 是孤立段，7 之后仍缺段
    aud.ingest(withheld)
    naive.ingest(withheld)
    check(aud.watermark() == naive.watermark() == 7, "补齐后水位=7")
    check(aud.can_seal(20) is False, "远端缺段仍挡住高水位")


# ---------------------------------------------------------------------------
# 7. 检查点锚定
# ---------------------------------------------------------------------------

def test_checkpoint_anchor():
    svc = Service(LEDGER, KEYS)
    recs = [svc.emit(i, body(i)) for i in range(4)]
    aud, naive = feed_both(recs, block_size=4)
    cp, root = make_checkpoint(svc, aud, 4)
    check(cp.root == root and len(cp.rev_root) == 32, "检查点字段完整")
    aud.ingest(cp)
    naive.ingest(cp)

    # 锚后公告以检查点 root 为新虚拟创世
    a4 = svc.emit(4, body(4), parent_digest=cp.root)
    a5 = svc.emit(5, body(5), parent_digest=a4.link_digest())
    aud.ingest(a4)
    aud.ingest(a5)
    naive.ingest(a4)
    naive.ingest(a5)
    check(aud.watermark() == naive.watermark() == 6, "检查点后链连续到 6")

    cert = build_certificate(aud, 5)
    expect_cert(cert, NO_CONFLICT)
    check(cert.anchor_water == 4 and cert.anchor is not None, "证书锚到检查点")
    # 证书只含锚后窗口记录（锚前公告不在内）
    check(all(r.seq >= 4 for r in cert.records if hasattr(r, "seq")),
          "证书窗口作用域")

    # 锚后撤回：封存撤回根只覆盖窗口，且与检查点 rev_root 共同可复核
    rev = svc.revoke(5, a5.version)
    aud.ingest(rev)
    seal = aud.issue_seal(svc, 5)
    scert = build_certificate(aud, 4)
    expect_cert(scert, NO_CONFLICT)
    check(scert.seal.digest() == seal.digest(), "封存承诺入证")

    # 坏签名检查点必须被忽略
    bad_cp = Service(LEDGER, Keys.generate(b"wrong")).checkpoint(4, root, cp.rev_root)
    before = aud.state_digest()
    aud.ingest(bad_cp)
    check(aud.state_digest() == before, "坏检查点不改变状态")


# ---------------------------------------------------------------------------
# 8. 前缀重放：每个旧水位都能按当时记录重建证书（逐字节）
# ---------------------------------------------------------------------------

def test_prefix_replay():
    from core import replay_prefix
    svc = Service(LEDGER, KEYS)
    journal = LedgerJournal()
    online = Auditor(LEDGER, KEYS, B)
    snapshots: dict[int, dict[int, bytes]] = {}
    claim_seqs = (0, 1, 2, 3, 5)

    def snapshot_now():
        snapshots[len(journal)] = {
            cs: build_certificate(online, cs).canonical_json()
            for cs in claim_seqs}

    seq_anns = {}
    for seq in range(5):
        ann = svc.emit(seq, body(seq))
        seq_anns[seq] = ann
        journal.append(ann)
        online.ingest(ann)
        snapshot_now()
    # 中途加入分叉与撤回
    fork = svc.emit_fork(3, body(3, b"fork"),
                         seq_anns[2].link_digest())
    journal.append(fork)
    online.ingest(fork)
    snapshot_now()
    rev = svc.revoke(3, fork.version)
    journal.append(rev)
    online.ingest(rev)
    snapshot_now()
    # 乱序补来的孤立段（缺段 5）：用无法解析的父摘要送达
    a6 = svc.emit_fork(6, body(6), b"\xcc" * 32)
    journal.append(a6)
    online.ingest(a6)
    snapshot_now()

    # 用任意前缀重放，重建的证书必须与当时在线输出逐字节相同
    for i in range(1, len(journal) + 1):
        prefix = journal.prefix(i)
        for cs in claim_seqs:
            rebuilt = rebuild_historical_certificate(
                prefix, LEDGER, KEYS, B, cs)
            check(rebuilt.canonical_json() == snapshots[i][cs],
                  f"前缀 {i} 水位 {cs} 证书逐字节重建")
            # 朴素实现重放：结论必须一致
            naive_cert = rebuild_historical_certificate(
                prefix, LEDGER, KEYS, B, cs, naive=True)
            check(naive_cert.verdict == rebuilt.verdict
                  and naive_cert.reason == rebuilt.reason
                  and naive_cert.claim_outcomes == rebuilt.claim_outcomes,
                  "朴素/分块重放结论一致")
        # 两实现水位互校
        va = replay_prefix(prefix, LEDGER, KEYS, B)
        vn = replay_prefix(prefix, LEDGER, KEYS, B, naive=True)
        check(va.watermark() == vn.watermark(), "前缀重放水位一致")


# ---------------------------------------------------------------------------
# 9. JSONL 落盘重载
# ---------------------------------------------------------------------------

def test_journal_roundtrip():
    svc = Service(LEDGER, KEYS)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "journal.jsonl")
        j1 = LedgerJournal(path)
        aud = Auditor(LEDGER, KEYS, B)
        for seq in range(6):
            ann = svc.emit(seq, body(seq))
            j1.append(ann)
            aud.ingest(ann)
        rev = svc.revoke(2, svc.get_ann(2, 0).version)
        j1.append(rev)
        aud.ingest(rev)
        seal = aud.issue_seal(svc, 2)
        j1.append(seal)
        before = aud.state_digest()

        j2 = LedgerJournal(path)
        check(len(j2) == len(j1), "JSONL 记录数一致")
        aud2 = Auditor(LEDGER, KEYS, B)
        for rec in j2.records:
            aud2.ingest(rec)
        check(aud2.state_digest() == before, "重载后状态摘要一致")
        check(build_certificate(aud2, 1).canonical_json()
              == build_certificate(aud, 1).canonical_json(),
              "重载后证书逐字节一致")


# ---------------------------------------------------------------------------
# 10. 封存承诺篡改检测
# ---------------------------------------------------------------------------

def test_seal_tamper():
    svc = Service(LEDGER, KEYS)
    aud, _ = fresh_pair()
    for seq in range(3):
        aud.ingest(svc.emit(seq, body(seq)))
    seal = aud.issue_seal(svc, 3)
    from core import Seal
    forged = Seal(seal.ledger_id, seal.water + 1, seal.root, seal.rev_root,
                  seal.anchor_cp_digest, seal.parent_seal_digest, seal.sig)
    before = len(aud.seals)
    aud.ingest(forged)
    check(len(aud.seals) == before, "篡改封存承诺被拒")


def main():
    tests = [
        test_version_permutations,
        test_revocation_subsets,
        test_duplicate_delivery,
        test_fork_conflict,
        test_negation_paths,
        test_gap_and_seals,
        test_checkpoint_anchor,
        test_prefix_replay,
        test_journal_roundtrip,
        test_seal_tamper,
    ]
    for t in tests:
        t()
        print(f"[ok] {t.__name__}")
    print("-" * 60)
    print(f"穷举测试全部通过：{STATS['checks']} 条断言，"
          f"{STATS['certs']} 张证书经独立复核+最小性检验")
    print("覆盖结论态:", sorted(STATS["verdicts"]))
    required = {CONFLICT, NO_CONFLICT, NEGATED, UNPROVEN}
    check(required <= STATS["verdicts"], "四态结论必须全部被 exercised")
    print("四态结论全覆盖：CONFLICT / NO_CONFLICT / NEGATED / UNPROVEN")


if __name__ == "__main__":
    main()
