# -*- coding: utf-8 -*-
"""
公开审计承诺的最小缺口见证 —— 核心库（仅使用 Python 3.12 标准库）。

设计概览
========
* 服务 :class:`Service` 逐段公布"合成账本"的封存承诺，每段一个版本化公告
  :class:`Ann`，公告绑定父摘要（链）、可信检查点 :class:`Cp`（锚）以及
  版本撤回 :class:`Rev`（撤销）。
* 审计员 :class:`Auditor` 以分块（block）方式接收可能乱序、重复、被替换的
  记录。封存水位永远停在"最早缺段"之前；后到的、带合法签名的段不能盖过
  缺段（缺段未补，水位不前进）。
* 对同一水位被两个分支同时声称的情形，:func:`build_certificate` 输出
  *最短边界证书* :class:`Certificate`，明确区分：
    - CONFLICT   两个锚定的分支给出不同摘要（冲突被证实）；
    - NO_CONFLICT 两个分支实际是同一公告（无冲突被证实）；
    - NEGATED    声称被签名记录否定（坏签名/已撤回/父摘要断裂）；
    - UNPROVEN   记录不足，无法证明也无法否定。
* 所有记录只追加写入 :class:`LedgerJournal`（JSONL）。任意旧水位都可以用
  "当时的记录前缀"重放（:func:`replay_prefix`），逐字节重新构建当时的证书。
* :class:`NaiveAuditor` 是一份完全独立的全量朴素实现，测试中与分块审计器
  做交叉核对；分块审计器的块访问计数器用于证明单段补齐/撤销只触达相关
  区间。

签名说明（演练模型）
====================
Python 3.12 标准库不提供非对称签名（Ed25519/RSA）原语，因此演练中使用
HMAC-SHA256 作为"签名"：服务私钥 svc_key、检查点权威私钥 cp_key，复核器
持有对应的对称验证密钥。接口 Signer/Verifier 是独立的，真实系统只需把
HMAC 替换为 Ed25519 等数字签名，协议其余部分不变。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# 1. 规范化编码与域分离哈希 / 签名原语
# ---------------------------------------------------------------------------

# 每个用途一个域前缀，防止不同结构之间的哈希混用（域分离）。
D_ANNOUNCE = b"ann-v1"
D_REVOKE = b"rev-v1"
D_CHECKPOINT = b"cp-v1"
D_SEAL = b"seal-v1"
D_GENESIS = b"genesis-v1"
D_ROW = b"row-v1"


def enc(x) -> bytes:
    """类型自描述的规范化字节编码：类型标签 + 长度前缀 + 载荷。"""
    if x is None:
        return b"0"
    if isinstance(x, bool):
        return b"b:" + (b"1" if x else b"0")
    if isinstance(x, int):
        return b"i:" + str(x).encode("ascii")
    if isinstance(x, str):
        b = x.encode("utf-8")
        return b"s:" + str(len(b)).encode("ascii") + b":" + b
    if isinstance(x, (bytes, bytearray)):
        b = bytes(x)
        return b"h:" + str(len(b)).encode("ascii") + b":" + b
    if isinstance(x, (list, tuple)):
        return b"l:" + str(len(x)).encode("ascii") + b":" + b"".join(enc(v) for v in x)
    if isinstance(x, dict):
        parts = [b"d:" + str(len(x)).encode("ascii") + b":"]
        for k in sorted(x):
            parts.append(enc(k))
            parts.append(enc(x[k]))
        return b"".join(parts)
    raise TypeError(f"不可规范化编码的类型: {type(x)!r}")


def dhash(tag: bytes, *parts) -> bytes:
    """域分离 SHA-256。"""
    h = hashlib.sha256()
    h.update(tag)
    for p in parts:
        e = enc(p)
        h.update(str(len(e)).encode("ascii"))
        h.update(b":")
        h.update(e)
    return h.digest()


def sign(key: bytes, tag: bytes, *parts) -> bytes:
    """对规范化消息做 HMAC-SHA256（演练用"数字签名"）。"""
    msg = tag + b"".join(
        (lambda e: str(len(e)).encode("ascii") + b":" + e)(enc(p)) for p in parts
    )
    return hmac.new(key, msg, hashlib.sha256).digest()


def verify_sig(key: bytes, tag: bytes, parts: list, sig: bytes) -> bool:
    """常数时间 HMAC 复核。"""
    return hmac.compare_digest(sign(key, tag, *parts), sig)


def merkle_root(items: Iterable[bytes]) -> bytes:
    """列表元素的聚合摘要（空列表取全零摘要）。"""
    items = list(items)
    if not items:
        return b"\x00" * 32
    h = hashlib.sha256()
    h.update(b"set-v1")
    for it in items:
        h.update(it)
    return h.digest()


# ---------------------------------------------------------------------------
# 2. 记录类型：公告 Ann / 撤回 Rev / 检查点 Cp / 封存承诺 Seal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Ann:
    """段公告（一个 seq 可有多个版本/分支，每个公告各自签名）。

    parent_digest 是父链摘要：
      seq == 0 时为创世锚 genesis；
      seq >  0 时为其所引用父段公告的 link_digest（可能引用另一个分支）。
    """

    ledger_id: str
    seq: int
    version: int
    body_hash: bytes
    parent_digest: bytes
    sig: bytes

    def digest(self) -> bytes:
        """公告身份摘要：同 (ledger_id, seq, version) 永远得到同一摘要。"""
        return dhash(
            D_ANNOUNCE,
            self.ledger_id,
            self.seq,
            self.version,
            self.body_hash,
            self.parent_digest,
        )

    def link_digest(self) -> bytes:
        """链上链接摘要 = 身份摘要（供子公告引用）。"""
        return self.digest()

    def signed_parts(self) -> list:
        return [self.ledger_id, self.seq, self.version, self.body_hash, self.parent_digest]

    def to_dict(self) -> dict:
        return {
            "kind": "Ann",
            "ledger_id": self.ledger_id,
            "seq": self.seq,
            "version": self.version,
            "body_hash": self.body_hash.hex(),
            "parent_digest": self.parent_digest.hex(),
            "sig": self.sig.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Ann":
        return Ann(
            d["ledger_id"],
            d["seq"],
            d["version"],
            bytes.fromhex(d["body_hash"]),
            bytes.fromhex(d["parent_digest"]),
            bytes.fromhex(d["sig"]),
        )


@dataclass(frozen=True)
class Rev:
    """版本撤回：撤销某条公告身份；revokes 即被撤公告的 digest()。"""

    ledger_id: str
    seq: int
    version: int
    revokes: bytes
    reason: str
    sig: bytes

    def identity(self) -> tuple:
        return self.ledger_id, self.seq, self.version

    def digest(self) -> bytes:
        return dhash(
            D_REVOKE,
            self.ledger_id,
            self.seq,
            self.version,
            self.revokes,
            self.reason,
        )

    def signed_parts(self) -> list:
        return [self.ledger_id, self.seq, self.version, self.revokes, self.reason]

    def to_dict(self) -> dict:
        return {
            "kind": "Rev",
            "ledger_id": self.ledger_id,
            "seq": int(self.seq),
            "version": int(self.version),
            "revokes": self.revokes.hex(),
            "reason": self.reason,
            "sig": self.sig.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Rev":
        return Rev(
            d["ledger_id"],
            d["seq"],
            d["version"],
            bytes.fromhex(d["revokes"]),
            d["reason"],
            bytes.fromhex(d["sig"]),
        )


@dataclass(frozen=True)
class Cp:
    """可信检查点（由独立检查点权威签名）：在水位 water 处锚定规范根。

    rev_root 是截至该水位全部撤回记录的聚合摘要，由检查点权威一并签名；
    这样检查点之后的封存承诺只需绑定 *锚后窗口* 内的撤回聚合，历史撤回
    由检查点背书，短证书即可独立复核。
    """

    ledger_id: str
    water: int
    root: bytes
    rev_root: bytes
    sig: bytes

    def digest(self) -> bytes:
        return dhash(D_CHECKPOINT, self.ledger_id, self.water, self.root, self.rev_root)

    def signed_parts(self) -> list:
        return [self.ledger_id, self.water, self.root, self.rev_root]

    def to_dict(self) -> dict:
        return {
            "kind": "Cp",
            "ledger_id": self.ledger_id,
            "water": self.water,
            "root": self.root.hex(),
            "rev_root": self.rev_root.hex(),
            "sig": self.sig.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Cp":
        return Cp(
            d["ledger_id"], d["water"],
            bytes.fromhex(d["root"]), bytes.fromhex(d["rev_root"]),
            bytes.fromhex(d["sig"]),
        )


@dataclass(frozen=True)
class Seal:
    """封存承诺。

    绑定要素：
      * parent_seal_digest —— 上一封存承诺（封存链，首封为全零）；
      * water              —— 封存水位（连续前缀长度）；
      * root               —— 该水位的规范链根（可能是多个根的集合摘要）；
      * rev_root           —— 锚后窗口内撤回记录的聚合摘要（锚前历史撤回
                               由检查点 rev_root 背书；创世锚时即全量撤回）；
      * anchor_cp_digest   —— 锚定的可信检查点摘要（创世锚时为全零）。
    sig 由服务密钥签发，复核器可独立验签并核对全部绑定字段。
    """

    ledger_id: str
    water: int
    root: bytes
    rev_root: bytes
    anchor_cp_digest: bytes
    parent_seal_digest: bytes
    sig: bytes

    def digest(self) -> bytes:
        return dhash(
            D_SEAL,
            self.ledger_id,
            self.water,
            self.root,
            self.rev_root,
            self.anchor_cp_digest,
            self.parent_seal_digest,
        )

    def signed_parts(self) -> list:
        return [
            self.ledger_id,
            self.water,
            self.root,
            self.rev_root,
            self.anchor_cp_digest,
            self.parent_seal_digest,
        ]

    def to_dict(self) -> dict:
        return {
            "kind": "Seal",
            "ledger_id": self.ledger_id,
            "water": self.water,
            "root": self.root.hex(),
            "rev_root": self.rev_root.hex(),
            "anchor_cp_digest": self.anchor_cp_digest.hex(),
            "parent_seal_digest": self.parent_seal_digest.hex(),
            "sig": self.sig.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Seal":
        return Seal(
            d["ledger_id"],
            d["water"],
            bytes.fromhex(d["root"]),
            bytes.fromhex(d["rev_root"]),
            bytes.fromhex(d["anchor_cp_digest"]),
            bytes.fromhex(d["parent_seal_digest"]),
            bytes.fromhex(d["sig"]),
        )


def record_to_dict(rec) -> dict:
    return rec.to_dict()


def record_from_dict(d: dict):
    kind = d["kind"]
    if kind == "Ann":
        return Ann.from_dict(d)
    if kind == "Rev":
        return Rev.from_dict(d)
    if kind == "Cp":
        return Cp.from_dict(d)
    if kind == "Seal":
        return Seal.from_dict(d)
    raise ValueError(f"未知记录类型: {kind}")


# ---------------------------------------------------------------------------
# 3. 密钥与服务（生成器）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Keys:
    """演练密钥对。真实系统中 cp_key 属于独立检查点权威。"""

    svc_key: bytes
    cp_key: bytes

    @staticmethod
    def generate(seed: bytes) -> "Keys":
        return Keys(
            svc_key=hashlib.sha256(b"svc" + seed).digest(),
            cp_key=hashlib.sha256(b"cp-authority" + seed).digest(),
        )


def genesis_anchor(ledger_id: str) -> bytes:
    """创世锚：空账本的公开固定摘要。"""
    return dhash(D_GENESIS, ledger_id)


def synthetic_row_hash(ledger_id: str, seq: int, payload: bytes = b"") -> bytes:
    """合成账本行的内容摘要（行体本身可由审计员另行复核）。"""
    return dhash(D_ROW, ledger_id, seq, payload)


class Service:
    """承诺生成器：签名发布公告、撤回、检查点与封存承诺。

    服务自身也维护规范链上每段的"当前父摘要"，从而能够：
      * emit()        正常顺序发布；
      * emit_fork()   在同一 seq 上发布另一分支公告（父摘要可不同）；
      * revoke()      撤回某个已发布版本；
      * checkpoint()  请检查点权威在某水位锚定规范根；
      * make_seal()   按审计员给出的水位与根签发封存承诺。
    """

    def __init__(self, ledger_id: str, keys: Keys):
        self.ledger_id = ledger_id
        self.keys = keys
        self.genesis = genesis_anchor(ledger_id)
        # 诚实链：seq -> 当前版本号；已发布公告 (seq, version) -> Ann
        self._honest_version: dict[int, int] = {}
        self._anns: dict[tuple[int, int], Ann] = {}

    # ---- 公告 -------------------------------------------------------------

    def _new_version(self, seq: int) -> int:
        v = self._honest_version.get(seq, -1) + 1
        self._honest_version[seq] = v
        return v

    def emit(self, seq: int, body_hash: bytes, *, parent_digest: Optional[bytes] = None,
             version: Optional[int] = None) -> Ann:
        """在诚实链上发布 seq 段；可显式指定版本号（替换场景）。"""
        if parent_digest is None:
            parent_digest = self.genesis if seq == 0 else self._honest_link(seq - 1)
        if version is None:
            version = self._new_version(seq)
        ann = Ann(
            self.ledger_id, seq, version, body_hash, parent_digest,
            sign(self.keys.svc_key, D_ANNOUNCE,
                 self.ledger_id, seq, version, body_hash, parent_digest),
        )
        self._anns[(seq, version)] = ann
        return ann

    def emit_fork(self, seq: int, body_hash: bytes, parent_digest: bytes) -> Ann:
        """发布分叉公告：独立版本号、显式给定父摘要（另一分支）。"""
        version = self._new_version(seq)
        ann = Ann(
            self.ledger_id, seq, version, body_hash, parent_digest,
            sign(self.keys.svc_key, D_ANNOUNCE,
                 self.ledger_id, seq, version, body_hash, parent_digest),
        )
        self._anns[(seq, version)] = ann
        return ann

    def _honest_link(self, seq: int) -> bytes:
        version = self._honest_version[seq]
        return self._anns[(seq, version)].link_digest()

    def get_ann(self, seq: int, version: int) -> Ann:
        return self._anns[(seq, version)]

    def tamper_ann(self, ann: Ann, *, body_hash: Optional[bytes] = None,
                   parent_digest: Optional[bytes] = None) -> Ann:
        """制造一个签名失效的篡改公告（仅供否定路径测试）。"""
        return Ann(
            ann.ledger_id, ann.seq, ann.version,
            body_hash if body_hash is not None else ann.body_hash,
            parent_digest if parent_digest is not None else ann.parent_digest,
            ann.sig,  # 保留旧签名 -> 验签必然失败
        )

    # ---- 撤回 -------------------------------------------------------------

    def revoke(self, seq: int, version: int, reason: str = "drill-revocation") -> Rev:
        ann = self._anns[(seq, version)]
        revokes = ann.digest()
        return Rev(
            self.ledger_id, seq, version, revokes, reason,
            sign(self.keys.svc_key, D_REVOKE,
                 self.ledger_id, seq, version, revokes, reason),
        )

    # ---- 检查点 -----------------------------------------------------------

    def checkpoint(self, water: int, root: bytes, rev_root: bytes) -> Cp:
        """检查点权威对 (water, root, rev_root) 签名。"""
        return Cp(
            self.ledger_id, water, root, rev_root,
            sign(self.keys.cp_key, D_CHECKPOINT,
                 self.ledger_id, water, root, rev_root),
        )

    # ---- 封存承诺 ---------------------------------------------------------

    def make_seal(self, water: int, root: bytes, rev_root: bytes,
                  anchor_cp_digest: bytes, parent_seal_digest: bytes) -> Seal:
        return Seal(
            self.ledger_id, water, root, rev_root, anchor_cp_digest,
            parent_seal_digest,
            sign(self.keys.svc_key, D_SEAL,
                 self.ledger_id, water, root, rev_root,
                 anchor_cp_digest, parent_seal_digest),
        )


# ---------------------------------------------------------------------------
# 4. 只追加日志（JSONL 持久化）
# ---------------------------------------------------------------------------


class LedgerJournal:
    """记录只追加落盘；重放前缀即可得到任意历史时刻的视图。"""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.records: list = []
        if path and os.path.exists(path):
            self._load()

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.records.append(record_from_dict(json.loads(line)))

    def append(self, rec) -> int:
        self.records.append(rec)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
        return len(self.records) - 1

    def extend(self, recs: Iterable) -> None:
        for rec in recs:
            self.append(rec)

    def __len__(self) -> int:
        return len(self.records)

    def prefix(self, n: int) -> list:
        return self.records[:n]


# ---------------------------------------------------------------------------
# 5. 共享辅助：撤回根 / 检查点根 / 视图协议
# ---------------------------------------------------------------------------


def revocation_root(rev_digests: Iterable[bytes]) -> bytes:
    """截至某水位全部撤回记录的聚合摘要（绑定进封存承诺）。"""
    return merkle_root(sorted(rev_digests))


def checkpoint_root(cp_digests: Iterable[bytes]) -> bytes:
    return merkle_root(sorted(cp_digests))


class View:
    """证书构建器所需的只读视图协议（Auditor / NaiveAuditor 均实现）。"""

    keys: Keys
    ledger_id: str

    def anns_in_window(self, lo_seq: int, hi_seq: int) -> list[Ann]: ...
    def revs_in_window(self, lo_seq: int, hi_seq: int) -> list[Rev]: ...
    def cp_at(self, water: int) -> Optional[Cp]: ...
    def cp_rev_root(self, water: int) -> Optional[bytes]: ...
    def anchor_before(self, water: int) -> tuple[bytes, int]: ...
    def is_good_ann(self, ann: Ann) -> bool: ...
    def is_revoked_identity(self, ann: Ann) -> bool: ...
    def seal_at(self, water: int) -> Optional[Seal]: ...
    def revs_before(self, water: int) -> list[Rev]: ...


def replay_roots(view: View, lo_water: int, hi_water: int,
                 claims: list[Ann]) -> list[bytes]:
    """在 [lo_water, hi_water) 区间内按 claims 重放链，返回 hi_water 处的根集合。

    每条 claim 的父摘要必须能在窗口内（含 lo_water 锚）解析，否则该 claim
    不形成链，被丢弃——这正是"父摘要断裂 => 已否定"的判定来源。
    """
    # 按 seq 组织候选
    by_seq: dict[int, list[Ann]] = {}
    for a in claims:
        by_seq.setdefault(a.seq, []).append(a)

    # 已知链接摘要集合：锚摘要 + 窗口内每条公告自身的链接摘要
    known_links: set[bytes] = set()
    anchor_digest, _ = view.anchor_before(lo_water)
    known_links.add(anchor_digest)

    roots: list[bytes] = []
    for seq in range(lo_water, hi_water):
        cands = by_seq.get(seq, [])
        chained: list[Ann] = []
        for a in cands:
            if a.parent_digest in known_links and view.is_good_ann(a) \
                    and not view.is_revoked_identity(a):
                chained.append(a)
        if not chained:
            return []  # 窗口内出现缺段，无法到达 hi_water
        # 去重（同一公告可能被重复引用/重复投递）
        uniq: dict[bytes, Ann] = {}
        for a in chained:
            uniq[a.link_digest()] = a
        chained = list(uniq.values())
        for a in chained:
            known_links.add(a.link_digest())
        if seq == hi_water - 1:
            roots = sorted(a.link_digest() for a in chained)
    return roots


# ---------------------------------------------------------------------------
# 6. 最短边界证书
# ---------------------------------------------------------------------------

# 证书结论
CONFLICT = "CONFLICT"
NO_CONFLICT = "NO_CONFLICT"
NEGATED = "NEGATED"
UNPROVEN = "UNPROVEN"


def make_checkpoint(svc: "Service", view: View, water: int) -> tuple["Cp", bytes]:
    """请检查点权威在 water 处锚定：重放求规范根、聚合全部撤回并签名。

    检查点之后发布的公告应以返回 Cp 的 root 作为父摘要（检查点即新虚拟
    创世）。返回 (检查点, 根)。
    """
    _, anchor_water = view.anchor_before(water)
    anns = [a for a in view.anns_in_window(anchor_water, water) if view.is_good_ann(a)]
    roots = replay_roots(view, anchor_water, water, anns)
    root = merkle_root(roots)
    rev_root = revocation_root(r.digest() for r in view.revs_before(water))
    return svc.checkpoint(water, root, rev_root), root


@dataclass
class Certificate:
    """最短边界证书。

    records  边界窗口 [anchor_water, claim_seq] 内的全部必要签名记录；
    anchor   锚定检查点（创世锚时为 None，anchor_water=0）；
    verdict  四态结论；
    reason   机器可读原因；
    seal     若 claim_seq+1 水位存在封存承诺则一并附上（链上自证）；
    claims   被评估的两个声称（可能为空，表示纯缺段见证）。
    """

    ledger_id: str
    claim_seq: int
    anchor_water: int
    anchor: Optional[Cp]
    records: list
    verdict: str
    reason: str
    seal: Optional[Seal] = None
    claims: list[Ann] = field(default_factory=list)
    # 逐声称结论：公告身份摘要(hex) -> LIVE / BAD-SIG / REVOKED / UNRESOLVABLE
    claim_outcomes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ledger_id": self.ledger_id,
            "claim_seq": self.claim_seq,
            "anchor_water": self.anchor_water,
            "anchor": self.anchor.to_dict() if self.anchor else None,
            "records": [r.to_dict() for r in self.records],
            "verdict": self.verdict,
            "reason": self.reason,
            "seal": self.seal.to_dict() if self.seal else None,
            "claims": [a.to_dict() for a in self.claims],
            "claim_outcomes": self.claim_outcomes,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False).encode("utf-8")


def build_certificate(view: View, claim_seq: int,
                      claims: Optional[list[Ann]] = None) -> Certificate:
    """构建关于 claim_seq 水位（段号 claim_seq）的最短边界证书。

    claims 为两个分支对该段的声称；为空时构建"缺段见证"证书。
    证书只保留边界窗口内 *支撑结论所必需* 的记录，从而通过逐条剥离的
    最小性检验。
    """
    # ---- 选择最近的可用锚（检查点优先，否则创世锚）----
    anchor_digest, anchor_water = view.anchor_before(claim_seq + 1)
    anchor_cp = view.cp_at(anchor_water) if anchor_water > 0 else None

    # ---- 边界窗口内的候选记录 ----
    all_anns = view.anns_in_window(anchor_water, claim_seq + 1)
    good_anns = [a for a in all_anns if view.is_good_ann(a)]
    revs = view.revs_in_window(anchor_water, claim_seq + 1)

    if claims is None:
        # 自动收集时按摘要排序，保证证书与投递顺序无关、逐字节确定
        claims = sorted((a for a in good_anns if a.seq == claim_seq),
                        key=lambda a: a.digest())
    claims = list(claims)

    # ---- 声称级否定判定（坏签名 / 已撤回 / 父摘要断裂）----
    link_index = {a.link_digest(): a for a in good_anns if a.seq <= claim_seq}

    def resolvable(a: Ann) -> bool:
        if a.parent_digest == anchor_digest:
            return True
        p = link_index.get(a.parent_digest)
        return p is not None and p.seq < a.seq

    negated: list[Ann] = []
    live_claims: list[Ann] = []
    claim_outcomes: dict[str, str] = {}
    for a in claims:
        key = a.digest().hex()
        if not view.is_good_ann(a):
            negated.append(a)
            claim_outcomes[key] = "BAD-SIG"
        elif view.is_revoked_identity(a):
            negated.append(a)
            claim_outcomes[key] = "REVOKED"
        elif not resolvable(a):
            negated.append(a)
            claim_outcomes[key] = "UNRESOLVABLE"
        else:
            live_claims.append(a)
            claim_outcomes[key] = "LIVE"

    # ---- 缺段（窗口内无法连续到达 claim_seq）----
    gap = False
    gap_at: Optional[int] = None
    present_good = {a.seq for a in good_anns}
    for seq in range(anchor_water, claim_seq + 1):
        if seq not in present_good:
            gap = True
            gap_at = seq
            break

    # ---- 结论判定（否定优先于未证）----
    if claims and negated and not live_claims:
        verdict, reason = NEGATED, "all-claims-negated"
    elif gap:
        verdict, reason = UNPROVEN, f"gap-at-{gap_at}"
    elif not live_claims:
        verdict, reason = UNPROVEN, "no-live-claim"
    else:
        # 冲突只取决于 *被评估的存活声称* 自身：同水位、各自锚定可解析，
        # 链接摘要相异即冲突；相同公告（含引用重复）即无冲突。
        # 不使用全窗口重放，避免把未被评估的其他分叉计入结论。
        distinct = {a.link_digest() for a in live_claims}
        if len(distinct) >= 2:
            verdict, reason = CONFLICT, "distinct-anchored-roots"
        else:
            verdict, reason = NO_CONFLICT, "single-root"

    # ---- 剪枝：只保留支撑结论的最短记录集合 ----
    all_negated = bool(claims) and bool(negated) and not live_claims
    kept: list = []
    if live_claims:
        # 从每个存活声称沿父链接反向 BFS 到锚，只保留支撑链上的公告
        needed_links: set[bytes] = set()
        frontier = list(live_claims)
        while frontier:
            a = frontier.pop()
            if a.link_digest() in needed_links:
                continue
            needed_links.add(a.link_digest())
            kept.append(a)
            if a.parent_digest != anchor_digest:
                parent = link_index.get(a.parent_digest)
                if parent is not None:
                    frontier.append(parent)
    # 被评估的声称（含被否定者）本身必须入证，复核器才能逐声称重建结论
    kept.extend(a for a in claims if a not in kept)
    # 缺段见证：保留锚之后、缺段之前所有连续段公告（证明缺段真实存在）
    if gap and not all_negated:
        run_end = gap_at  # 第一个缺失 seq
        kept.extend(a for a in good_anns
                    if anchor_water <= a.seq < run_end and a not in kept)

    seal = view.seal_at(claim_seq + 1)

    # 撤回记录：无封存时只保留与被评估声称相关的否定证据；有封存承诺时
    # 窗口内全部撤回都参与撤回根聚合，必须全量保留（剥离任一都会失配）。
    kept_ids = {a.digest() for a in kept if isinstance(a, Ann)}
    if seal is not None:
        kept_revs = list(revs)
    else:
        kept_revs = [r for r in revs if r.revokes in kept_ids
                     or any(a.seq == r.seq and a.version == r.version
                            for a in kept)]
    kept.extend(kept_revs)
    if anchor_cp is not None and not all_negated:
        kept.append(anchor_cp)

    # 去重后按 (类型, 摘要) 确定性排序：引用重复/乱序投递不影响证书字节
    uniq: dict = {}
    for r in kept:
        uniq[(type(r).__name__, r.digest())] = r
    window_records = sorted(uniq.values(),
                            key=lambda r: (type(r).__name__, r.digest()))

    # 否定证书的证据是声称局部的：锚归创世、窗口归零，保证剥离检验严格成立；
    # 因此不携带绑定真实锚的封存承诺（封存可由同水位前缀证书另行证明）。
    cert_anchor_water = 0 if all_negated else anchor_water
    cert_anchor_cp = None if all_negated else anchor_cp
    if all_negated:
        seal = None

    return Certificate(
        ledger_id=view.ledger_id,
        claim_seq=claim_seq,
        anchor_water=cert_anchor_water,
        anchor=cert_anchor_cp,
        records=window_records,
        verdict=verdict,
        reason=reason,
        seal=seal,
        claims=claims,
        claim_outcomes=claim_outcomes,
    )


# ---------------------------------------------------------------------------
# 7. 独立复核器：仅凭证书 + 验证密钥复核，并做最小性剥离检验
# ---------------------------------------------------------------------------


class _CertificateView:
    """把单张证书包装成只读视图，供共享重放逻辑复核（不依赖审计器状态）。"""

    def __init__(self, cert: Certificate, keys: Keys):
        self.cert = cert
        self.keys = keys
        self.ledger_id = cert.ledger_id
        self._anns = [r for r in cert.records if isinstance(r, Ann)]
        self._revs = [r for r in cert.records if isinstance(r, Rev)]
        self._cp = cert.anchor
        self._revoked = {r.revokes for r in self._revs}

    def anns_in_window(self, lo_seq, hi_seq):
        return [a for a in self._anns if lo_seq <= a.seq < hi_seq]

    def revs_in_window(self, lo_seq, hi_seq):
        return [r for r in self._revs if lo_seq <= r.seq < hi_seq]

    def cp_at(self, water):
        if self._cp is not None and self._cp.water == water:
            return self._cp
        return None

    def cp_rev_root(self, water):
        if self._cp is not None and self._cp.water == water:
            return self._cp.rev_root
        return None

    def anchor_before(self, water):
        if self._cp is not None:
            return self._cp.root, self._cp.water
        return genesis_anchor(self.ledger_id), 0

    def is_good_ann(self, ann):
        return verify_sig(self.keys.svc_key, D_ANNOUNCE, ann.signed_parts(), ann.sig)

    def is_revoked_identity(self, ann):
        return ann.digest() in self._revoked

    def seal_at(self, water):
        if self.cert.seal is not None and self.cert.seal.water == water:
            return self.cert.seal
        return None

    def revs_before(self, water):
        return list(self._revs)


def verify_certificate(cert: Certificate, keys: Keys) -> tuple[bool, str]:
    """独立复核。返回 (是否通过, 说明)。

    复核内容：
      1. 证书内每条记录签名独立验签（服务/检查点权威分别用钥）；
      2. 锚检查点与证书声明一致且验签；创世锚核对公开固定摘要；
      3. 用证书内记录重放，独立得出四态结论，必须与证书声明一致；
      4. 若附封存承诺，验签并核对水位、根、撤回根、锚摘要、父封存链；
      5. 最小性：逐条剥离证书记录，任何一条被移除后复核结论都应改变或
         验签失败——证明证书是"最短边界证书"。
    """
    # 1. 逐条验签。坏签名公告允许作为"否定证据"入证，但必须在
    #    claim_outcomes 中被明确标注为 BAD-SIG；其余记录坏签名一律拒绝。
    bad_sig_ids = {k for k, v in cert.claim_outcomes.items() if v == "BAD-SIG"}
    for rec in cert.records:
        if isinstance(rec, Ann):
            if not verify_sig(keys.svc_key, D_ANNOUNCE, rec.signed_parts(), rec.sig):
                if rec.digest().hex() not in bad_sig_ids:
                    return False, f"未声明的坏签名公告: {rec}"
        elif isinstance(rec, Rev):
            if not verify_sig(keys.svc_key, D_REVOKE, rec.signed_parts(), rec.sig):
                return False, f"撤回验签失败: {rec}"
        elif isinstance(rec, Cp):
            if not verify_sig(keys.cp_key, D_CHECKPOINT, rec.signed_parts(), rec.sig):
                return False, f"检查点验签失败: {rec}"
        else:
            return False, f"未知记录类型: {type(rec)}"
    for a in cert.claims:
        if not verify_sig(keys.svc_key, D_ANNOUNCE, a.signed_parts(), a.sig):
            if a.digest().hex() not in bad_sig_ids:
                return False, "声称验签失败且未标注 BAD-SIG"

    # 2. 锚核对
    if cert.anchor is not None:
        if not verify_sig(keys.cp_key, D_CHECKPOINT,
                          cert.anchor.signed_parts(), cert.anchor.sig):
            return False, "锚检查点验签失败"
        if cert.anchor.water != cert.anchor_water:
            return False, "锚水位与证书声明不一致"
    else:
        if cert.anchor_water != 0:
            return False, "非零锚水位却缺少检查点"

    # 3. 独立重放得出结论（结论、原因、逐声称否定原因都必须逐字一致）
    cview = _CertificateView(cert, keys)
    rebuilt = build_certificate(cview, cert.claim_seq, list(cert.claims))
    if (rebuilt.verdict != cert.verdict or rebuilt.reason != cert.reason
            or rebuilt.claim_outcomes != cert.claim_outcomes):
        return False, (f"结论不一致: 证书=({cert.verdict},{cert.reason},"
                       f"{cert.claim_outcomes}) 独立重放=({rebuilt.verdict},"
                       f"{rebuilt.reason},{rebuilt.claim_outcomes})")

    # 4. 封存承诺核对
    if cert.seal is not None:
        seal = cert.seal
        if not verify_sig(keys.svc_key, D_SEAL, seal.signed_parts(), seal.sig):
            return False, "封存承诺验签失败"
        if seal.water != cert.claim_seq + 1:
            return False, "封存水位与证书水位不一致"
        # 撤回根：封存承诺绑定"锚后窗口内"的撤回聚合；锚之前的历史撤回
        # 由检查点 rev_root 背书（创世锚时窗口即从头开始）。
        # 证书剪枝保证窗口内每条撤回都被保留，剥离任意一条都会使聚合失配。
        window_revs = [r for r in cview.revs_before(seal.water)
                       if r.seq >= cert.anchor_water]
        rr = revocation_root(r.digest() for r in window_revs)
        if rr != seal.rev_root:
            return False, "撤回根不一致"
        if cert.anchor is not None and cert.anchor.rev_root is not None:
            # 检查点背书的历史撤回聚合本身必须验签通过（步骤1已覆盖其签名）
            if not isinstance(cert.anchor.rev_root, (bytes, bytearray)):
                return False, "检查点撤回根格式错误"
        # 锚摘要
        if cert.anchor is not None:
            if seal.anchor_cp_digest != cert.anchor.digest():
                return False, "封存承诺锚摘要不一致"
        else:
            if seal.anchor_cp_digest != b"\x00" * 32:
                return False, "创世锚封存的锚摘要应为全零"
        # 根：用证书内（剪枝后保留的完整支撑链）公告独立重放
        roots = replay_roots(cview, cert.anchor_water, seal.water,
                             [a for a in cert.records if isinstance(a, Ann)])
        if merkle_root(roots) != seal.root:
            return False, "封存承诺根不一致"

    # 5. 最小性（O(k) 结构化检验）：独立重算"必要记录闭包"，证书内不得有冗余
    anchor_digest = (cert.anchor.root if cert.anchor is not None
                     else genesis_anchor(cert.ledger_id))
    ok, why = _check_structural_minimality(cert, anchor_digest)
    if not ok:
        return False, why
    return True, "复核通过且证书最小"


def _check_structural_minimality(cert: Certificate, anchor_digest: bytes) -> tuple[bool, str]:
    """线性时间的最小性复核：证书内每条记录都必须是结论的必要元素。

    * 公告：必须是被评估声称，或位于某声称沿父链接到锚的支撑闭包内；
    * 撤回：无封存时必须直接指向某被评估声称；有封存时必须落在边界窗口内
      （封存撤回根的聚合绑定使集合自证：少任一条聚合即失配）；
    * 检查点：至多一条且必须就是证书锚；
    * 所有公告/撤回的 seq 必须落在边界窗口内。
    """
    anns = [r for r in cert.records if isinstance(r, Ann)]
    revs = [r for r in cert.records if isinstance(r, Rev)]
    cps = [r for r in cert.records if isinstance(r, Cp)]

    if cert.anchor is None:
        if cps:
            return False, "非锚定证书却包含检查点"
    elif cps != [cert.anchor]:
        return False, "检查点与证书锚不一致或存在冗余检查点"

    ann_by_link = {a.link_digest(): a for a in anns}
    claim_ids = {a.digest() for a in cert.claims}
    # 缺段见证（UNPROVEN/gap-at-* 且无声称）：全部公告共同构成缺段前缀证据
    gap_witness = (cert.verdict == UNPROVEN
                   and cert.reason.startswith("gap-at-") and not cert.claims)
    if gap_witness:
        needed = {a.digest() for a in anns}
    else:
        # 从全部被评估声称出发，沿父链接求必要公告闭包
        needed = set()
        stack = list(cert.claims)
        while stack:
            a = stack.pop()
            if a.digest() in needed:
                continue
            needed.add(a.digest())
            if a.parent_digest != anchor_digest:
                parent = ann_by_link.get(a.parent_digest)
                if parent is not None:
                    stack.append(parent)
    for a in anns:
        if a.digest() not in needed:
            return False, f"冗余公告（不在声称支撑闭包内）: seq={a.seq}"
        if not (cert.anchor_water <= a.seq <= cert.claim_seq):
            return False, "公告越出边界窗口"
    if not gap_witness and not claim_ids <= {a.digest() for a in anns}:
        return False, "存在无证书记录佐证的声称"

    target_ids = {a.digest() for a in cert.claims}
    for r in revs:
        if not (cert.anchor_water <= r.seq <= cert.claim_seq):
            return False, "撤回越出边界窗口"
        if cert.seal is None and r.revokes not in target_ids:
            return False, "无封存时存在与声称无关的冗余撤回"
    return True, "minimal"


def verify_minimality_peel(cert: Certificate, keys: Keys) -> tuple[bool, str]:
    """O(k^2) 强最小性检验（小账本用）：逐条剥离，结论必须改变。

    大规模证书改用 verify_certificate 内的 O(k) 结构化检验。
    """
    peelable = list(cert.records)
    for i in range(len(peelable)):
        rec = peelable[i]
        reduced = Certificate(
            cert.ledger_id, cert.claim_seq, cert.anchor_water,
            None if isinstance(rec, Cp) else cert.anchor,
            [r for j, r in enumerate(peelable) if j != i],
            cert.verdict, cert.reason, cert.seal, list(cert.claims),
            claim_outcomes=dict(cert.claim_outcomes),
        )
        ok, _detail = _replay_only(reduced, keys)
        if ok:
            return False, f"证书非最小：移除记录 {i} 后结论仍成立"
    return True, "剥离检验通过：证书最小"


def _replay_only(cert: Certificate, keys: Keys) -> tuple[bool, str]:
    """剥离检验用：只做独立验签与重放，不递归做最小性检查。"""
    bad_sig_ids = {k for k, v in cert.claim_outcomes.items() if v == "BAD-SIG"}
    for rec in cert.records:
        if isinstance(rec, Ann):
            if not verify_sig(keys.svc_key, D_ANNOUNCE, rec.signed_parts(), rec.sig) \
                    and rec.digest().hex() not in bad_sig_ids:
                return False, "未声明的坏签名公告"
        elif isinstance(rec, Rev):
            if not verify_sig(keys.svc_key, D_REVOKE, rec.signed_parts(), rec.sig):
                return False, "撤回验签失败"
        elif isinstance(rec, Cp):
            if not verify_sig(keys.cp_key, D_CHECKPOINT, rec.signed_parts(), rec.sig):
                return False, "检查点验签失败"
        else:
            return False, "未知记录"
    cview = _CertificateView(cert, keys)
    # 剥离后，声称必须仍由证书内记录佐证；否则视为结论不再成立
    record_ids = {r.digest() for r in cert.records if isinstance(r, Ann)}
    effective_claims = [a for a in cert.claims if a.digest() in record_ids]
    if len(effective_claims) != len(cert.claims):
        return False, "claim-evidence-removed"
    rebuilt = build_certificate(cview, cert.claim_seq, effective_claims)
    same = (rebuilt.verdict == cert.verdict
            and rebuilt.reason == cert.reason
            and rebuilt.claim_outcomes == cert.claim_outcomes)
    if not same:
        return False, f"{rebuilt.verdict}/{rebuilt.reason}/{rebuilt.claim_outcomes}"
    # 封存承诺也属于证书结论的一部分：剥离后其绑定核对必须失败
    if cert.seal is not None:
        window_revs = [r for r in cview.revs_before(cert.seal.water)
                       if r.seq >= cert.anchor_water]
        rr = revocation_root(r.digest() for r in window_revs)
        roots = replay_roots(cview, cert.anchor_water, cert.seal.water,
                             [a for a in cert.records if isinstance(a, Ann)])
        if rr == cert.seal.rev_root and merkle_root(roots) == cert.seal.root:
            return True, "seal-still-holds"
    return True, rebuilt.verdict


# ---------------------------------------------------------------------------
# 8. 分块审计器（局部访问 + 访问计数）
# ---------------------------------------------------------------------------


@dataclass
class BlockState:
    bid: int
    anns: dict[tuple[int, int], Ann] = field(default_factory=dict)
    revs: list[Rev] = field(default_factory=list)
    bad_anns: dict[tuple[int, int], Ann] = field(default_factory=dict)
    anchor_cp: Optional[Cp] = None
    eligible: bool = False
    starved: bool = False         # 锚缺失（前序块未闭合或被撤回击穿）
    local_water: int = 0          # 块内连续可达水位（绝对 seq）
    roots_at_end: list[bytes] = field(default_factory=list)
    sealed: bool = False


class Auditor(View):
    """分块审计器。

    block_size 为每块段数；块 bid 覆盖 seq ∈ [bid*B, (bid+1)*B)。
    访问计数器 access_events 记录每一次被触达的块号与操作类型，测试据此
    证明"单段补齐/撤销只访问相关区间"。

    局部性不变量
    ------------
    * 摄入一条公告/撤回只触达它所属的那一个块（ann/rev/recompute 事件）；
    * 块间依赖通过 *边界根缓存* boundary_roots 以 O(1) 索引读取，前序块
      闭合/失效只会翻转下游块的脏标记（dirty），不产生块访问事件；
    * 下游块在被查询（watermark/证书/封存）时按脏标记惰性重算，事件记为
      read，与摄入路径的事件分开统计。
    注：分块引擎的块锚取块边界检查点；任意水位检查点仍由证书层与朴素
    参考实现完整支持。
    """

    def __init__(self, ledger_id: str, keys: Keys, block_size: int = 1024):
        self.ledger_id = ledger_id
        self.keys = keys
        self.block_size = block_size
        self.genesis = genesis_anchor(ledger_id)
        self.blocks: dict[int, BlockState] = {}
        self.known_bids: set[int] = set()
        self.max_bid = -1
        self.dirty: set[int] = set()
        self.cps: dict[int, Cp] = {}                 # water -> Cp（验签通过）
        self.bad_cps: list[Cp] = []
        self.seals: dict[int, Seal] = {}
        self.seal_chain: list[Seal] = []
        # 边界水位 -> 该边界可达的链接摘要集合（块闭合时写入，失效时清除）
        self.boundary_roots: dict[int, set[bytes]] = {}
        self.access_events: list[tuple[str, int]] = []
        self.revoked_digests: set[bytes] = set()
        self._ingest_count = 0

    # ---- 访问计数 ---------------------------------------------------------

    def _touch(self, op: str, bid: int) -> None:
        self.access_events.append((op, bid))

    def touched_bids(self, op: Optional[str] = None) -> set[int]:
        return {bid for o, bid in self.access_events if op is None or o == op}

    def ingest_touched_bids(self) -> set[int]:
        """摄入路径触达的块（不含查询期的惰性 read）。"""
        return {bid for o, bid in self.access_events
                if o in ("ann", "rev", "recompute", "cp")}

    def reset_access(self) -> None:
        self.access_events.clear()

    # ---- 记录摄入 ---------------------------------------------------------

    def ingest(self, rec) -> None:
        self._ingest_count += 1
        if isinstance(rec, Ann):
            self._ingest_ann(rec)
        elif isinstance(rec, Rev):
            self._ingest_rev(rec)
        elif isinstance(rec, Cp):
            self._ingest_cp(rec)
        elif isinstance(rec, Seal):
            self._ingest_seal(rec)
        else:
            raise TypeError(f"未知记录: {rec!r}")

    def _bid_of(self, seq: int) -> int:
        return seq // self.block_size

    def _window_bids(self, lo_seq: int, hi_seq: int) -> range:
        """覆盖 [lo_seq, hi_seq) 的块号区间；空窗口返回空 range。"""
        if hi_seq <= lo_seq:
            return range(0)
        return range(self._bid_of(lo_seq), self._bid_of(hi_seq - 1) + 1)

    def _block(self, bid: int) -> BlockState:
        if bid not in self.blocks:
            self.blocks[bid] = BlockState(bid=bid)
            self.known_bids.add(bid)
            self.max_bid = max(self.max_bid, bid)
            self.dirty.add(bid)
        return self.blocks[bid]

    def _ingest_ann(self, ann: Ann) -> None:
        bid = self._bid_of(ann.seq)
        blk = self.blocks.get(bid)
        key = (ann.seq, ann.version)
        # 幂等判断先于访问计数：重复投递不产生任何块访问事件
        if blk is not None and (key in blk.anns or key in blk.bad_anns):
            return
        if blk is None:
            blk = self._block(bid)
        self._touch("ann", bid)
        if not verify_sig(self.keys.svc_key, D_ANNOUNCE, ann.signed_parts(), ann.sig):
            blk.bad_anns[key] = ann
            self.dirty.add(bid)
            self._recompute(bid)
            return
        blk.anns[key] = ann
        self.dirty.add(bid)
        self._recompute(bid)

    def _ingest_rev(self, rev: Rev) -> None:
        bid = self._bid_of(rev.seq)
        blk = self.blocks.get(bid)
        # 重复撤回幂等：先查重，再计数
        if blk is not None and any(r.digest() == rev.digest() for r in blk.revs):
            return
        if blk is None:
            blk = self._block(bid)
        self._touch("rev", bid)
        if not verify_sig(self.keys.svc_key, D_REVOKE, rev.signed_parts(), rev.sig):
            return  # 坏撤回直接忽略（不产生撤回效力，也不计入证据）
        blk.revs.append(rev)
        self.revoked_digests.add(rev.revokes)
        self.dirty.add(bid)
        self._recompute(bid)

    def _ingest_cp(self, cp: Cp) -> None:
        if not verify_sig(self.keys.cp_key, D_CHECKPOINT, cp.signed_parts(), cp.sig):
            self.bad_cps.append(cp)
            return
        if cp.water in self.cps:
            return
        self.cps[cp.water] = cp
        # 块边界检查点只影响其锚定的那一个块；非边界检查点交由证书层使用
        if cp.water % self.block_size == 0:
            bid = cp.water // self.block_size
            if bid in self.blocks:
                self._touch("cp", bid)
                self.dirty.add(bid)
                self._recompute(bid)

    def _ingest_seal(self, seal: Seal) -> None:
        if not verify_sig(self.keys.svc_key, D_SEAL, seal.signed_parts(), seal.sig):
            return
        if seal.water in self.seals:
            return
        self.seals[seal.water] = seal
        self.seal_chain.append(seal)

    # ---- 块锚与块重算（只触达本块；块间锚为 O(1) 缓存索引）----

    def _block_anchor(self, bid: int) -> tuple[set[bytes], int]:
        """块 bid 的锚链接摘要集合与锚水位。"""
        start = bid * self.block_size
        cp = self.cps.get(start)
        if cp is not None:
            return {cp.root}, start
        if start == 0:
            return {self.genesis}, 0
        return set(self.boundary_roots.get(start, ())), start

    def _ensure_fresh(self, bid: int) -> None:
        if bid in self.dirty and bid in self.blocks:
            self._touch("read", bid)
            self._recompute(bid)

    def _recompute(self, bid: int) -> None:
        blk = self.blocks[bid]
        self._touch("recompute", bid)
        self.dirty.discard(bid)
        anchor_set, anchor_water = self._block_anchor(bid)
        start = bid * self.block_size
        end = start + self.block_size

        revoked = {r.revokes for r in blk.revs}
        # 按 seq 收集合法、未撤回候选
        by_seq: dict[int, list[Ann]] = {}
        for a in blk.anns.values():
            if a.digest() in revoked:
                continue
            by_seq.setdefault(a.seq, []).append(a)

        blk.starved = not anchor_set
        known_links = set(anchor_set)
        local_water = anchor_water
        roots: list[bytes] = []
        eligible = bool(anchor_set)
        for seq in range(start, end):
            cands = by_seq.get(seq, [])
            chained = [a for a in cands if a.parent_digest in known_links]
            if not chained:
                eligible = False
                break
            uniq = {a.link_digest(): a for a in chained}
            known_links.update(uniq.keys())
            local_water = seq + 1
            roots = sorted(uniq.keys())
        blk.eligible = eligible
        blk.local_water = local_water
        blk.roots_at_end = roots
        blk.anchor_cp = self.cps.get(start)
        blk.sealed = eligible and local_water == end and end in self.seals

        # 维护边界根缓存：本块闭合则发布边界根，否则撤回可能过期的缓存。
        # 下游块只翻转脏标记（无块访问事件），惰性到查询期再重算。
        if eligible and local_water == end:
            self.boundary_roots[end] = set(roots)
        else:
            self.boundary_roots.pop(end, None)
        nxt = bid + 1
        if nxt in self.blocks:
            self.dirty.add(nxt)

    # ---- 全局水位 ---------------------------------------------------------

    def watermark(self) -> int:
        """封存水位 = 最早缺段所在位置；后到签名段不能盖过缺段。

        若存在块边界检查点，最早检查点之前的链由检查点权威背书，水位扫描
        从该锚定块开始。
        """
        if not self.known_bids:
            return 0
        boundary_cp_bids = [w // self.block_size
                            for w in self.cps if w % self.block_size == 0]
        start_bid = min(boundary_cp_bids) if boundary_cp_bids else 0
        for bid in range(start_bid, self.max_bid + 1):
            blk = self.blocks.get(bid)
            if blk is None:
                return bid * self.block_size       # 整块缺失
            self._ensure_fresh(bid)
            if not blk.eligible:
                return blk.local_water             # 块内最早缺段
        # 所有已知块均闭合：水位即末块实际到达的连续水位（末块可能非满）
        return self.blocks[self.max_bid].local_water

    def can_seal(self, water: int) -> bool:
        return water <= self.watermark()

    # ---- View 协议实现 ----------------------------------------------------

    def anns_in_window(self, lo_seq: int, hi_seq: int) -> list[Ann]:
        out: list[Ann] = []
        for bid in self._window_bids(lo_seq, hi_seq):
            self._ensure_fresh(bid)
            self._touch("read", bid)
            blk = self.blocks.get(bid)
            if blk:
                out.extend(a for a in blk.anns.values() if lo_seq <= a.seq < hi_seq)
                # 坏签名公告作为否定证据可见（同样限制在窗口内）
                out.extend(a for a in blk.bad_anns.values() if lo_seq <= a.seq < hi_seq)
        return out

    def revs_in_window(self, lo_seq: int, hi_seq: int) -> list[Rev]:
        out: list[Rev] = []
        for bid in self._window_bids(lo_seq, hi_seq):
            self._ensure_fresh(bid)
            self._touch("read", bid)
            blk = self.blocks.get(bid)
            if blk:
                out.extend(r for r in blk.revs if lo_seq <= r.seq < hi_seq)
        return out

    def cp_at(self, water: int) -> Optional[Cp]:
        return self.cps.get(water)

    def cp_rev_root(self, water: int) -> Optional[bytes]:
        cp = self.cps.get(water)
        return cp.rev_root if cp is not None else None

    def anchor_before(self, water: int) -> tuple[bytes, int]:
        # 不晚于 water 的最近检查点
        candidates = [w for w in self.cps if w <= water]
        if candidates:
            w = max(candidates)
            return self.cps[w].root, w
        return self.genesis, 0

    def is_good_ann(self, ann: Ann) -> bool:
        return verify_sig(self.keys.svc_key, D_ANNOUNCE, ann.signed_parts(), ann.sig)

    def is_revoked_identity(self, ann: Ann) -> bool:
        return ann.digest() in self.revoked_digests

    def seal_at(self, water: int) -> Optional[Seal]:
        return self.seals.get(water)

    def revs_before(self, water: int) -> list[Rev]:
        out: list[Rev] = []
        for bid in self._window_bids(0, water):
            blk = self.blocks.get(bid)
            if blk:
                out.extend(r for r in blk.revs if r.seq < water)
        return out

    # ---- 封存承诺生成（服务与审计员协作）----

    def issue_seal(self, svc: Service, water: int) -> Seal:
        """在不超过当前水位处签发封存承诺；超水位请求被拒绝。"""
        if not self.can_seal(water):
            raise PermissionError(
                f"拒绝封存水位 {water}：最早缺段水位为 {self.watermark()}，"
                "后到签名段不能盖过缺段"
            )
        anchor_digest, anchor_water = self.anchor_before(water)
        anchor_cp = self.cps.get(anchor_water)
        # 重放 [anchor_water, water) 求规范根集合（只扫相关区间的块）
        anns: list[Ann] = []
        for bid in self._window_bids(anchor_water, water):
            self._ensure_fresh(bid)
            self._touch("seal", bid)
            blk = self.blocks.get(bid)
            if blk:
                anns.extend(a for a in blk.anns.values() if anchor_water <= a.seq < water)
        roots = replay_roots(self, anchor_water, water, anns)
        root = merkle_root(roots)
        # 封存承诺只绑定锚后窗口内的撤回聚合；锚前历史撤回由检查点背书
        window_revs = [r for r in self.revs_before(water) if r.seq >= anchor_water]
        rev_root = revocation_root(r.digest() for r in window_revs)
        parent = self.seal_chain[-1].digest() if self.seal_chain else b"\x00" * 32
        seal = svc.make_seal(
            water, root, rev_root,
            anchor_cp.digest() if anchor_cp else b"\x00" * 32,
            parent,
        )
        self.ingest(seal)
        # 标记落在完整块边界的封存
        bid = self._bid_of(water - 1)
        if water % self.block_size == 0 and bid in self.blocks:
            self.blocks[bid].sealed = True
        return seal

    # ---- 状态摘要（与朴素实现互校）----

    def state_digest(self) -> bytes:
        self.watermark()  # 先惰性刷新全部脏块，保证摘要反映最新状态
        h = hashlib.sha256()
        h.update(b"state-v1")
        h.update(enc(self.watermark()))
        for bid in sorted(self.blocks):
            blk = self.blocks[bid]
            h.update(enc(bid))
            h.update(enc(sorted(a.digest() for a in blk.anns.values())))
            h.update(enc(sorted(a.digest() for a in blk.bad_anns.values())))
            h.update(enc(sorted(r.digest() for r in blk.revs)))
            h.update(enc(blk.eligible))
            h.update(enc(blk.local_water))
        h.update(enc(sorted(self.cps)))
        h.update(enc(sorted(self.seals)))
        h.update(enc(sorted(self.revoked_digests)))
        return h.digest()


# ---------------------------------------------------------------------------
# 9. 朴素全量审计器（独立参考实现，无分块、无局部性优化）
# ---------------------------------------------------------------------------


class NaiveAuditor(View):
    """扁平全量实现：每个操作都全量重扫，作为分块审计器的对照预言机。"""

    def __init__(self, ledger_id: str, keys: Keys):
        self.ledger_id = ledger_id
        self.keys = keys
        self.genesis = genesis_anchor(ledger_id)
        self.anns: dict[tuple[int, int], Ann] = {}
        self.bad_anns: dict[tuple[int, int], Ann] = {}
        self.revs: list[Rev] = []
        self.cps: dict[int, Cp] = {}
        self.seals: dict[int, Seal] = {}
        self.revoked_digests: set[bytes] = set()

    def ingest(self, rec) -> None:
        if isinstance(rec, Ann):
            key = (rec.seq, rec.version)
            if key in self.anns or key in self.bad_anns:
                return
            if not verify_sig(self.keys.svc_key, D_ANNOUNCE, rec.signed_parts(), rec.sig):
                self.bad_anns[key] = rec
                return
            self.anns[key] = rec
        elif isinstance(rec, Rev):
            if not verify_sig(self.keys.svc_key, D_REVOKE, rec.signed_parts(), rec.sig):
                return
            if any(r.digest() == rec.digest() for r in self.revs):
                return
            self.revs.append(rec)
            self.revoked_digests.add(rec.revokes)
        elif isinstance(rec, Cp):
            if not verify_sig(self.keys.cp_key, D_CHECKPOINT, rec.signed_parts(), rec.sig):
                return
            self.cps.setdefault(rec.water, rec)
        elif isinstance(rec, Seal):
            if not verify_sig(self.keys.svc_key, D_SEAL, rec.signed_parts(), rec.sig):
                return
            self.seals.setdefault(rec.water, rec)

    def _good_live(self) -> list[Ann]:
        return [a for a in self.anns.values() if a.digest() not in self.revoked_digests]

    def watermark(self) -> int:
        """全量贪心：从创世/最近检查点出发找最早缺段。"""
        anchor_digest, anchor_water = self.anchor_before(10 ** 12)
        live = self._good_live()
        by_seq: dict[int, list[Ann]] = {}
        for a in live:
            by_seq.setdefault(a.seq, []).append(a)
        known = {anchor_digest}
        seq = anchor_water
        while True:
            cands = [a for a in by_seq.get(seq, []) if a.parent_digest in known]
            if not cands:
                return seq
            for a in cands:
                known.add(a.link_digest())
            seq += 1

    def can_seal(self, water: int) -> bool:
        return water <= self.watermark()

    def anns_in_window(self, lo_seq, hi_seq):
        return [a for a in list(self.anns.values()) + list(self.bad_anns.values())
                if lo_seq <= a.seq < hi_seq]

    def revs_in_window(self, lo_seq, hi_seq):
        return [r for r in self.revs if lo_seq <= r.seq < hi_seq]

    def cp_at(self, water):
        return self.cps.get(water)

    def cp_rev_root(self, water):
        cp = self.cps.get(water)
        return cp.rev_root if cp is not None else None

    def anchor_before(self, water):
        candidates = [w for w in self.cps if w <= water]
        if candidates:
            w = max(candidates)
            return self.cps[w].root, w
        return self.genesis, 0

    def is_good_ann(self, ann):
        return verify_sig(self.keys.svc_key, D_ANNOUNCE, ann.signed_parts(), ann.sig)

    def is_revoked_identity(self, ann):
        return ann.digest() in self.revoked_digests

    def seal_at(self, water):
        return self.seals.get(water)

    def revs_before(self, water):
        return [r for r in self.revs if r.seq < water]

    def issue_seal(self, svc: Service, water: int) -> Seal:
        if not self.can_seal(water):
            raise PermissionError("超水位封存被拒绝")
        anchor_digest, anchor_water = self.anchor_before(water)
        anchor_cp = self.cps.get(anchor_water)
        roots = replay_roots(
            self, anchor_water, water,
            [a for a in self.anns.values() if anchor_water <= a.seq < water],
        )
        root = merkle_root(roots)
        window_revs = [r for r in self.revs_before(water) if r.seq >= anchor_water]
        rev_root = revocation_root(r.digest() for r in window_revs)
        parent = max(self.seals.values(), key=lambda s: s.water).digest() \
            if self.seals else b"\x00" * 32
        seal = svc.make_seal(
            water, root, rev_root,
            anchor_cp.digest() if anchor_cp else b"\x00" * 32, parent,
        )
        self.ingest(seal)
        return seal

    def state_digest(self) -> bytes:
        h = hashlib.sha256()
        h.update(b"state-v1")
        h.update(enc(self.watermark()))
        h.update(enc(sorted(a.digest() for a in self.anns.values())))
        h.update(enc(sorted(a.digest() for a in self.bad_anns.values())))
        h.update(enc(sorted(r.digest() for r in self.revs)))
        h.update(enc(sorted(self.cps)))
        h.update(enc(sorted(self.seals)))
        h.update(enc(sorted(self.revoked_digests)))
        return h.digest()


# ---------------------------------------------------------------------------
# 10. 历史重放：用"当时的记录前缀"重建任意旧水位视图与证书
# ---------------------------------------------------------------------------


def replay_prefix(records: list, ledger_id: str, keys: Keys, block_size: int,
                  *, naive: bool = False) -> "Auditor | NaiveAuditor":
    """重放记录前缀，得到该历史时刻的审计器视图（确定性）。"""
    view: View = NaiveAuditor(ledger_id, keys) if naive else Auditor(ledger_id, keys, block_size)
    for rec in records:
        view.ingest(rec)
    return view


def rebuild_historical_certificate(records: list, ledger_id: str, keys: Keys,
                                   block_size: int, claim_seq: int,
                                   claims: Optional[list[Ann]] = None,
                                   *, naive: bool = False) -> Certificate:
    """按 journal 前缀重放后重建证书；与当时在线输出逐字节可比。"""
    view = replay_prefix(records, ledger_id, keys, block_size, naive=naive)
    return build_certificate(view, claim_seq, claims)
