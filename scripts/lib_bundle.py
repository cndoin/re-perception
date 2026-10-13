"""快照 + 证据 bundle 导入/导出/对比 —— 复刻 REA 的可复用/可重放机制。

对齐 REA 的三项横切能力：
- **快照**：保留一次成功分析结果供复用。**内容寻址精确命中**才复用 —— 目标字节
  摘要 + 操作 + 参数 + provider 全等才算命中；变更即失效。是「缓存观察」而非
  provider 数据库，owner-only 权限、原子写。
- **bundle 导出**：规范字节稳定排序（同一内容 → 同一字节），原子发布，显式
  overwrite。
- **bundle 导入**：逐条校验证据 ID 与内容摘要一致后原子合并；篡改/不一致拒收。
- **bundle 对比**：成员一一配对，给出 added / removed / changed。

纯标准库；异常要么抛出、要么显式记录，绝不静默吞。
"""

from __future__ import annotations

import json
import os
import time

from lib_evidence import canonical_digest  # noqa: E402 —— 复用统一哈希裁决点

__all__ = [
    "snapshot_key", "save_snapshot", "load_snapshot",
    "export_bundle", "import_bundle", "compare_bundles",
]


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _atomic_write(path, payload_bytes):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(payload_bytes)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)  # owner-only（快照/证据属敏感资产）
    except Exception:  # lint:ok 某些文件系统不支持 chmod，失败不致命、无补救手段
        pass


# ---------------------------------------------------------------- 快照

def snapshot_key(subject_sha256, operation, parameters, provider=None):
    """内容寻址的快照键（精确命中）。

    目标字节摘要 + 操作 + 参数 + provider 全等才共享一个键 —— 任一变化即不同键，
    天然实现「变更即失效」。
    """
    payload = {
        "subject_sha256": subject_sha256,
        "operation": operation,
        "parameters": parameters or {},
        "provider": provider,
    }
    return "snap-" + canonical_digest(payload)[:32]


def save_snapshot(cache_dir, key, result):
    """保存一条快照。原子写、owner-only。返回快照文件路径。"""
    if not key.startswith("snap-"):
        raise ValueError("快照键必须以 snap- 开头：%r" % key)
    path = os.path.join(cache_dir, key + ".json")
    record = {
        "version": 1,
        "key": key,
        "saved_at": _now_iso(),
        "result": result,
    }
    _atomic_write(path, json.dumps(record, ensure_ascii=False, indent=2,
                                  default=str).encode("utf-8"))
    return path


def load_snapshot(cache_dir, key):
    """读取快照；不存在返回 None（不算错误），损坏抛 ValueError。"""
    path = os.path.join(cache_dir, key + ".json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except Exception as ex:  # noqa: BLE001
        raise ValueError("快照损坏：%s（%s）" % (path, ex))
    if rec.get("key") != key:
        raise ValueError("快照键不匹配：%s ≠ %s" % (rec.get("key"), key))
    return rec.get("result")


# ---------------------------------------------------------------- bundle

def _as_dict(rec):
    """把证据对象规范化为 dict（Evidence 有 to_dict；dict 原样返回）。"""
    if isinstance(rec, dict):
        return rec
    to_dict = getattr(rec, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError("无法序列化的证据类型: %s" % type(rec).__name__)


def _canonical_bytes(bundle):
    """规范字节：键排序、无多余空白、UTF-8。同内容 → 同字节。"""
    return json.dumps(bundle, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def export_bundle(path, evidence_records, meta=None, overwrite=False):
    """导出证据 bundle（规范字节稳定、原子发布）。"""
    if os.path.exists(path) and not overwrite:
        raise FileExistsError("目标已存在，需显式 overwrite：%s" % path)
    records = [_as_dict(r) for r in evidence_records]
    bundle = {
        "version": 1,
        "kind": "evidence-bundle",
        "exported_at": _now_iso(),
        "meta": meta or {},
        "evidence": records,
    }
    _atomic_write(path, _canonical_bytes(bundle))
    return {"path": path, "count": len(records),
            "digest": canonical_digest(bundle)}


def import_bundle(path, existing_ids=None, strict=True):
    """导入证据 bundle 并校验。

    逐条验证据 ``evidence_id`` 与其内容摘要一致（防篡改）。``strict=True`` 时
    任何一条不一致整体拒收；``strict=False`` 跳过坏条目并记录 ``rejected``。
    返回 ``{imported, rejected, duplicates, digest}``。
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        try:
            bundle = json.load(f)
        except Exception as ex:  # noqa: BLE001
            raise ValueError("bundle 解析失败：%s" % ex)
    records = bundle.get("evidence", [])
    existing = set(existing_ids or ())
    imported, rejected, dup = [], [], []
    for i, rec in enumerate(records):
        rid = rec.get("evidence_id")
        if not rid:
            _reject_or_raise(rejected, i, "缺 evidence_id", strict)
            continue
        # 校验内容哈希与 ID 一致（复用 compute_evidence_id 语义）
        from lib_evidence import compute_evidence_id
        try:
            expect = compute_evidence_id(rec)
        except Exception as ex:  # noqa: BLE001
            _reject_or_raise(rejected, i, "内容摘要失败: %s" % ex, strict)
            continue
        if expect != rid:
            _reject_or_raise(rejected, i,
                             "ID 与内容摘要不一致（疑似篡改）", strict)
            continue
        if rid in existing:
            dup.append(rid)
            continue
        imported.append(rec)
        existing.add(rid)
    return {"imported": len(imported), "rejected": rejected,
            "duplicates": dup, "records": imported,
            "digest": canonical_digest(bundle)}


def _reject_or_raise(rejected, index, reason, strict):
    if strict:
        raise ValueError("bundle 第 %d 条：%s" % (index, reason))
    rejected.append({"index": index, "reason": reason})


def compare_bundles(bundle_a, bundle_b):
    """对比两个 bundle 的证据成员（一一配对）。

    返回 ``{added, removed, changed, unchanged}``，每个 ``changed`` 给两侧摘要。
    """
    a = {_as_dict(r).get("evidence_id"): _as_dict(r) for r in bundle_a.get("evidence", [])}
    b = {_as_dict(r).get("evidence_id"): _as_dict(r) for r in bundle_b.get("evidence", [])}
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed, unchanged = [], []
    for rid in sorted(set(a) & set(b)):
        da, db = canonical_digest(a[rid]), canonical_digest(b[rid])
        if da == db:
            unchanged.append(rid)
        else:
            changed.append({"evidence_id": rid,
                            "a_digest": da, "b_digest": db})
    return {"added": added, "removed": removed,
            "changed": changed, "unchanged": unchanged,
            "added_count": len(added), "removed_count": len(removed),
            "changed_count": len(changed), "unchanged_count": len(unchanged)}
