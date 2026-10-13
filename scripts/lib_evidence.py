# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""lib_evidence.py —— 证据契约层（把逆向发现变成可溯源、可哈希、可去重的证据）

这是 REA（morluto/rea，MIT）证据模型移植进本工具箱的一层。re-perception 的各
`lib_*.py` 负责**产出发现**（识别格式、提字符串、反汇编、还原符号……），本模块
负责把这些发现**包装成可审计的证据**，回答「这条结论从哪来、有多硬、边界在哪」。

    发现（finding）  →  证据（evidence）  →  裁决（adjudication）

三件事让「发现」升级成「证据」：

**① confidence 三分法**：`observed`（引擎直出的原始事实）→ `derived`（从若干事实
   推导、可复算）→ `inferred`（分析者推断）。工具箱原来只在 identify 里塞了个
   `"confidence": "low"` 字符串，把「我看到的」和「我猜的」混在一起。三分法补这个洞。

**② limitations 必填**：结论再确定也必须写清边界。这比「没把握就标 unverified」强
   一档 —— 后者只管失败路径，前者管成功路径上的过度外推。

**③ evidence_id 是内容哈希，不是随机 UUID**：同样的输入必然产生同样的 ID。于是
   「同源即非独立」从人工判断变成 `==` 比较：两条证据 ID 相同 ⇒ 只算 1 个源。

配套的**残余未知项**（residual unknown）把「不知道」结构化成待办 —— 记下为什么
不知道、要什么条件才能知道、该往哪路由，而不是让「不知道」当终点。登记未知项这个
动作本身也产出证据，但**固定标注 `inferred` / `analyst-inference`**：登记 ≠ 知道。

## 与 morluto/rea 的对应

    rea/src/domain/evidence.ts      → 本文件「证据契约」段
    rea/src/domain/residualUnknown  → 本文件「残余未知项」段
    rea/src/adapters/（provider）    → 本文件「证据提供者」段

移植做了三处本地化：TypeScript+zod → 纯标准库；标识算法用 `ev-<sha256[:32]>`；
不可变语义用 canonical JSON 字符串 + `__setattr__` 封印。**零第三方依赖**，与本
工具箱其余部分一致。

## 边界

本模块只做证据的**构造、校验、哈希、比对、登记、路由建议**，不执行任何工具、不发
网络请求、不解析目标文件 —— 那是各 `lib_*.py` 与 `re.py` 的事。这样它才能被逐条单测。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time

# 退出码与 re.py 保持一致：0 成功 / 2 用法错误 / 3 目标不可读 / 4 分析出错。
# 刻意不 import re.py —— 它会遮蔽标准库 re，且本模块不该依赖 CLI 层。
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_TARGET = 3
EXIT_RUNTIME = 4

# ==========================================================================
# 第一段 · 证据契约（枚举 + 校验 + 内容哈希 + 不可变 Evidence）
# ==========================================================================

#: 结论强度。observed=引擎直出；derived=可复算推导；inferred=分析者推断。
CONFIDENCE_LEVELS = ("observed", "derived", "inferred")

#: 证据权威来源类型。
AUTHORITY_LEVELS = (
    "shipped-artifact",      # 来自目标产物本身（静态解析、反汇编、符号还原）
    "controlled-replay",     # 受控重放/复现（跑过一遍拿到回执）
    "historical-reference",  # 历史参考（文档、旧记录、规则库）
    "external-service",      # 外部服务（工具链探测、registry/URL 查询）
    "analyst-inference",     # 分析者推断 —— 最弱，别当事实用
)

#: 执行隔离级别。沙箱里跑出来的和本机裸跑的不是一回事。
ISOLATION_LEVELS = ("none", "process", "container", "virtual-machine")

#: 位置类型 —— 判别联合，按 kind 决定其余字段。
LOCATION_KINDS = (
    "address",
    "address-range",
    "artifact-path",
    "file-offset",
    "file-offset-range",
)

#: subject.format 取值（对齐 REA 的 format 枚举，收敛为本工具箱可产出的子集）。
SUBJECT_FORMATS = (
    "pe", "elf", "mach-o", "mach-o-universal", "dex", "apk", "ipa", "jar",
    "class", "pyc", "wasm", "sqlite", "zip", "dmg", "firmware", "javascript",
    "source-map", "directory", "file", "raw-binary", "unknown",
)


def _frozen(value):
    """把任意 JSON 值编码成不可变的 canonical JSON 字符串。

    存字符串而不是把 dict/list 转 tuple：tuple 化后**解冻有歧义** ——
    `[["a",1],["b",2]]` 冻成 tuple 再解，会分不清是「字典键值对」还是「二元组列表」，
    可能被还原成 `{"a":1,"b":2}`，数据被悄悄改写。审计凭据被悄悄改写 = 审计无效，
    所以宁可牺牲一点可读性，也要保证 round-trip 无歧义。字符串天然不可变。
    """
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)


def _thaw(frozen):
    """把 canonical JSON 字符串还原成普通 JSON 值。"""
    return json.loads(frozen)


class Validation:
    """校验结果收集器。errors 非空即不通过。错误以字符串返回，不抛异常。"""

    __slots__ = ("errors",)

    def __init__(self):
        self.errors = []

    def check(self, cond, msg):
        if not cond:
            self.errors.append(msg)

    def check_in(self, value, allowed, field):
        self.check(value in allowed,
                   "%s=%r 不在允许取值 %s" % (field, value, list(allowed)))

    def check_str(self, value, field, allow_empty=False):
        self.check(isinstance(value, str),
                   "%s 必须是字符串，实际是 %s" % (field, type(value).__name__))
        if isinstance(value, str) and not allow_empty:
            self.check(value.strip() != "", "%s 不允许为空" % field)

    @property
    def ok(self):
        return not self.errors


_LOCATION_FIELDS = {
    "address": {"kind", "address"},
    "address-range": {"kind", "start", "end"},
    "artifact-path": {"kind", "path"},
    "file-offset": {"kind", "offset"},
    "file-offset-range": {"kind", "start", "end"},
}


def _check_location(v, i):
    """校验单个 location。判别联合：先看 kind，再按 kind 查字段。"""
    if not isinstance(v, dict):
        return ["locations[%d] 必须是对象" % i]
    kind = v.get("kind")
    if kind not in LOCATION_KINDS:
        return ["locations[%d].kind=%r 不在 %s" % (i, kind, list(LOCATION_KINDS))]
    errs = []
    if kind == "address":
        if not isinstance(v.get("address"), str) or not v.get("address"):
            errs.append("locations[%d] kind=address 需要非空 address" % i)
    elif kind == "address-range":
        for k in ("start", "end"):
            if not isinstance(v.get(k), str) or not v.get(k):
                errs.append("locations[%d] kind=address-range 需要非空 %s" % (i, k))
    elif kind == "artifact-path":
        if not isinstance(v.get("path"), str) or not v.get("path"):
            errs.append("locations[%d] kind=artifact-path 需要非空 path" % i)
    elif kind == "file-offset":
        n = v.get("offset")
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            errs.append("locations[%d] kind=file-offset 的 offset 必须是非负整数" % i)
    elif kind == "file-offset-range":
        for k in ("start", "end"):
            n = v.get(k)
            if not isinstance(n, int) or isinstance(n, bool) or n < 0:
                errs.append("locations[%d] kind=file-offset-range 的 %s 必须是非负整数" % (i, k))
    allowed = _LOCATION_FIELDS[kind]
    for k in v:
        if k not in allowed:
            errs.append("locations[%d] 多余字段 %r（kind=%s 只允许 %s）"
                        % (i, k, kind, sorted(allowed)))
    return errs


def validate_record(rec):
    """校验一条证据记录（不含 evidence_id 自校验）。返回 Validation。"""
    v = Validation()
    if not isinstance(rec, dict):
        v.check(False, "证据记录必须是对象，实际是 %s" % type(rec).__name__)
        return v

    v.check_str(rec.get("predicate_type"), "predicate_type")
    v.check_str(rec.get("operation"), "operation")
    v.check_in(rec.get("confidence"), CONFIDENCE_LEVELS, "confidence")
    v.check_in(rec.get("authority"), AUTHORITY_LEVELS, "authority")

    # limitations 必填，且必须是非空字符串数组 —— 空串等于没写限制。
    lim = rec.get("limitations")
    if not isinstance(lim, list):
        v.check(False, "limitations 必须是数组（必填，无限制时写明 \"无已知限制\"）")
    else:
        v.check(len(lim) > 0, "limitations 不允许为空数组；确无限制请写 [\"无已知限制\"]")
        for i, item in enumerate(lim):
            v.check(isinstance(item, str) and item.strip(),
                    "limitations[%d] 必须是非空字符串" % i)

    # provider 必填：证据必须说清是谁产出的。
    prov = rec.get("provider")
    if not isinstance(prov, dict):
        v.check(False, "provider 必须是对象")
    else:
        v.check_str(prov.get("id"), "provider.id")
        v.check_str(prov.get("name"), "provider.name")
        ver = prov.get("version")
        v.check(ver is None or isinstance(ver, str), "provider.version 必须是字符串或 null")

    # subject 可空（对抽象概念的推断），但非空时字段要齐。
    subj = rec.get("subject")
    if subj is not None:
        if not isinstance(subj, dict):
            v.check(False, "subject 必须是对象或 null")
        else:
            v.check_str(subj.get("name"), "subject.name")
            digest = subj.get("digest")
            if not isinstance(digest, dict) or not isinstance(digest.get("sha256"), str) \
                    or not digest.get("sha256"):
                v.check(False, "subject.digest.sha256 必须是非空字符串")
            v.check_in(subj.get("format"), SUBJECT_FORMATS, "subject.format")
            v.check_str(subj.get("local_path"), "subject.local_path")

    # environment 可空，非空时 isolation 必须落在允许取值。
    env = rec.get("environment")
    if env is not None:
        if not isinstance(env, dict):
            v.check(False, "environment 必须是对象或 null")
        else:
            v.check_in(env.get("isolation"), ISOLATION_LEVELS, "environment.isolation")
            for k in ("id", "platform", "architecture"):
                v.check_str(env.get(k), "environment." + k)

    v.check(isinstance(rec.get("parameters"), dict), "parameters 必须是 JSON 对象")

    # normalized_result 必填；拿不到就别建证据，去登记未知项。
    v.check(rec.get("normalized_result") is not None,
            "normalized_result 不允许为 null（拿不到就别建证据，去登记未知项）")

    locs = rec.get("locations")
    if not isinstance(locs, list):
        v.check(False, "locations 必须是数组（可为空）")
    else:
        for i, item in enumerate(locs):
            for e in _check_location(item, i):
                v.errors.append(e)

    links = rec.get("evidence_links")
    if not isinstance(links, list):
        v.check(False, "evidence_links 必须是数组")
    else:
        for i, item in enumerate(links):
            v.check(isinstance(item, str) and item.startswith("ev-"),
                    "evidence_links[%d] 必须是 ev- 前缀的证据 ID" % i)
        v.check(len(set(links)) == len(links),
                "evidence_links 内不应有重复项（重复项会被内容哈希放大）")

    return v


def compute_evidence_id(record):
    """按内容算证据 ID。**同样的输入必然得到同样的 ID**。

    随机 UUID 让「两条证据是不是其实同一条」只能靠人看；内容哈希让这件事变成
    `==` 比较。「同源即非独立」由此可执行。
    """
    payload = {k: v for k, v in record.items() if k != "evidence_id"}
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)
    return "ev-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def canonical_digest(value):
    """对任意 JSON 值算稳定摘要。用于给 subject/输入打指纹。"""
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def input_fingerprint(operation, parameters, subject_sha256=None):
    """给「一次核查」打指纹，用于判同源。

    三要素：干什么(operation) + 用什么参数(parameters) + 对谁(subject)。
    三者全同 ⇒ 同一条证据，只算 1 个源。
    """
    return "fp-" + canonical_digest({
        "operation": operation,
        "parameters": parameters,
        "subject_sha256": subject_sha256,
    })


class Evidence:
    """一条已校验、已冻结的证据。

    不继承 dict：刻意拦住 `ev["confidence"] = "observed"` 这类事后改写。
    审计凭据可被修改 = 审计无效。

    ⚠️ 仅用 `__slots__` **不等于不可变** —— slots 只挡新增属性，挡不住对已声明
    属性的赋值，所以必须再拦一道 `__setattr__`。（实测踩出来的：光加 slots 时
    `ev._data = 1` 照样成功，于是 to_dict() 直接崩。"看起来不可变"和"真的不可变"
    是两回事。）
    """

    __slots__ = ("_data", "_id", "_sealed")

    def __init__(self, record, validate=True):
        object.__setattr__(self, "_sealed", False)
        if not isinstance(record, dict):
            raise TypeError("证据记录必须是 dict")
        if validate:
            val = validate_record(record)
            if not val.ok:
                raise ValueError("证据校验失败: " + "; ".join(val.errors))
        eid = record.get("evidence_id") or compute_evidence_id(record)
        if record.get("evidence_id") and record["evidence_id"] != compute_evidence_id(record):
            raise ValueError("evidence_id 与记录内容不匹配（内容被改过）")
        object.__setattr__(self, "_id", eid)
        object.__setattr__(self, "_data", _frozen(record))
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "Evidence 已冻结，禁止改写 %r（审计凭据必须不可变）" % name)
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        raise AttributeError("Evidence 已冻结，禁止删除属性 %r" % name)

    @property
    def evidence_id(self):
        return self._id

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    @property
    def confidence(self):
        return self.get("confidence")

    @property
    def authority(self):
        return self.get("authority")

    @property
    def limitations(self):
        return self.get("limitations", [])

    @property
    def evidence_links(self):
        return self.get("evidence_links", [])

    def to_dict(self):
        """导出为普通 dict（含 evidence_id）。输出用，别拿它改内部状态。"""
        d = _thaw(self._data)
        d["evidence_id"] = self._id
        return d

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def __eq__(self, other):
        return isinstance(other, Evidence) and other._id == self._id

    def __hash__(self):
        return hash(self._id)

    def __repr__(self):
        return "<Evidence %s conf=%s auth=%s>" % (
            self._id, self.get("confidence"), self.get("authority"))


def create_evidence(provider, predicate_type, operation, parameters,
                    normalized_result, confidence, authority,
                    limitations, subject=None, environment=None,
                    locations=None, evidence_links=None,
                    raw_result=None, analysis_profile=None):
    """构造一条证据。`limitations` 是位置参数而不是关键字参数 —— 刻意的：
    让「想不出限制」的人必须停下来想，而不是靠默认值蒙混过去。
    """
    rec = {
        "subject": subject,
        "provider": provider,
        "analysis_profile": analysis_profile,
        "predicate_type": predicate_type,
        "operation": operation,
        "parameters": parameters,
        "raw_result": raw_result,
        "normalized_result": normalized_result,
        "confidence": confidence,
        "authority": authority,
        "environment": environment,
        "limitations": list(limitations),
        "locations": list(locations or []),
        "evidence_links": list(evidence_links or []),
    }
    return Evidence(rec)


_RANK = {"observed": 3, "derived": 2, "inferred": 1}


def adjudicate(evidence_list):
    """对一组证据做强度裁决。两条硬规则：

      - **同源即非独立**：相同 evidence_id 只算 1 条
      - **弱者下限**：链条强度取决于最弱一环，不取决于最强
    """
    if not evidence_list:
        return {
            "count": 0, "unique_count": 0, "independent_sources": 0,
            "strength": "unknown", "blocked_reasons": ["无任何证据"],
        }
    ids = [e.evidence_id for e in evidence_list]
    unique = set(ids)
    blocked = []
    if len(unique) < len(ids):
        blocked.append("存在 %d 条重复证据（同源），独立源只算 %d 条"
                       % (len(ids) - len(unique), len(unique)))
    confs = [e.confidence for e in evidence_list]
    weakest = min(confs, key=lambda c: _RANK.get(c, 0))
    strongest = max(confs, key=lambda c: _RANK.get(c, 0))
    if all(e.authority == "analyst-inference" for e in evidence_list):
        blocked.append("全部证据均为 analyst-inference，不得作为事实陈述")
    return {
        "count": len(ids), "unique_count": len(unique),
        "independent_sources": len(unique), "strength": weakest,
        "strongest": strongest, "blocked_reasons": blocked,
    }


def can_support_confirmed(evidence_list, require_sources=2):
    """判断一组证据够不够格撑起一个「已确认」声明。返回 (bool, reasons)。

    默认要求 >=2 个独立源，且至少一条来自 shipped-artifact / controlled-replay /
    external-service（分析者推断不能单独当事实）。
    """
    verdict = adjudicate(evidence_list)
    reasons = list(verdict["blocked_reasons"])
    if verdict["independent_sources"] < require_sources:
        reasons.append("独立源 %d 个 < 要求的 %d 个"
                       % (verdict["independent_sources"], require_sources))
    if verdict["strength"] == "inferred":
        reasons.append("证据链强度仅 inferred，只能支撑推断，不能支撑已确认")
    if not any(e.authority in ("shipped-artifact", "controlled-replay",
                               "external-service") for e in evidence_list):
        reasons.append("缺少 shipped-artifact / controlled-replay / external-service 类证据")
    return (not reasons), reasons


# ==========================================================================
# 第二段 · 残余未知项（把「不知道」结构化成待办）
# ==========================================================================

#: 解决状态。
RESOLUTION_STATUS = ("open", "resolved", "abandoned")

#: 默认未知项登记处文件名（相对当前分析目录，跨会话复用）。
DEFAULT_REGISTRY_NAME = os.path.join(".re-perception", "unknown-registry.json")


class UnknownError(ValueError):
    """登记参数不合法。语义上对应退出码 2（用法错误）。"""


def _require_str(value, field, allow_empty=False):
    if not isinstance(value, str):
        raise UnknownError("%s 必须是字符串，实际是 %s" % (field, type(value).__name__))
    if not allow_empty and not value.strip():
        raise UnknownError("%s 不允许为空" % field)


def _check_id_list(values, field):
    if values is None:
        return []
    if not isinstance(values, list):
        raise UnknownError("%s 必须是数组" % field)
    out = []
    for i, item in enumerate(values):
        _require_str(item, "%s[%d]" % (field, i))
        out.append(item)
    return out


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def compute_unknown_id(record):
    """按问题内容算 ID。**同一个问题重复登记会得到同一个 ID**，从而在登记处
    天然去重 —— 不需要人记得「这个问过了没」。"""
    payload = {
        "question": record["question"],
        "required_authority": record["required_authority"],
        "required_confidence": record["required_confidence"],
    }
    return "uk-" + canonical_digest(payload)[:32]


def make_unknown(question, required_authority, required_confidence,
                 blocked_by, supporting_evidence_ids=None,
                 contradicting_evidence_ids=None, resolution=None,
                 owner=None):
    """构造一条未知项记录（未写盘）。`blocked_by` 是位置参数而非关键字参数 ——
    刻意的：「为什么不知道」不该被省略；想省略就说明你还没查清楚。
    """
    _require_str(question, "question")
    _require_str(blocked_by, "blocked_by")
    if required_authority not in AUTHORITY_LEVELS:
        raise UnknownError("required_authority=%r 不在 %s"
                           % (required_authority, list(AUTHORITY_LEVELS)))
    if required_confidence not in CONFIDENCE_LEVELS:
        raise UnknownError("required_confidence=%r 不在 %s"
                           % (required_confidence, list(CONFIDENCE_LEVELS)))
    rec = {
        "unknown_id": "",
        "question": question,
        "required_authority": required_authority,
        "required_confidence": required_confidence,
        "blocked_by": blocked_by,
        "supporting_evidence_ids": _check_id_list(
            supporting_evidence_ids, "supporting_evidence_ids"),
        "contradicting_evidence_ids": _check_id_list(
            contradicting_evidence_ids, "contradicting_evidence_ids"),
        "status": "open",
        "resolution": resolution,
        "owner": owner,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    rec["unknown_id"] = compute_unknown_id(rec)
    return rec


class UnknownRegistry:
    """未知项登记处。可落盘（跨会话大项目），也可只在内存（测试/一次性脚本）。

    登记处损坏不该让调用方崩 —— 从空开始，损坏的文件留着供人排查。
    """

    def __init__(self, path=None):
        self.path = path
        self._items = {}
        self.load_error = None
        if path and os.path.exists(path):
            self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for rec in data.get("unknowns", []):
                if isinstance(rec, dict) and rec.get("unknown_id"):
                    self._items[rec["unknown_id"]] = rec
        except Exception as ex:  # noqa: BLE001 —— 损坏登记处不崩，但要留痕
            self.load_error = "登记处读取失败（从空开始）: %s" % ex

    def save(self):
        if not self.path:
            return
        d = os.path.dirname(os.path.abspath(self.path))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, self.path)

    def to_dict(self):
        return {
            "version": 1,
            "updated_at": _now_iso(),
            "unknowns": [self._items[k] for k in sorted(self._items)],
        }

    def record(self, question, required_authority, required_confidence,
               blocked_by, **kwargs):
        """登记一条未知项。重复登记同一问题 → 幂等返回已有条目。"""
        rec = make_unknown(question, required_authority, required_confidence,
                           blocked_by, **kwargs)
        existing = self._items.get(rec["unknown_id"])
        if existing is not None:
            return existing, False        # False = 未新增
        self._items[rec["unknown_id"]] = rec
        return rec, True

    def update(self, unknown_id, status=None, resolution=None):
        """更新未知项状态。找不到 → KeyError（调用方决定当失败还是用法错）。"""
        rec = self._items.get(unknown_id)
        if rec is None:
            raise KeyError("未知项不存在: %s" % unknown_id)
        if status is not None:
            if status not in RESOLUTION_STATUS:
                raise UnknownError("status=%r 不在 %s" % (status, list(RESOLUTION_STATUS)))
            rec["status"] = status
        if resolution is not None:
            rec["resolution"] = resolution
        rec["updated_at"] = _now_iso()
        self._items[unknown_id] = rec
        return rec

    def get(self, unknown_id):
        return self._items.get(unknown_id)

    def list(self, status=None):
        out = [self._items[k] for k in sorted(self._items)]
        if status:
            out = [r for r in out if r.get("status") == status]
        return out

    def __len__(self):
        return len(self._items)


def unknown_mutation_evidence(mutation_operation, payload):
    """把「登记/更新未知项」这个动作本身包装成证据。

    两条硬约束：confidence 固定 `inferred`、authority 固定 `analyst-inference`，
    且 limitations 必须点明「记录的是意图，不是答案的证明」。
    **登记动作绝不冒充观测** —— 这是整套未知项机制的地基。
    """
    provider = {
        "id": "re-perception-unknown-registry",
        "name": "re-perception residual unknown registry",
        "version": "1",
    }
    return create_evidence(
        provider=provider,
        predicate_type="re-perception.residual-unknown-mutation",
        operation=mutation_operation,
        parameters=dict(payload),
        normalized_result={
            "action": mutation_operation,
            "question": payload.get("question"),
            "required_authority": payload.get("required_authority"),
            "required_confidence": payload.get("required_confidence"),
        },
        confidence="inferred",
        authority="analyst-inference",
        limitations=[
            "Registry mutation evidence records analyst intent, "
            "not proof of the answer."
        ],
        evidence_links=_dedup_links(payload),
    )


def _dedup_links(payload):
    """合并并去重支撑/反证/解决证据 ID。"""
    merged = []
    for key in ("supporting_evidence_ids", "contradicting_evidence_ids"):
        merged.extend(payload.get(key) or [])
    res = payload.get("resolution")
    if isinstance(res, dict):
        merged.extend(res.get("evidence_ids") or [])
    seen, out = set(), []
    for x in merged:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def route_unknown(rec):
    """给一条未知项出路由建议 —— **「不知道」不再是终点，而是带路由信号的待办**。

    建议只做判定，不执行。需要什么证据类型（required_authority）就路由到能产出
    那类证据的 re-perception 命令。
    """
    q = (rec.get("question") or "").lower()
    need = rec.get("required_authority")
    blocked = (rec.get("blocked_by") or "").lower()

    if rec.get("status") == "resolved":
        return {"action": "none", "reason": "已解决", "tool": None}

    if need == "shipped-artifact":
        return {"action": "static-analysis", "reason": "需要目标产物证据",
                "tool": "re.py identify/info（静态解析）"}

    if need == "controlled-replay":
        return {"action": "replay", "reason": "需要受控复现",
                "tool": "re.py sim/diff（重放比对）或动态 Hook"}

    if need == "external-service":
        return {"action": "probe-or-lookup", "reason": "需要外部服务证据",
                "tool": "re.py doctor（探测外部工具链）"}

    if need == "historical-reference":
        return {"action": "retrieve", "reason": "需要检索历史参考",
                "tool": "references/（方法论与工具链文档）"}

    if "权限" in blocked or "permission" in blocked or "authoriz" in blocked:
        return {"action": "escalate-human",
                "reason": "被权限阻塞，机器无法自行获取授权", "tool": None}

    if any(k in q for k in ("算", "多少", "总价", "税", "汇率", "sum", "total", "price")):
        return {"action": "deterministic-engine",
                "reason": "疑似数值结论，须走确定性引擎", "tool": "python3 / SymPy"}

    return {"action": "isolated-verify",
            "reason": "默认走隔离验证，不带入初稿", "tool": "隔离环境复算"}


def summarize_unknowns(registry):
    """登记处概览，供 report 输出与人工扫一眼。"""
    items = registry.list()
    by_status = {}
    by_need = {}
    for r in items:
        s = r.get("status", "open")
        by_status[s] = by_status.get(s, 0) + 1
        need = r.get("required_authority")
        by_need[need] = by_need.get(need, 0) + 1
    return {
        "total": len(items),
        "by_status": by_status,
        "by_required_authority": by_need,
        "open": len([r for r in items if r.get("status") == "open"]),
    }


# ==========================================================================
# 第三段 · 证据提供者（provider）注册与探测
# ==========================================================================

#: provider 可用性状态。
AVAILABILITY = ("ready", "missing", "degraded", "unknown")


class Provider:
    """一个证据提供者的注册信息。

    re-perception 里 provider 就是各分析引擎（识别/字符串/反汇编/符号/能力规则……），
    每个都能产出某类可溯源证据。`executables` 是外部可执行依赖（本工具箱的内置引擎
    通常为空 = 纯 Python）；`check` 是可选的自定义探测函数。
    """

    __slots__ = ("id", "name", "version", "authority", "operations",
                 "executables", "probe_args", "env_hint", "_check")

    def __init__(self, id, name, version, authority, operations,
                 executables=None, probe_args=None, env_hint=None, check=None):
        self.id = id
        self.name = name
        self.version = version
        self.authority = authority
        self.operations = list(operations or [])
        self.executables = list(executables or [])
        self.probe_args = list(probe_args or ["--help"])
        self.env_hint = env_hint
        self._check = check

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "version": self.version,
            "authority": self.authority, "operations": list(self.operations),
            "executables": list(self.executables), "env_hint": self.env_hint,
        }


class ProviderRegistry:
    """provider 注册表。支持静态登记 + 运行时探测。"""

    def __init__(self):
        self._providers = {}

    def register(self, provider):
        if not isinstance(provider, Provider):
            raise TypeError("只能注册 Provider 实例")
        if provider.authority not in AUTHORITY_LEVELS:
            raise ValueError("authority=%r 不在 %s"
                             % (provider.authority, list(AUTHORITY_LEVELS)))
        self._providers[provider.id] = provider
        return provider

    def get(self, pid):
        return self._providers.get(pid)

    def all(self):
        return [self._providers[k] for k in sorted(self._providers)]

    def by_operation(self, operation):
        return [p for p in self.all() if operation in p.operations]

    def __len__(self):
        return len(self._providers)


def _probe_executable(name):
    """探测可执行文件。返回 (路径或 None, None)。"""
    try:
        path = shutil.which(name)
    except Exception:  # noqa: BLE001 —— which 失败就当没找到，不崩
        return None, None
    return path, None


def _probe_version(exe, args=("--version",), timeout=5):
    """试着跑一次拿版本号。拿不到就返回 None（不抛）。"""
    try:
        r = subprocess.run([exe] + list(args), capture_output=True, text=True,
                           timeout=timeout, shell=False)
        if r.returncode == 0 and r.stdout:
            return r.stdout.strip().splitlines()[0][:120]
    except Exception:  # noqa: BLE001 —— 探测失败即「拿不到版本」，不是错误
        return None
    return None


def probe(provider, timeout=5):
    """实测一个 provider 的可用性。状态语义（工具失败 ≠ 通过）：

      ready     找到可执行文件且探测跑通（或纯内置实现）
      degraded  找到了但探测异常（可能能用，但别当 ready）
      missing   没找到可执行文件
      unknown   探测本身出错（不该发生，真发生了也要如实记）

    **任何异常都不会让 probe 崩** —— 探测器崩溃比探测器说「不知道」危害大得多。
    """
    out = {
        "provider_id": provider.id, "name": provider.name,
        "availability": "unknown", "executables_found": {}, "detail": "",
    }
    try:
        if provider._check is not None:
            ok, detail = provider._check()
            out["availability"] = "ready" if ok else "missing"
            out["detail"] = detail or ""
            return out

        if not provider.executables:
            out["availability"] = "ready"
            out["detail"] = "内置实现，无外部可执行依赖"
            return out

        found_any = False
        for name in provider.executables:
            path, _ = _probe_executable(name)
            if path:
                found_any = True
                ver = _probe_version(path, provider.probe_args, timeout=timeout)
                out["executables_found"][name] = {"path": path, "version": ver}
            else:
                out["executables_found"][name] = None

        if not found_any:
            out["availability"] = "missing"
            out["detail"] = "未找到任何所需可执行文件: %s" % provider.executables
        else:
            missing = [k for k, v in out["executables_found"].items() if v is None]
            if missing:
                out["availability"] = "degraded"
                out["detail"] = "部分可执行文件缺失: %s" % missing
            else:
                out["availability"] = "ready"
                out["detail"] = "全部可执行文件就绪"

        if provider.env_hint and out["availability"] != "ready":
            out["detail"] += "；提示: " + provider.env_hint

    except Exception as ex:  # noqa: BLE001 —— 探测异常也要如实记，不崩
        out["availability"] = "unknown"
        out["detail"] = "探测异常: %s" % ex

    return out


def probe_all(registry, timeout=5):
    """探测注册表里所有 provider。**绝不因单个 provider 崩掉而中断。**"""
    return [probe(p, timeout=timeout) for p in registry.all()]


def build_default_registry():
    """登记 re-perception 自带的证据提供者（各分析引擎）。

    这些都是**内置 Python 实现**，没有外部可执行依赖 —— 探测结果恒为 ready。
    这正是本工具箱「零第三方依赖」定位在调用框架里的体现。外部逆向工具
    （Ghidra/IDA/Frida 等）通过 `re.py doctor` 单独探测，不混进这张内置表。
    """
    reg = ProviderRegistry()
    reg.register(Provider(
        id="identify", name="re-perception 格式识别", version="1",
        authority="shipped-artifact",
        operations=["identify", "parse_structure", "magic", "info"]))
    reg.register(Provider(
        id="analyze", name="re-perception 字符串/熵/雕刻/差分", version="1",
        authority="shipped-artifact",
        operations=["strings", "entropy", "carve", "diff", "ioc"]))
    reg.register(Provider(
        id="disasm", name="re-perception 反汇编", version="1",
        authority="shipped-artifact",
        operations=["disasm"]))
    reg.register(Provider(
        id="code", name="re-perception 函数/CFG/XREF", version="1",
        authority="shipped-artifact",
        operations=["funcs", "cfg", "xref", "sim"]))
    reg.register(Provider(
        id="semantics", name="re-perception 函数语义画像", version="1",
        authority="shipped-artifact",
        operations=["semantics"]))
    reg.register(Provider(
        id="symbols", name="re-perception 符号还原", version="1",
        authority="shipped-artifact",
        operations=["symbols", "demangle", "names"]))
    reg.register(Provider(
        id="obfstr", name="re-perception 混淆串恢复", version="1",
        authority="shipped-artifact",
        operations=["obfstr"]))
    reg.register(Provider(
        id="capability", name="re-perception 能力规则引擎", version="1",
        authority="shipped-artifact",
        operations=["capability"]))
    reg.register(Provider(
        id="tool-probe", name="re-perception 工具链探测", version="1",
        authority="external-service",
        operations=["doctor", "plan"],
        env_hint="外部逆向工具缺失时相关结论记 unverified（≠ 通过）"))
    reg.register(Provider(
        id="unknown-registry", name="re-perception residual unknown registry",
        version="1", authority="analyst-inference",
        operations=["record_unknown", "update_unknown"]))
    return reg


def __brief__():
    return {
        "module": "lib_evidence",
        "confidence_levels": list(CONFIDENCE_LEVELS),
        "authority_levels": list(AUTHORITY_LEVELS),
        "location_kinds": list(LOCATION_KINDS),
        "availability": list(AVAILABILITY),
        "resolution_status": list(RESOLUTION_STATUS),
    }
