"""契约层 —— 复刻 REA 的「平台契约」骨架（纯标准库）。

这一层不是分析逻辑，而是把一次逆向调查里**跨命令通用的语义约定**固化下来，
让所有子命令共享同一套口径（这正是 REA 把 evidence/error/provider/subject 做成
一等公民的原因）：

- **错误契约** ``error_contract``：结构化错误 ``{code,category,message,retryable,
  remediation,details}``，10 个类别闭集，调用方能据 ``category``/``retryable``
  决定重试还是报障，而不是解析人类字符串。
- **Provider 抽象**：确定性选择（request > env > auto-single）、绑定不可变、
  **失败绝不自动换引擎**、12 个拒绝码、启动 deadline 分层、探测。
  复刻的是 REA「诚实 provider 抽象」原则 —— 依赖重型外部工具的域（Ghidra/IDA/
  adb/浏览器/LLDB）在这里以 provider 槽位表达，未配置就如实降级，绝不假装成功。
- **subject format 枚举**：证据要描述的「被分析对象」格式闭集。
- **relationship_coverage**：关系覆盖度（complete/partial/unknown）——
  落实 REA「缺失覆盖 ≠ 不存在」：空调用列表 + partial 不能证明「无调用」。
- **规范分析阶段** ``DISPATCH_STAGES``：REA 的 9 阶段 fail-closed 流程基准。

设计约束：纯标准库、无静默吞异常（异常要么抛出、要么显式记录）、退出码语义与
re.py 对齐（0/2/3/4）。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

__all__ = [
    "ERROR_CATEGORIES", "error_contract", "make_error",
    "SUBJECT_FORMATS", "subject",
    "RELATIONSHIP_COVERAGE_STATUS", "relationship_coverage", "assert_not_absent",
    "DISPATCH_STAGES", "stage_index", "check_stage_closure",
    "REJECTION_CODES", "PROVIDER_SELECTION_SOURCES", "ProviderDescriptor",
    "select_provider", "probe_provider", "provider_status",
    "DEADLINE_LAYERS",
]

# ---------------------------------------------------------------- 错误契约

#: 错误类别闭集（复刻 REA error contract 的 10 个 category）。
ERROR_CATEGORIES = (
    "invalid_input",           # 入参不合法
    "unsupported_provider",    # provider 不支持/拒绝
    "unsupported_target",      # 目标类型/格式不支持
    "integrity_mismatch",      # 声明与实测完整性不一致
    "truncated",               # 结果被截断
    "cancelled",               # 被取消
    "timeout",                 # 超时
    "resource_constraint",     # 资源受限（内存/传输/磁盘）
    "unavailable",             # 依赖能力当前不可用
    "execution_failure",       # 执行失败
)


def error_contract(code, category, message, retryable, remediation, details=None):
    """构造一条结构化错误。

    ``code`` 是稳定的机器可读标识（如 ``provider_unavailable``、
    ``revision_conflict``），``category`` 必须落在 ``ERROR_CATEGORIES`` 闭集里，
    ``remediation`` 是 ``{"action": "..."}`` 形式的可执行建议。校验失败直接抛
    ``ValueError`` —— 错误对象本身不合法属于编程错误，不该静默。
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("error code 必须是非空字符串")
    if category not in ERROR_CATEGORIES:
        raise ValueError("category=%r 不在 %s" % (category, list(ERROR_CATEGORIES)))
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message 必须是非空字符串")
    if not isinstance(retryable, bool):
        raise ValueError("retryable 必须是布尔值")
    if not isinstance(remediation, dict) or not remediation.get("action"):
        raise ValueError("remediation 必须是含 action 的对象")
    return {
        "code": code,
        "category": category,
        "message": message,
        "retryable": retryable,
        "remediation": {"action": remediation["action"]},
        "details": dict(details) if details else {},
    }


def make_error(code, category, message, remediation_action, retryable=False,
               details=None):
    """``error_contract`` 的便捷包装（remediation 只给 action 字符串）。"""
    return error_contract(code, category, message, retryable,
                          {"action": remediation_action}, details)


# ---------------------------------------------------------------- subject（被分析对象）

#: 被分析对象的格式闭集（复刻 REA subject.format 枚举）。
SUBJECT_FORMATS = (
    "mach-o", "mach-o-universal", "elf", "pe", "dos-mz", "dos-com", "raw-binary",
    "zip", "ipa", "apk", "msix", "appx", "hap", "hsp", "app-pack", "asar",
    "dmg", "pkg", "plist", "javascript", "source-map", "directory", "file",
    "javascript-bundle", "entitlements", "dex", "wasm", "go-binary",
    "managed-assembly", "evm-bytecode",
)


def subject(name, sha256, fmt, architecture=None, local_path=None):
    """构造证据的 ``subject`` 块。``fmt`` 必须落在 ``SUBJECT_FORMATS`` 闭集。"""
    if fmt not in SUBJECT_FORMATS:
        raise ValueError("subject.format=%r 不在 %s" % (fmt, list(SUBJECT_FORMATS)))
    if not isinstance(sha256, str) or not sha256.strip():
        raise ValueError("subject.sha256 必须是非空字符串")
    return {
        "name": name,
        "digest": {"sha256": sha256},
        "format": fmt,
        "architecture": architecture,
        "local_path": local_path,
    }


# ---------------------------------------------------------------- relationship_coverage

#: 关系覆盖度三态。
RELATIONSHIP_COVERAGE_STATUS = ("complete", "partial", "unknown")


def relationship_coverage(status, limitations=None, diagnostics=None):
    """关系覆盖度块。用于落实「缺失覆盖 ≠ 不存在」。"""
    if status not in RELATIONSHIP_COVERAGE_STATUS:
        raise ValueError("status=%r 不在 %s"
                         % (status, list(RELATIONSHIP_COVERAGE_STATUS)))
    return {
        "status": status,
        "limitations": list(limitations) if limitations else [],
        "diagnostics": list(diagnostics) if diagnostics else [],
    }


def assert_not_absent(items, coverage, claim="该关系不存在"):
    """守卫「缺失覆盖 ≠ 不存在」。

    当 ``items`` 为空时，只有 ``coverage.status == "complete"`` 才允许断言
    「不存在」；partial/unknown 必须抛出，防止把「没查到」当成「没有」。
    """
    if items:
        return items
    status = (coverage or {}).get("status", "unknown")
    if status == "complete":
        return []
    raise ValueError("%s：覆盖度为 %s，不能据此断言%s（缺失覆盖 ≠ 不存在）"
                     % (claim, status, claim))


# ---------------------------------------------------------------- 规范分析阶段

#: REA 规范分析阶段（fail-closed：每阶段恰好执行一次并链接证据）。
DISPATCH_STAGES = (
    "discover-classify",            # 发现并分类目标
    "diagnose-environment",         # 诊断分析环境/provider 就绪
    "declare-request",              # 声明本次请求的范围与目标身份
    "static-analysis",              # 静态分析
    "reactive-scenarios",           # 反应式场景/运行时观测
    "compare-authority-candidate",  # 与权威候选对比
    "preserve-contradictions",      # 保留矛盾证据
    "verify-reconstruction-closure",  # 校验重构闭合
    "export-replay",                # 导出可重放结果
)


def stage_index(stage):
    if stage not in DISPATCH_STAGES:
        raise ValueError("未知阶段 %r" % (stage,))
    return DISPATCH_STAGES.index(stage)


def check_stage_closure(stage_results):
    """校验阶段闭合（fail-closed）。

    ``stage_results`` 是 ``{stage: status}``，``status ∈
    {pass, fail, unknown, unsupported, truncated, skipped}``。规则：任何非
    ``pass`` 状态**不得被聚合为 pass** —— 只有全部 pass 才整体 pass；否则返回
    ``{"closed": False, "reason": ...}``。绝不把 fail/unknown/skipped 混成成功。
    """
    ok_status = ("pass",)
    problems = []
    for st in DISPATCH_STAGES:
        got = stage_results.get(st)
        if got is None:
            problems.append("%s: 未执行" % st)
        elif got not in ok_status:
            problems.append("%s: %s" % (st, got))
    return {"closed": not problems, "reason": "; ".join(problems)}


# ---------------------------------------------------------------- Provider 抽象

#: provider 拒绝码闭集（复刻 REA 的 12 个拒绝原因）。
REJECTION_CODES = (
    "not_configured",
    "executable_missing",
    "runtime_missing",
    "unsupported_host",
    "unsupported_version",
    "target_kind_unsupported",
    "target_format_unsupported",
    "architecture_unsupported",
    "target_role_unsupported",
    "managed_target_unsupported",
    "open_options_invalid",
    "version_unresolved",
)

#: provider 选择来源。
PROVIDER_SELECTION_SOURCES = ("request", "environment", "auto-single-candidate")

#: 启动 deadline 分层（秒）—— 连接 ≠ provider 启动。
DEADLINE_LAYERS = {
    "connect": 60,
    "provider_startup": {
        "ghidra": 330,
        "hopper": 120,
        "ida": 60,
        "jeb": 60,
        "default": 60,
    },
}


class ProviderDescriptor:
    """provider 描述符（只读属性 + 不可变绑定语义）。

    绑定后 ``bound_profile`` 不可变 —— 复刻 REA「成功深绑定后不可变」的确定性
    原则：一旦绑定，运行期失败**不换引擎**、不重选 provider。
    """

    __slots__ = ("provider_id", "kind", "requires", "_bound_profile", "_bound_at")

    def __init__(self, provider_id, kind, requires=()):
        self.provider_id = provider_id
        self.kind = kind
        self.requires = tuple(requires)
        self._bound_profile = None
        self._bound_at = None

    @property
    def bound(self):
        return self._bound_profile is not None

    @property
    def bound_profile(self):
        return self._bound_profile

    def bind(self, profile):
        """深绑定一个 analysis profile；重复绑定抛 ``RuntimeError``。"""
        if self._bound_profile is not None:
            raise RuntimeError("provider %s 已绑定，绑定不可变"
                               % self.provider_id)
        self._bound_profile = dict(profile) if profile else {}
        self._bound_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return self._bound_profile

    def to_dict(self):
        return {
            "provider_id": self.provider_id,
            "kind": self.kind,
            "requires": list(self.requires),
            "bound": self.bound,
            "bound_profile": self._bound_profile,
            "bound_at": self._bound_at,
        }


def _probe_executable(name):
    """返回 (ok, resolved_path)。找不到返回 (False, None)，不抛。"""
    try:
        path = shutil.which(name)
    except Exception:  # noqa: BLE001 —— 探测失败按「缺失」处理，但不静默崩
        return False, None
    return (path is not None), path


def _probe_version(exe, args=("--version",), timeout=5):
    """执行 ``exe args`` 取版本串；失败返回 None（不抛）。"""
    try:
        proc = subprocess.run([exe, *args], capture_output=True,
                              text=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or proc.stderr or "").strip()
    return out.splitlines()[0] if out else None


def probe_provider(descriptor, extra_env=None):
    """探测一个 provider 的就绪度（复刻 REA probe）。

    返回 ``{provider_id, state, detail}``，``state ∈
    {ready, missing, degraded, unknown}``。**探测永不抛** —— provider 未配置是
    常态（诚实降级），不该让整次分析崩掉。
    """
    pid = descriptor.provider_id
    result = {"provider_id": pid, "state": "unknown", "detail": {}}
    missing = []
    resolved = {}
    for req in descriptor.requires:
        ok, path = _probe_executable(req)
        resolved[req] = path
        if not ok:
            missing.append(req)
    result["detail"]["resolved"] = resolved
    if missing:
        result["state"] = "missing"
        result["detail"]["missing"] = missing
        result["detail"]["rejection_code"] = "executable_missing"
        return result
    # 都找到了 → 试着取版本（版本取不到算 degraded，不算失败）
    versions = {}
    degraded = False
    for req in descriptor.requires:
        ver = _probe_version(resolved[req])
        versions[req] = ver
        if ver is None:
            degraded = True
    result["detail"]["versions"] = versions
    result["state"] = "degraded" if degraded else "ready"
    return result


def select_provider(candidates, requested=None, env_provider=None,
                    env_var="REA_ANALYSIS_PROVIDER"):
    """确定性选择 provider（复刻 REA 选择协议）。

    优先级：``requested``（request） > ``env_provider``/环境变量（environment）
    > 唯一候选（auto-single-candidate）。歧义（多候选且无显式指定）返回
    ``{"error": "ambiguous", "candidate_ids": [...]}``；指定但不存在返回
    ``{"error": "provider_unavailable"}``。**绝不静默降级到别的引擎**。
    """
    ids = [c.provider_id if isinstance(c, ProviderDescriptor) else c
           for c in candidates]
    ids = sorted(set(ids))
    if env_provider is None and env_var:
        env_provider = os.environ.get(env_var) or None

    if requested:
        if requested == "auto":
            pass  # 落到 auto-single 逻辑
        elif requested in ids:
            return {"provider_id": requested,
                    "selection_source": "request", "candidates": ids}
        else:
            return {"error": "provider_unavailable",
                    "details": {"requested": requested, "candidates": ids}}
    if requested != "auto" and env_provider:
        if env_provider in ids:
            return {"provider_id": env_provider,
                    "selection_source": "environment", "candidates": ids}
        return {"error": "provider_unavailable",
                "details": {"requested": env_provider, "candidates": ids}}

    # auto：仅当唯一候选时自动选定，否则歧义
    if len(ids) == 1:
        return {"provider_id": ids[0],
                "selection_source": "auto-single-candidate", "candidates": ids}
    if not ids:
        return {"error": "provider_unavailable",
                "details": {"reason": "not_configured", "candidates": []}}
    return {"error": "ambiguous", "details": {"candidate_ids": ids}}


def provider_status(candidates, requested=None, env_provider=None):
    """一次给出「选择 + 各候选探测」的就绪总览（对应 REA ``providers``）。"""
    sel = select_provider(candidates, requested, env_provider)
    probes = [probe_provider(c if isinstance(c, ProviderDescriptor)
                             else ProviderDescriptor(c, "unknown"))
              for c in candidates]
    return {"selection": sel, "probes": probes}
