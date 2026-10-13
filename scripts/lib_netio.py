"""网络与接口面提取 —— 应用内接口 / 端口接口 / 连接网络地址（纯标准库）。

三个入口对齐「逆向接口功能」的三类：
- ``extract_endpoints`` 应用内接口：URL API 路径、content:// URI、Intent action、
  命名管道、COM ProgID、.NET/Java 类型名、gRPC 服务、SOAP/WS 端点。
- ``extract_ports``    端口接口：URL 显式端口、``host:port`` / ``port=NNN`` 常量、
  协议默认端口（按协议字符串配对，confidence=derived 不冒充观测）。
- ``extract_netaddrs`` 连接网络地址：URL / IPv4 / IPv6 / 域名 / 邮箱 / UNC 主机。

假阳性防护（反向用例进 selftest）：
- IPv4 严格 0-255 分段，并排除版本号样式（前后是 ``digit.`` 续段的不收）；
  按 scope 标注（loopback/private/link-local/multicast/public）。
- 域名要求：≥2 标签、末段在常见 TLD 表内或上下文带 scheme、标签不以连字符开头/结尾。
- 端口只信显式出现（1-65535），协议默认端口单独分组、confidence=derived。
- 所有结果带 source（offset/字符串）与 confidence（observed/derived），
  可直接喂给证据契约层（lib_evidence）。
"""

from __future__ import annotations

import re

from lib_analyze import scan_strings

__all__ = ["extract_endpoints", "extract_ports", "extract_netaddrs"]


# ---------------------------------------------------------------- 正则


_RX_URL = re.compile(
    r"\b(?:https?|ftps?|wss?|tcp|udp|smb|ldap|ldaps|irc|git|ssh|telnet|mqtt|amqp|"
    r"redis|postgres|mysql|jdbc|socks5?|rdp|vnc)://"
    r"[^\s\"'<>\\)\]},;]{4,300}", re.I)

_RX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}"
                       r"(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b")

# IPv4：严格分段。后面跟版本续段（.数字）的排除。
_RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_RX_VER_TAIL = re.compile(r"\.\d")   # 紧跟 .数字 → 版本号样式

_RX_IPV6 = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|"
    r"\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b|"
    r"\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b")

_RX_UNC = re.compile(r"\\\\([A-Za-z0-9._-]{1,63})\\([A-Za-z0-9 $._-]{1,64})")

# 命名管道 \\.\pipe\name —— 字面量用 re.escape，别手写反斜杠层数
# （手写 r"\\\\\\." 曾把 \. 拆成裸 .，正则永不命中——实测漏报过）
_RX_PIPE = re.compile(re.escape("\\\\.\\pipe\\") + r"([A-Za-z0-9 _.$-]{1,128})", re.I)

_RX_CONTENT_URI = re.compile(r"content://[A-Za-z0-9._/-]{2,120}")

_RX_INTENT = re.compile(r"\b(?:android|com|org|net|io)\.[a-z0-9_.]*\.action\.[A-Z0-9_.]{2,60}")

# gRPC 全方法名：package(.sub)*.Service/Method —— 包名段可为 0（两段式也合法）；
# Service/Method 段 1 字符起（Do/Get 这类短方法名是真实存在的）
_RX_GRPC = re.compile(r"\b[a-z][a-z0-9_]{1,30}(?:\.[a-z][a-z0-9_]{1,30}){0,5}"
                      r"\.[A-Z][A-Za-z0-9_]{1,40}/[A-Za-z][A-Za-z0-9_]{1,40}\b")

_RX_DOTNET_TYPE = re.compile(r"\b[A-Z][A-Za-z0-9_]{1,40}(?:\.[A-Z][A-Za-z0-9_]{1,40}){1,6}"
                             r"::[A-Za-z_][A-Za-z0-9_]{1,60}\b")

_RX_JAVA_TYPE = re.compile(r"\b[a-z][a-z0-9_]{1,30}(?:\.[a-z][a-z0-9_]{1,30}){1,6}"
                           r"\.[A-Z][A-Za-z0-9_$]{2,60}\b")

# COM ProgID：2-3 段（Word.Application / Scripting.FileSystemObject 都是两段式）
_RX_PROGID = re.compile(r"\b[A-Za-z][A-Za-z0-9]{1,20}\.[A-Za-z][A-Za-z0-9]{1,20}"
                        r"(?:\.[A-Za-z][A-Za-z0-9]{1,20})?\b")

_RX_SOAP = re.compile(r"[\w./-]{1,80}\.(?:asmx|svc|wsdl|soap)\b", re.I)

# URL 路径型 API（/api/v1/users、/v2/xxx、/graphql）
_RX_API_PATH = re.compile(r"(?<![\w/])(?:/api)?/v\d{1,2}/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{2,80}"
                          r"|/graphql\b|/swagger[\w./-]{0,40}|/openapi[\w./-]{0,40}", re.I)

# 端口线索
_RX_HOSTPORT = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                          r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d):(\d{1,5})\b")
_RX_PORT_EQ = re.compile(r"\bport[=_\s]?(\d{2,5})\b", re.I)
_RX_COLON_PORT = re.compile(r":(\d{2,5})\b")
_RX_URL_PORT = re.compile(r"://[^/\s\"']+:(\d{1,5})\b")

# 协议 → 默认端口（confidence=derived，只作"协议字符串出现→端口配对"线索）
_PROTO_PORTS = [
    (re.compile(r"\bhttps?\b|winhttp|wininet", re.I), [80, 443], "http/https"),
    (re.compile(r"\bftp\b", re.I), [21], "ftp"),
    (re.compile(r"\bssh\b", re.I), [22], "ssh"),
    (re.compile(r"\btelnet\b", re.I), [23], "telnet"),
    (re.compile(r"\bsmtp\b", re.I), [25], "smtp"),
    (re.compile(r"\bdns\b|resolvehostname|getaddrinfo", re.I), [53], "dns"),
    (re.compile(r"\bdhcp\b", re.I), [67, 68], "dhcp"),
    (re.compile(r"\bimap\b", re.I), [143, 993], "imap"),
    (re.compile(r"\bpop3?\b", re.I), [110, 995], "pop3"),
    (re.compile(r"\bldap\b", re.I), [389, 636], "ldap"),
    (re.compile(r"\bsmb\b|netbios", re.I), [445, 139], "smb"),
    (re.compile(r"\brdp\b|terminalservices", re.I), [3389], "rdp"),
    (re.compile(r"\bvnc\b", re.I), [5900], "vnc"),
    (re.compile(r"\bmysql\b", re.I), [3306], "mysql"),
    (re.compile(r"\bpostgres", re.I), [5432], "postgresql"),
    (re.compile(r"\bmongodb\b", re.I), [27017], "mongodb"),
    (re.compile(r"\bredis\b", re.I), [6379], "redis"),
    (re.compile(r"\bmqtt\b", re.I), [1883, 8883], "mqtt"),
    (re.compile(r"\bsmtps\b|submission", re.I), [465, 587], "smtps"),
    (re.compile(r"\bsocks5?\b", re.I), [1080], "socks"),
    (re.compile(r"\brdp\b|rdpwrap", re.I), [3389], "rdp"),
]

# 常见 TLD（保守表：命中或带 scheme 上下文才算域名）
_TLDS = set("""
com net org edu gov mil int io co ai app dev cloud info biz me tv cc cn uk de fr jp
ru us ca au nl se no fi it es br in kr tw hk sg my th vn id mx ar cl za eu xyz top
online site store shop tech pro life work club group network systems software
security solutions services digital global tech ai ml llp ltd gmbh srl sa pty
onion local host space fun win bid date download stream trade science agency
company directory academy center engineering laboratory foundation institute
museum aero coop jobs mobi travel cat post tel asia geo name edu.cn gov.cn com.cn
net.cn org.cn ac.cn me.uk co.jp or.jp ne.jp ac.uk org.uk gov.uk co.kr com.br com.mx
com.au net.au org.au com.cn com.hk com.tw com.sg co.in org.in net.in
""".split())


# ---------------------------------------------------------------- 工具


def _ok(**kw):
    d = {"ok": True}
    d.update(kw)
    return d


def _bad(reason, **kw):
    d = {"ok": False, "reason": reason}
    d.update(kw)
    return d


def _scan(path, max_items=40000):
    return scan_strings(path, min_len=5, max_items=max_items,
                        budget_seconds=30.0, dedupe=True, categorize=False)


def _scope_ipv4(ip: str) -> str:
    o = [int(x) for x in ip.split(".")]
    if ip == "0.0.0.0":
        return "unspecified"
    if o[0] == 127:
        return "loopback"
    if o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or \
       (o[0] == 192 and o[1] == 168):
        return "private"
    if o[0] == 169 and o[1] == 254:
        return "link-local"
    if 224 <= o[0] <= 239:
        return "multicast"
    return "public"


def _looks_version_tail(s: str, m: re.Match) -> bool:
    """IP 后面紧跟 .数字 → 版本号样式（如 1.2.3.4.5），判假阳性。"""
    tail = s[m.end():m.end() + 2]
    return bool(_RX_VER_TAIL.match(tail)) if tail else False


def _looks_version_head(s: str, m: re.Match) -> bool:
    """IP 前面是 数字. → 更长版本串的尾段（如 9.1.2.3.4 的后四段）。"""
    head = s[max(0, m.start() - 2):m.start()]
    return bool(re.search(r"\d\.$", head))


# ---------------------------------------------------------------- 网络地址


def extract_netaddrs(path: str, max_items: int = 2000, max_str: int = 40000) -> dict:
    """提取连接网络地址（URL/IPv4/IPv6/域名/邮箱/UNC）。"""
    try:
        sc = _scan(path, max_items=max_str)
    except OSError as e:
        return _bad("读取失败: %s" % e)
    if not sc.get("items") and sc.get("count", 0) == 0 and not sc.get("ok", True):
        return _bad("字符串扫描失败")

    urls, ipv4, ipv6, domains, emails, unc = [], [], [], [], [], []
    seen = {k: set() for k in ("url", "ip4", "ip6", "dom", "mail", "unc")}

    def put(lst, key, val, **extra):
        if val in seen[key]:
            return
        seen[key].add(val)
        rec = {"value": val, "confidence": "observed"}
        rec.update(extra)
        lst.append(rec)

    for it in sc["items"]:
        s = it.get("value", "")
        if not s:
            continue
        for m in _RX_URL.finditer(s):
            u = m.group().rstrip(".,;:)")
            host = u.split("://", 1)[-1].split("/")[0].split("@")[-1].split(":")[0]
            put(urls, "url", u, offset=it.get("offset"), host=host or None)
        for m in _RX_EMAIL.finditer(s):
            put(emails, "mail", m.group(), offset=it.get("offset"))
        for m in _RX_IPV4.finditer(s):
            if _looks_version_tail(s, m) or _looks_version_head(s, m):
                continue
            ip = m.group()
            put(ipv4, "ip4", ip, scope=_scope_ipv4(ip), offset=it.get("offset"))
        for m in _RX_IPV6.finditer(s):
            v = m.group()
            if v.count(":") < 3 or v.endswith("::"):
                continue
            if re.fullmatch(r"(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}", v):
                put(ipv6, "ip6", v, offset=it.get("offset"))
        for m in _RX_UNC.finditer(s):
            put(unc, "unc", m.group(), host=m.group(1), offset=it.get("offset"))
        # 域名：从 URL 主机 + 独立 hostname 样式串
        for m in _RX_URL.finditer(s):
            u = m.group()
            host = u.split("://", 1)[-1].split("/")[0].split("@")[-1].split(":")[0]
            if host and "." in host and not _RX_IPV4.fullmatch(host):
                put(domains, "dom", host, source="url", offset=it.get("offset"))
        # 独立域名：xx.yy 样式且 yy 在 TLD 表（或串里带 scheme 佐证）
        for tok in re.findall(r"\b[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}\b", s):
            if _RX_IPV4.fullmatch(tok) or _RX_EMAIL.fullmatch(tok):
                continue
            tld = tok.rsplit(".", 1)[-1].lower()
            if tld not in _TLDS:
                continue
            if tok.startswith("-") or tok.endswith("-") or ".." in tok:
                continue
            if len(tok) > 253 or any(len(p) > 63 for p in tok.split(".")):
                continue
            put(domains, "dom", tok.lower(), source="string", offset=it.get("offset"))
        if len(urls) + len(ipv4) + len(domains) > max_items * 3:
            break

    return _ok(
        urls=urls[:max_items], ipv4=ipv4[:max_items], ipv6=ipv6[:max_items],
        domains=domains[:max_items], emails=emails[:max_items], unc=unc[:max_items],
        counts={"urls": len(urls), "ipv4": len(ipv4), "ipv6": len(ipv6),
                "domains": len(domains), "emails": len(emails), "unc": len(unc)},
        strings_scanned=sc.get("count"), scan_seconds=sc.get("scan_seconds"),
    )


# ---------------------------------------------------------------- 端口


def extract_ports(path: str, max_items: int = 1000, max_str: int = 40000) -> dict:
    """提取端口接口（显式端口高置信 + 协议默认端口派生置信）。"""
    try:
        sc = _scan(path, max_items=max_str)
    except OSError as e:
        return _bad("读取失败: %s" % e)

    explicit: dict[int, dict] = {}
    derived: dict[int, dict] = {}

    def note_port(bucket, port, source, proto=None):
        if not (1 <= port <= 65535):
            return
        rec = bucket.get(port)
        if rec is None:
            bucket[port] = {"port": port, "sources": [source],
                            "protocols": [proto] if proto else [],
                            "confidence": "observed" if bucket is explicit else "derived"}
        else:
            if source not in rec["sources"]:
                rec["sources"].append(source)
            if proto and proto not in rec["protocols"]:
                rec["protocols"].append(proto)

    text_all = []
    for it in sc["items"]:
        s = it.get("value", "")
        if not s:
            continue
        text_all.append(s)
        for m in _RX_URL_PORT.finditer(s):
            note_port(explicit, int(m.group(1)), "url")
        for m in _RX_HOSTPORT.finditer(s):
            note_port(explicit, int(m.group(1)), "host:port")
        for m in _RX_PORT_EQ.finditer(s):
            note_port(explicit, int(m.group(1)), "port-literal")

    blob = "\n".join(text_all[:20000])
    for rx, ports, proto in _PROTO_PORTS:
        if rx.search(blob):
            for p in ports:
                note_port(derived, p, "protocol-default", proto)

    ex = sorted(explicit.values(), key=lambda r: -len(r["sources"]))
    de = sorted(derived.values(), key=lambda r: r["port"])
    return _ok(explicit_ports=ex, derived_ports=de,
               counts={"explicit": len(ex), "derived": len(de)},
               note="derived 为协议字符串→默认端口的配对线索，不是观测到的监听端口",
               strings_scanned=sc.get("count"))


# ---------------------------------------------------------------- 应用内接口


def extract_endpoints(path: str, max_items: int = 1500, max_str: int = 40000) -> dict:
    """提取应用内接口面（API 路径/IPC/类型接口/Intent/COM/gRPC/SOAP）。"""
    try:
        sc = _scan(path, max_items=max_str)
    except OSError as e:
        return _bad("读取失败: %s" % e)

    buckets = {
        "api_paths": [], "content_uris": [], "intent_actions": [],
        "named_pipes": [], "com_progid": [], "dotnet_types": [],
        "java_types": [], "grpc_services": [], "soap_wsdl": [],
    }
    seen = {k: set() for k in buckets}

    def put(bucket, val, **extra):
        if val in seen[bucket]:
            return
        seen[bucket].add(val)
        rec = {"value": val, "confidence": "observed"}
        rec.update(extra)
        buckets[bucket].append(rec)

    for it in sc["items"]:
        s = it.get("value", "")
        if not s:
            continue
        off = it.get("offset")
        for m in _RX_URL.finditer(s):
            u = m.group().rstrip(".,;:)")
            # URL 自带路径也要进 api_paths：/v1/users 在 :8443 之后，
            # 裸路径正则的 lookbehind 会把它挡掉（实测漏报过）
            path = u.split("://", 1)[-1]
            path = "/" + path.split("/", 1)[1] if "/" in path else ""
            if path and re.match(r"^(/api)?/v\d{1,2}/|^/graphql|^/swagger|^/openapi",
                                 path, re.I):
                put("api_paths", path, source="url", offset=off)
        for m in _RX_API_PATH.finditer(s):
            put("api_paths", m.group(), offset=off)
        for m in _RX_CONTENT_URI.finditer(s):
            put("content_uris", m.group(), offset=off)
        for m in _RX_INTENT.finditer(s):
            put("intent_actions", m.group(), offset=off)
        for m in _RX_PIPE.finditer(s):
            put("named_pipes", m.group(), offset=off)
        for m in _RX_DOTNET_TYPE.finditer(s):
            put("dotnet_types", m.group(), offset=off)
        for m in _RX_GRPC.finditer(s):
            put("grpc_services", m.group(), offset=off)
        for m in _RX_SOAP.finditer(s):
            put("soap_wsdl", m.group(), offset=off)
        for m in _RX_JAVA_TYPE.finditer(s):
            v = m.group()
            # Java 类型名的误报面大：要求包名 ≥2 段且末段首字母大写、无常见英文句式
            if v.lower().startswith(("www.", "http", "file.", "this.", "that.")):
                continue
            put("java_types", v, offset=off)
        for m in _RX_PROGID.finditer(s):
            v = m.group()
            # COM ProgID：首段首字母大写（Word.Application / System.Net.Sockets）；
            # 小写开头的三段式（svc1.Svc.svc）不当 ProgID。仍是 inferred 级启发式。
            parts = v.split(".")
            if parts[0][:1].isupper() and all(p.isalnum() for p in parts):
                put("com_progid", v, confidence="inferred", offset=off)
        if sum(len(v) for v in buckets.values()) > max_items * 6:
            break

    return _ok(**{k: v[:max_items] for k, v in buckets.items()},
               counts={k: len(v) for k, v in buckets.items()},
               strings_scanned=sc.get("count"),
               note="com_progid 为 inferred（三段式命名启发式）；其余为 observed 字符串证据")
