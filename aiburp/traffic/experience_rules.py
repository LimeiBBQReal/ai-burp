"""
EXPERIENCE_LESSONS 流量规则引擎 — V4 ALL-IN-TRAFFIC.

把 prompts.py 里的 22 条经验规则从"静态文本"提升为"流量分析规则".

每条规则是一个 (predicate, severity, finding_type) 三元组:
  - predicate(req_or_resp) -> bool
  - severity: critical / high / medium / low
  - finding_type: short tag

调用方: TrafficEngine / MultiChannelAnalyzer 在每次请求-响应后 apply_rules().
"""
from __future__ import annotations
import re
from typing import Callable, List, Tuple, Dict, Any
from dataclasses import dataclass, field


@dataclass
class TrafficRule:
    rule_id: str
    description: str
    severity: str          # critical / high / medium / low
    finding_type: str      # 短标签, 如 cve_marker / debug_enabled / weak_csp
    layer: str             # http / tls / app / api
    predicate: Callable[[Dict[str, Any]], bool] = field(repr=False)

    def match(self, context: Dict[str, Any]) -> bool:
        try:
            return bool(self.predicate(context))
        except Exception:
            return False


# ====================================================================
# 经验规则定义 (LLM/历史经验, 改到这里就改到了流量分析)
# ====================================================================

def _is_resp(ctx: Dict[str, Any]) -> bool:
    return ctx.get("response") is not None

def _headers(ctx: Dict[str, Any]) -> Dict[str, str]:
    r = ctx.get("response") or {}
    h = r.get("headers") or {}
    if hasattr(h, "items"):
        return {k.lower(): v for k, v in h.items()}
    return {k.lower(): str(v) for k, v in h.items()}

def _body(ctx: Dict[str, Any]) -> str:
    r = ctx.get("response") or {}
    b = r.get("body") or b""
    if isinstance(b, bytes):
        try:
            b = b.decode("utf-8", errors="ignore")
        except Exception:
            b = str(b)
    return b[:20000]  # 截断防爆

def _url(ctx: Dict[str, Any]) -> str:
    r = ctx.get("response") or {}
    return (r.get("url") or ctx.get("url") or "").lower()


# 1) 错误页泄露物理路径 / 调试
def _rule_error_path_leak(ctx):
    if not _is_resp(ctx): return False
    body = _body(ctx)
    return bool(re.search(
        r'(/var/www|/home/|/usr/local/|C:\\\\inetpub|D:\\\\)',
        body, re.I
    )) and re.search(r'(error|exception|traceback|fatal)', body, re.I)

# 2) ThinkPHP debug 标记
def _rule_thinkphp_debug(ctx):
    if not _is_resp(ctx): return False
    return "thinkphp" in _body(ctx).lower() and re.search(
        r'(thinksns|onethink|think\\)', _body(ctx), re.I
    ) is not None

# 3) Spring Boot actuator 暴露
def _rule_springboot_actuator(ctx):
    if not _is_resp(ctx): return False
    return "actuator" in _url(ctx) and re.search(
        r'"\w+":\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"', _body(ctx)
    ) is not None

# 4) 弱 CSP / 缺失 CSP
def _rule_weak_csp(ctx):
    if not _is_resp(ctx): return False
    h = _headers(ctx)
    csp = h.get("content-security-policy", "")
    if not csp:
        return True  # 缺失本身就是 finding
    if "unsafe-inline" in csp and "unsafe-eval" in csp:
        return True
    return False

# 5) 缺失 HSTS
def _rule_missing_hsts(ctx):
    if not _is_resp(ctx): return False
    r = ctx.get("response") or {}
    if r.get("status", 200) != 200: return False
    h = _headers(ctx)
    if h.get("strict-transport-security"):
        return False
    # 只对 https 报
    url = _url(ctx)
    return url.startswith("https://")

# 6) CORS 反射 Origin + Allow-Credentials
def _rule_cors_credential_reflect(ctx):
    if not _is_resp(ctx): return False
    h = _headers(ctx)
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    req = ctx.get("request") or {}
    origin = ""
    if hasattr(req.get("headers"), "get"):
        origin = req["headers"].get("origin", "") or req["headers"].get("Origin", "")
    return bool(origin) and (acao == origin or acao == "*") and acac.lower() == "true"

# 7) 暴露敏感 header (Server/Powered-By 含版本)
def _rule_version_disclosure(ctx):
    if not _is_resp(ctx): return False
    h = _headers(ctx)
    server = h.get("server", "") or h.get("x-powered-by", "")
    return bool(re.search(r'\d+\.\d+', server))

# 8) HTTP 方法敏感 (PUT/DELETE/TRACE/PATCH 允许)
def _rule_dangerous_methods(ctx):
    r = ctx.get("response") or {}
    allow = r.get("allow") or ""
    if isinstance(allow, str):
        allow = allow.upper()
    if not allow and r.get("status") in (200, 204, 405):
        # 部分服务器 405 也透出 allow, 但这里保守
        pass
    bad = {"PUT", "DELETE", "TRACE", "PATCH"}
    return bool(set(allow.split(",")) & bad) if allow else False

# 9) phpMyAdmin 暴露
def _rule_phpmyadmin(ctx):
    if not _is_resp(ctx): return False
    return bool(re.search(r'phpmyadmin', _url(ctx) + _body(ctx)[:2000], re.I))

# 10) WordPress 登录页
def _rule_wordpress(ctx):
    if not _is_resp(ctx): return False
    return bool(re.search(r'wp-login\.php|wp-includes', _url(ctx) + _body(ctx)[:2000], re.I))

# 11) SSH banner 含 OpenSSH 老版本
def _rule_old_openssh(ctx):
    if not _is_resp(ctx): return False
    r = ctx.get("response") or {}
    banner = (r.get("banner") or "").lower()
    if "openssh" not in banner: return False
    m = re.search(r'openssh[_-]?(\d+)\.(\d+)', banner)
    if not m: return False
    major, minor = int(m.group(1)), int(m.group(2))
    return (major, minor) < (7, 5)

# 12) Redis INFO 含危险字段 (cluster_slots, replicaof)
def _rule_redis_info_danger(ctx):
    r = ctx.get("response") or {}
    body = r.get("body") or ""
    if not isinstance(body, str): return False
    return bool(re.search(r'^(replicaof|cluster_slots|role):', body, re.M))

# 13) Docker API 暴露 (/v1.40/containers/json)
def _rule_docker_api_exposed(ctx):
    r = ctx.get("response") or {}
    body = r.get("body") or ""
    if not isinstance(body, str): return False
    try:
        import json
        d = json.loads(body)
        return isinstance(d, list) and any("Image" in x and "Id" in x for x in d)
    except Exception:
        return False

# 14) Kibana 暴露
def _rule_kibana(ctx):
    if not _is_resp(ctx): return False
    return "kibana" in _url(ctx) and re.search(
        r'kbn-name|kibana[-_]?version', _body(ctx)[:3000], re.I
    ) is not None

# 15) Grafana 暴露
def _rule_grafana(ctx):
    if not _is_resp(ctx): return False
    return bool(re.search(r'/grafana/|grafana.*version', _url(ctx) + _body(ctx)[:2000], re.I))

# 16) Nagios 暴露
def _rule_nagios(ctx):
    if not _is_resp(ctx): return False
    return bool(re.search(r'nagios.*login|nagiosxi', _url(ctx) + _body(ctx)[:2000], re.I))

# 17) Tomcat Manager
def _rule_tomcat_manager(ctx):
    if not _is_resp(ctx): return False
    return "manager/html" in _url(ctx) and re.search(
        r'(401|403|username|password)', _body(ctx)[:1500], re.I
    ) is not None

# 18) Log4j log4j2.xml 配置泄露
def _rule_log4j_config_leak(ctx):
    if not _is_resp(ctx): return False
    return bool(re.search(r'<Configuration[^>]*log4j2?|<AppenderRef', _body(ctx)))

# 19) JWT 在 URL 里 (token 泄露)
def _rule_jwt_in_url(ctx):
    req = ctx.get("request") or {}
    url = (req.get("url") or ctx.get("url") or "").lower()
    return bool(re.search(r'(eyj[a-z0-9_=]+\.eyj[a-z0-9_=]+\.[a-z0-9_=]+)', url))

# 20) HTTP 401 缺 WWW-Authenticate
def _rule_401_no_challenge(ctx):
    r = ctx.get("response") or {}
    if r.get("status") != 401: return False
    h = _headers(ctx)
    return not h.get("www-authenticate")

# 21) API 列表泄露
def _rule_api_listing(ctx):
    if not _is_resp(ctx): return False
    body = _body(ctx)
    return bool(re.search(
        r'(\.git/config|\.svn/entries|\.env|robots\.txt|sitemap\.xml|swagger|'
        r'openapi|/api/v[0-9]+/?(\?|$)|adminer|phpmyadmin|wp-config)',
        _url(ctx) + body[:2000], re.I
    ))

# 22) C 段/内网 IP 泄露
def _rule_internal_ip_leak(ctx):
    if not _is_resp(ctx): return False
    body = _body(ctx)
    return bool(re.search(
        r'(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)',
        body
    ))


# ====================================================================
# 规则注册表
# ====================================================================

DEFAULT_RULES: List[TrafficRule] = [
    TrafficRule("R01", "错误页泄露物理路径/堆栈", "high", "info_disclosure", "app", _rule_error_path_leak),
    TrafficRule("R02", "ThinkPHP 调试标记泄露", "high", "framework_leak", "app", _rule_thinkphp_debug),
    TrafficRule("R03", "Spring Boot Actuator 未鉴权", "critical", "spring_actuator", "app", _rule_springboot_actuator),
    TrafficRule("R04", "缺失/过弱 CSP", "medium", "weak_csp", "http", _rule_weak_csp),
    TrafficRule("R05", "HTTPS 缺 HSTS", "low", "missing_hsts", "http", _rule_missing_hsts),
    TrafficRule("R06", "CORS Origin 反射 + 凭据", "high", "cors_misconfig", "http", _rule_cors_credential_reflect),
    TrafficRule("R07", "Server/Powered-By 暴露版本", "low", "version_disclosure", "http", _rule_version_disclosure),
    TrafficRule("R08", "危险 HTTP 方法启用 (PUT/DELETE/TRACE)", "medium", "dangerous_methods", "http", _rule_dangerous_methods),
    TrafficRule("R09", "phpMyAdmin 暴露", "high", "phpmyadmin_exposed", "app", _rule_phpmyadmin),
    TrafficRule("R10", "WordPress 登录页暴露", "medium", "wordpress_exposed", "app", _rule_wordpress),
    TrafficRule("R11", "OpenSSH 版本 < 7.5", "high", "old_openssh", "tls", _rule_old_openssh),
    TrafficRule("R12", "Redis 暴露 cluster/replicaof 元数据", "critical", "redis_info_leak", "app", _rule_redis_info_danger),
    TrafficRule("R13", "Docker API 未鉴权", "critical", "docker_api_exposed", "app", _rule_docker_api_exposed),
    TrafficRule("R14", "Kibana 暴露", "high", "kibana_exposed", "app", _rule_kibana),
    TrafficRule("R15", "Grafana 暴露", "high", "grafana_exposed", "app", _rule_grafana),
    TrafficRule("R16", "Nagios 暴露", "high", "nagios_exposed", "app", _rule_nagios),
    TrafficRule("R17", "Tomcat Manager 暴露", "critical", "tomcat_manager", "app", _rule_tomcat_manager),
    TrafficRule("R18", "Log4j 配置泄露", "high", "log4j_config", "app", _rule_log4j_config_leak),
    TrafficRule("R19", "JWT 出现在 URL 中", "high", "jwt_in_url", "app", _rule_jwt_in_url),
    TrafficRule("R20", "401 缺 WWW-Authenticate 质询", "low", "401_no_challenge", "http", _rule_401_no_challenge),
    TrafficRule("R21", "API 列表/敏感路径可访问", "high", "api_listing", "app", _rule_api_listing),
    TrafficRule("R22", "C 段/内网 IP 泄露", "medium", "internal_ip_leak", "app", _rule_internal_ip_leak),
]


@dataclass
class RuleHit:
    rule_id: str
    rule_desc: str
    severity: str
    finding_type: str
    layer: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_desc": self.rule_desc,
            "severity": self.severity,
            "finding_type": self.finding_type,
            "layer": self.layer,
            "evidence": self.evidence[:200],
        }


class TrafficRuleEngine:
    """
    EXPERIENCE_LESSONS 流量规则引擎.

    用法:
        eng = TrafficRuleEngine()
        for ctx in contexts:   # 每个 (request, response, banner...) 一个 ctx
            hits = eng.apply(ctx)
            for h in hits:
                journal.record(h)
    """
    def __init__(self, rules: List[TrafficRule] = None):
        self.rules = rules or DEFAULT_RULES

    def apply(self, context: Dict[str, Any]) -> List[RuleHit]:
        hits: List[RuleHit] = []
        for r in self.rules:
            if r.match(context):
                ev = ""
                if "response" in context and isinstance(context["response"], dict):
                    body = context["response"].get("body", "")
                    if isinstance(body, str) and body:
                        ev = body[:120]
                hits.append(RuleHit(
                    rule_id=r.rule_id, rule_desc=r.description,
                    severity=r.severity, finding_type=r.finding_type,
                    layer=r.layer, evidence=ev,
                ))
        return hits

    def apply_batch(self, contexts: List[Dict[str, Any]]) -> List[RuleHit]:
        out: List[RuleHit] = []
        for c in contexts:
            out.extend(self.apply(c))
        return out

    def critical_only(self, contexts: List[Dict[str, Any]]) -> List[RuleHit]:
        return [h for h in self.apply_batch(contexts) if h.severity == "critical"]
