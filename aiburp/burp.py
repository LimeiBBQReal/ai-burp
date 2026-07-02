"""
AI-Burp V3 - Autonomous Agent Core
全自动异步智能体核心

改进点:
1. 全面异步化 (httpx.AsyncClient)
2. 引入 IntentAnalyzer (意图分析/语义画像)
3. 扩展 KnowledgeBase (全局知识存储)
4. 支持并发探测 (asyncio.gather)
"""

import asyncio
import httpx
import time
import json
import re
import urllib.parse
from .intel import KnowledgeBase, VulnerabilityChainer
from .constants import SQL_ERRORS, WAF_SIGNATURES, INTENT_KEYWORDS
from pathlib import Path

from typing import Dict, Any, List, Optional, Tuple, Union, Set
from datetime import datetime
from dataclasses import dataclass, field

# ============================================================
#                        1. 数据结构
# ============================================================

@dataclass
class Response:
    """HTTP 响应 (V3 增强版)"""
    ok: bool = True
    status: int = 0
    length: int = 0
    time_ms: float = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    
    # 自动监测标记
    error: str = ""          # 错误类型
    blocked: bool = False    # WAF 拦截
    reflects: bool = False   # 反射
    anomalies: List[str] = field(default_factory=list) # 异常列表
    
    # 元数据
    url: str = ""
    method: str = ""
    payload: str = ""
    tags: List[str] = field(default_factory=list) # 语义标签
    
    def __str__(self) -> str:
        flags = []
        if self.error: flags.append(f"ERR:{self.error}")
        if self.blocked: flags.append("BLOCKED")
        if self.reflects: flags.append("REFLECTS")
        if self.tags: flags.append(f"TAGS:{','.join(self.tags[:2])}")
        flag_str = f" [{','.join(flags)}]" if flags else ""
        return f"[{self.status}] {self.length}b {self.time_ms:.0f}ms{flag_str}"

    @property
    def is_interesting(self) -> bool:
        return bool(self.error) or self.reflects or self.blocked or len(self.anomalies) > 0

# ============================================================
#                      2. IntentAnalyzer (语义分析)
# ============================================================

class IntentAnalyzer:
    """
    语义分析器 - 理解接口/资产的"攻击价值".

    V4 扩展: 支持任意协议的 TrafficResponse 分析 (不只 HTTP).
    原有 analyze(url, params) / suggest_detectors(tags) 保持不变 (向后兼容).
    新增 analyze_response(resp) / suggest_next_steps(tags, protocol).
    """
    PATTERNS = {
        "AUTH": [r"login", r"auth", r"sign[_-]?in", r"pwd", r"password", r"token", r"session"],
        "FILE": [r"download", r"upload", r"file", r"path", r"temp", r"pdf", r"image", r"export"],
        "DB": [r"id", r"uuid", r"query", r"search", r"list", r"find", r"data"],
        "ADMIN": [r"admin", r"manage", r"config", r"setting", r"root", r"system"],
        "REDIRECT": [r"url", r"redirect", r"callback", r"next", r"goto", r"return"],
        "CMD": [r"exec", r"run", r"ping", r"shell", r"command", r"calc"],
    }

    @staticmethod
    def analyze(url: str, params: Dict = None) -> List[str]:
        """为 URL 和参数打标签 (HTTP 专用, 向后兼容)"""
        tags = set()
        text = (url + str(params)).lower()

        for tag, patterns in INTENT_KEYWORDS.items():
            for p in patterns:
                if re.search(p, text):
                    tags.add(tag)
        return list(tags)


    @staticmethod
    def suggest_detectors(tags: List[str]) -> List[str]:
        """根据标签建议 HTTP 探测器顺序 (向后兼容)"""
        weight = {
            "sqli": 10, "xss": 10, "ssrf": 0, "lfi": 0, "cmdi": 0, "ssti": 0
        }
        if "DB" in tags: weight["sqli"] += 20
        if "REDIRECT" in tags: weight["ssrf"] += 30
        if "FILE" in tags: weight["lfi"] += 30
        if "CMD" in tags: weight["cmdi"] += 50
        if "AUTH" in tags: weight["sqli"] += 15 # Auth bypass

        # 排序
        sorted_detectors = sorted(weight.items(), key=lambda x: x[1], reverse=True)
        return [d[0] for d in sorted_detectors if d[1] > 0]

    # ============================================================
    # V4: 多协议扩展
    # ============================================================

    @staticmethod
    def analyze_response(resp) -> List[str]:
        """
        分析任意协议的 TrafficResponse, 输出协议无关的攻击意图标签.

        输入: aiburp.traffic.TrafficResponse (或含 protocol/banner/tags/text 的对象)
        输出: 语义标签列表, 供 AI 决策层排序攻击向量.

        标签体系:
            - HTTP 业务意图: AUTH/DB/FILE/CMD/ADMIN/REDIRECT (原有)
            - 服务风险:     HIGH-VALUE / UNAUTH-CHECK / RCE-PATH / DATA-LEAK
            - 协议特征:     DNS-AXFR-LEAK / SSH-VERSION / TLS-WEAK / CSWSH
        """
        tags = set()

        # 1. 先继承 resp 已有的 tags (adapter 已经打的)
        existing = getattr(resp, "tags", None) or []
        tags.update(existing)

        protocol = (getattr(resp, "protocol", "") or "").lower()
        banner = (getattr(resp, "banner", "") or "").lower()
        text_lower = (getattr(resp, "text", "") or "").lower()
        text_raw = getattr(resp, "text", "") or ""  # 保留原始大小写 (敏感 key 匹配用)
        target = (getattr(resp, "target", "") or "").lower()
        anomalies = getattr(resp, "anomalies", None) or []

        # 2. HTTP: 走原有 URL 关键词分析 (用 url + body)
        if protocol in ("http", "https"):
            url = getattr(resp, "url", "") or target
            tags.update(IntentAnalyzer.analyze(url, {}))

        # 3. 服务名识别 (从 protocol / banner 提取)
        from .constants import HIGH_VALUE_SERVICES
        service = ""
        if protocol in HIGH_VALUE_SERVICES:
            service = protocol
        elif banner:
            # banner 形如 "redis/7.0" / "ssh" / "mysql"
            service = banner.split("/")[0].split("(")[0].strip()

        # 4. 服务风险打标
        if service in HIGH_VALUE_SERVICES:
            tags.add("HIGH-VALUE")
            tags.add("UNAUTH-CHECK")
            # 已确认未授权 = RCE 路径
            if any("unauth" in a for a in anomalies) or "UNAUTH-CONFIRMED" in tags:
                tags.add("RCE-PATH")

        # 5. 协议特定语义
        if protocol == "dns":
            if "axfr" in " ".join(anomalies).lower():
                tags.add("ZONE-LEAK")
            if "bind" in banner:
                tags.add("DNS-VERSION-LEAK")
            # 内网域名特征
            if any(s in target for s in ("internal", "corp", "local", "intranet", "private")):
                tags.add("INTERNAL-ASSET")

        elif protocol in ("redis", "docker", "kubelet"):
            if "AUTH-REQUIRED" in tags:
                tags.discard("HIGH-VALUE")
                tags.discard("UNAUTH-CHECK")
                tags.add("SECURED")

        elif protocol == "ws":
            if "CSWSH-VULNERABLE" in tags:
                tags.add("HIGH-VALUE")

        elif protocol == "tls":
            # TLS 证书 SAN 泄露子域名 = 高价值侦察情报
            if "SAN-LEAK" in tags:
                tags.add("HIGH-VALUE")
                tags.add("RECON-VALUE")  # 信息收集价值 (非直接 RCE)
            # 自签名 = 可能钓鱼/未配置
            if "SELF-SIGNED" in tags:
                tags.add("SUSPICIOUS")
            # 过期证书 = 运维疏忽
            if "EXPIRED" in tags:
                tags.add("MISCONFIG")
            # 弱套件 = 可被中间人攻击
            if "WEAK-CIPHER" in tags or "WEAK-TLS-VERSION" in tags:
                tags.add("DOWNGRADE-POSSIBLE")

        elif service in ("ssh", "ftp", "telnet"):
            tags.add("BRUTEFORCE-TARGET")

        # 6. 响应内容里的敏感信息泄露
        # 用原始大小写 text_raw (AWS key AKIA / JWT ey 等需大小写敏感)
        # 安全: 限制扫描文本长度 (超过 100KB 截断), 防止恶意长响应拖垮分析
        # 安全: email 正则含 [a-z0-9._+-]* 量词, 无 @ 时会 ReDoS,
        #        用 '@' in text 前置检查跳过 (其它模式不受影响)
        from .constants import SENSITIVE_PATTERNS
        scan_text = text_raw[:102400] if len(text_raw) > 102400 else text_raw
        for name, pat in SENSITIVE_PATTERNS.items():
            try:
                # email 特殊处理: 无 @ 直接跳过 (避免 ReDoS)
                if name == "email" and "@" not in scan_text:
                    continue
                if isinstance(pat, list):
                    for p in pat:
                        if re.search(p, scan_text, re.I):
                            tags.add(f"LEAK-{name.upper()}")
                            break
                else:
                    if re.search(pat, scan_text):
                        tags.add(f"LEAK-{name.upper()}")
            except (re.error, RuntimeError):
                # 正则异常 (如 RecursionError) 不应让整个分析失败
                continue

        return sorted(tags)

    @staticmethod
    def suggest_next_steps(tags: List[str], protocol: str = "") -> List[Dict[str, str]]:
        """
        根据语义标签 + 协议, 建议下一步攻击操作 (协议无关).

        输出: [{"action": "...", "desc": "...", "priority": high/medium/low}, ...]
        按 priority 排序. AI 可直接消费做决策.

        与 suggest_detectors 的区别:
            - suggest_detectors: 只输出 HTTP 漏洞类型 (sqli/xss/...)
            - suggest_next_steps: 输出具体攻击操作 (check_unauth/dump_ssh_key/...)
        """
        from .constants import SERVICE_ATTACK_VECTORS, PROTOCOL_RISK
        steps = []
        tags_set = set(tags)

        # 1. 协议/服务对应的攻击向量
        service = protocol.lower() if protocol else ""
        # 从 tags 里推断 service (HIGH-VALUE + REDIS 等)
        if not service:
            for t in tags:
                if t.lower() in SERVICE_ATTACK_VECTORS:
                    service = t.lower()
                    break

        if service in SERVICE_ATTACK_VECTORS:
            priority = "high" if service in ("redis", "docker", "kubelet") else "medium"
            for action, desc in SERVICE_ATTACK_VECTORS[service]:
                steps.append({
                    "action": action,
                    "desc": desc,
                    "priority": priority,
                })

        # 2. RCE 路径已确认 -> 最高优先级
        if "RCE-PATH" in tags_set or "UNAUTH-CONFIRMED" in tags_set:
            steps.insert(0, {
                "action": "exploit_rce",
                "desc": "确认 RCE 路径, 直接利用 (反弹shell/持久化)",
                "priority": "critical",
            })

        # 3. HTTP 业务意图 -> 漏洞检测器
        if protocol.lower() in ("http", "https"):
            http_detectors = IntentAnalyzer.suggest_detectors(tags)
            for d in http_detectors:
                desc_map = {
                    "sqli": "SQL 注入检测 (错误/时间/UNION)",
                    "xss": "XSS 检测 (反射/存储/DOM)",
                    "ssrf": "SSRF 检测 (内网/云元数据)",
                    "lfi": "LFI/路径穿越检测",
                    "cmdi": "命令注入检测",
                    "ssti": "SSTI 模板注入检测",
                }
                steps.append({
                    "action": f"scan_{d}",
                    "desc": desc_map.get(d, d),
                    "priority": "medium",
                })

        # 4. 信息泄露
        for t in tags:
            if t.startswith("LEAK-"):
                steps.append({
                    "action": f"extract_{t[5:].lower()}",
                    "desc": f"提取泄露的 {t[5:]} (确认并收集)",
                    "priority": "high",
                })

        # 5. 去重 + 排序
        seen = set()
        unique = []
        for s in steps:
            key = s["action"]
            if key not in seen:
                seen.add(key)
                unique.append(s)

        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 3))
        return unique

# ============================================================
#                        3. AsyncBurp (核心)
# ============================================================

class AsyncBurp:
    """
    异步 AI-Burp 核心 (V3)
    """
    
    def __init__(

        self,
        project: str = "default",
        delay: float = 0.5, # 异步下默认延迟降低
        timeout: float = 30.0,
        concurrency: int = 5,
        proxy: str = None,
        stealth: bool = False,
        stealth_profile: str = "chrome_120"
    ):
        self.project = project
        self.delay = delay
        self.concurrency = concurrency
        self.stealth_mode = stealth
        
        # 初始化 HTTP 客户端
        if stealth:
            from .stealth import StealthClient, AdaptiveRateLimiter
            rate_limiter = AdaptiveRateLimiter(base_delay=delay)
            self._stealth_client = StealthClient(
                profile=stealth_profile,
                rate_limiter=rate_limiter,
                proxy=proxy,
                timeout=timeout
            )
            self._client = None
        else:
            self._stealth_client = None
            self._client = httpx.AsyncClient(
                timeout=timeout,
                verify=False,
                follow_redirects=False,
                proxy=proxy
            )
        
        self.history = []
        self._semaphore = asyncio.Semaphore(concurrency)
        
        # V3 智力层
        self.kb = KnowledgeBase(project)
        self.chainer = VulnerabilityChainer(self.kb)

    async def _send_param(self, url: str, param: str, value: str, method: str) -> Response:
        """替换参数值并发送 (与 V2 保持兼容)"""
        if method.upper() == "GET":
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param] = [value]
            new_query = urllib.parse.urlencode(params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            return await self.get(new_url, check=value)
        else:
            return await self.post(url, data={param: value}, check=value)

    async def get(self, url: str, params: Dict = None, **kw) -> Response:
        return await self.request("GET", url, params=params, **kw)


    async def post(self, url: str, data=None, json: Dict = None, **kw) -> Response:
        return await self.request("POST", url, data=data, json_data=json, **kw)

    async def request(
        self,
        method: str,
        url: str,
        params: Dict = None,
        headers: Dict = None,
        data: Any = None,
        json_data: Dict = None,
        check: str = None,
        **kwargs
    ) -> Response:

        """异步请求核心"""
        async with self._semaphore:
            # 自动添加语义标签
            tags = IntentAnalyzer.analyze(url, data or json_data)
            
            try:
                if self.stealth_mode and self._stealth_client:
                    # 使用 StealthClient (自带速率限制)
                    result = await self._stealth_client.request(
                        method, url, headers=headers, data=data, json=json_data, **kwargs
                    )
                    r = Response(
                        ok=result.get("ok", False),
                        status=result.get("status", 0),
                        length=len(result.get("body", "")),
                        time_ms=result.get("time_ms", 0),
                        body=result.get("body", ""),
                        headers=result.get("headers", {}),
                        url=url,
                        method=method,
                        tags=tags,
                        error=result.get("error", "")
                    )
                else:
                    # 标准 httpx 客户端
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    
                    resp = await self._client.request(
                        method, url, params=params, headers=headers, data=data, json=json_data, **kwargs
                    )
                    
                    body = resp.text
                    r = Response(
                        status=resp.status_code,
                        length=len(resp.content),
                        time_ms=resp.elapsed.total_seconds() * 1000,
                        body=body,
                        headers=dict(resp.headers),
                        url=url,
                        method=method,
                        tags=tags
                    )
                
                self._detect_error(r)
                if check and check in r.body: r.reflects = True
                if r.status in [403, 406, 429]: r.blocked = True
                
            except Exception as e:
                r = Response(ok=False, url=url, method=method, error=str(e), tags=tags)
            
            self.history.append(r)
            return r

    async def send(self, method: str, url: str, **kwargs) -> Response:
        return await self.request(method, url, **kwargs)

    async def fuzz(
        self,
        url: str,
        payloads: List[str],
        marker: str = "§"
    ) -> List[Response]:
        """超高并发 Fuzz"""
        tasks = []
        for p in payloads:
            test_url = url.replace(marker, str(p))
            # 注意: Async 下我们在 request 内部处理信号量
            tasks.append(self.request("GET", test_url, check=str(p)))
        
        results = await asyncio.gather(*tasks)
        for i, r in enumerate(results):
            r.payload = payloads[i]
        return results

    def _detect_error(self, r: Response):
        for err_type, patterns in SQL_ERRORS.items():
            for p in patterns:
                if re.search(p, r.body, re.I):
                    r.error = err_type
                    return

        # 同时探测 WAF
        for waf_name, patterns in WAF_SIGNATURES.items():
            for p in patterns:
                if re.search(p, r.body, re.I) or any(re.search(p, str(h), re.I) for h in r.headers.values()):
                    r.blocked = True
                    return


    async def close(self):
        if self.stealth_mode and self._stealth_client:
            await self._stealth_client.close()
        elif self._client:
            await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

# ============================================================
#                        4. 异步决策机制
# ============================================================

@dataclass
class Decision:
    """异步决策请求"""
    type: str = ""
    status: str = ""
    findings: Dict[str, Any] = field(default_factory=dict)
    options: List[Dict[str, str]] = field(default_factory=list)
    suggestion: str = ""
    data: Any = None

class AsyncSmartBurp(AsyncBurp):
    """
    异步智能决策引擎
    """
    async def smart_scan(self, url: str, param: str, value: str) -> Decision:
        """
        全自动流水线: 语义分析 -> 精准扫描 -> 决策生成 -> 漏洞链分析
        """
        # 1. 语义分析
        tags = IntentAnalyzer.analyze(url, {param: value})
        suggested = IntentAnalyzer.suggest_detectors(tags)
        
        # 2. 执行扫描
        from .detectors import AsyncVulnScanner
        scanner = AsyncVulnScanner(self)
        findings = await scanner.scan_all(url, param, value)
        
        # 3. 结果入库 (KnowledgeBase)
        for f in findings:
            if f.confidence == "high":
                self.kb.add("vulnerability", f.evidence, url, context=f.payload)
        
        # 4. 漏洞链潜力分析
        chain_analysis = self.chainer.analyze_chain_potential(findings)
        
        # 5. 生成决策
        decision = Decision(
            type="scan_done",
            status=f"分析完成: {url} [{','.join(tags)}]",
            findings={
                "漏洞总数": len(findings),
                "高危漏洞": len([f for f in findings if f.confidence == "high"]),
                "漏洞类型": chain_analysis["current_vulns"],
                "RCE路径数": chain_analysis["rce_paths"],
                "最高影响": chain_analysis["highest_impact"],
            },
            data=findings
        )
        
        # 6. 漏洞链建议
        chain_suggestions = self.chainer.suggest_next_steps(findings)
        if chain_suggestions:
            top = chain_suggestions[0]
            decision.suggestion = f"🧠 漏洞链建议: {top['reason']} (优先级: {top.get('priority', 'N/A')})"
            decision.options = chain_suggestions[:5]
        
        # 7. 如果有 RCE 路径，高亮提示
        if chain_analysis["rce_paths"] > 0:
            decision.suggestion = f"🔴 发现 {chain_analysis['rce_paths']} 条通往 RCE 的攻击路径! " + decision.suggestion
        
        return decision
    
    async def smart_fuzz_with_injection(self, url: str, vuln_type: str, marker: str = "§") -> List[Response]:
        """
        使用 DependencyInjector 注入知识库数据进行 Fuzz
        
        Args:
            url: 包含 marker 的 URL
            vuln_type: 漏洞类型 (ssrf, lfi, auth)
            marker: 替换标记
        
        Returns:
            Fuzz 结果列表
        """
        # 获取注入后的 payload
        payloads = self.chainer.get_injection_payloads(vuln_type)
        
        if not payloads:
            return []
        
        return await self.fuzz(url, payloads, marker)


# 示例用法 (仅供测试)
if __name__ == "__main__":
    async def test():
        async with AsyncBurp(concurrency=10) as burp:
            r = await burp.send("GET", "https://httpbin.org/get?id=1")
            print(f"Single: {r}")
            
            print("Fuzzing...")
            results = await burp.fuzz("https://httpbin.org/get?id=§", ["'", '"', "1 OR 1=1"])
            for res in results:
                print(res)

    # asyncio.run(test())
