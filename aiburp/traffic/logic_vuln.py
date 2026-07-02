"""
业务逻辑漏洞检测引擎.

核心思路: 一切以流量为王 —— 拦截请求 → 变异参数 → 对比响应 → 判断越权.

支持的漏洞类型:
    1. IDOR (越权访问): 用 A 的凭据访问 B 的资源
    2. 权限提升: 普通用户 token 访问管理员接口
    3. 参数篡改: 修改 price/quantity/discount 等业务参数
    4. 批量遍历: ID 递增/递减遍历
    5. 竞争条件: 同一请求并发发多次

设计:
    - 组合 AuthManager (多账户) + SimpleBurp (HTTP 请求) + 差异分析
    - 从一个 HTTP 请求 (History 记录或手动构造) 开始
    - AI 识别"哪些参数是 ID/价格/权限标识" → 自动变异
    - 对比变异前后的响应差异 → 判断是否越权

工作流:
    1. 用户提供目标请求 (URL + 参数 + 凭据)
    2. 引擎建立基线 (正常请求的响应)
    3. 对每个疑似敏感参数做变异:
       - ID 类: +1/-1/其它用户 ID
       - 价格类: *0.01/-1/0
       - 角色类: admin/user/guest
    4. 对比响应: 状态码/长度/内容差异
    5. 差异显著 = 可能存在漏洞
"""

import asyncio
import re
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode

from .bridge import SimpleBurp, create_bridge_burp


# ============================================================
#                   数据结构
# ============================================================

@dataclass
class LogicVulnFinding:
    """业务逻辑漏洞发现"""
    vuln_type: str           # IDOR / PRIVILEGE-ESCALATION / PRICE-TAMPERING / MASS-ASSIGNMENT
    url: str
    param: str
    original_value: str
    test_value: str
    severity: str = "high"   # high / medium / low
    confidence: str = "confirmed"  # confirmed / probable / possible

    # 响应对比
    baseline_status: int = 0
    baseline_length: int = 0
    test_status: int = 0
    test_length: int = 0

    # 差异
    status_changed: bool = False
    length_diff: int = 0
    evidence: str = ""

    # 哪个账户的凭据
    test_account: str = ""

    def to_dict(self) -> Dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "original_value": self.original_value,
            "test_value": self.test_value,
            "severity": self.severity,
            "confidence": self.confidence,
            "baseline": {"status": self.baseline_status, "length": self.baseline_length},
            "test": {"status": self.test_status, "length": self.test_length},
            "status_changed": self.status_changed,
            "length_diff": self.length_diff,
            "evidence": self.evidence[:200],
            "test_account": self.test_account,
        }


@dataclass
class LogicScanResult:
    """业务逻辑扫描结果"""
    target_url: str = ""
    findings: List[LogicVulnFinding] = field(default_factory=list)
    params_analyzed: int = 0
    total_tests: int = 0
    accounts_used: List[str] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.confidence == "confirmed")

    def to_dict(self) -> Dict:
        return {
            "target_url": self.target_url,
            "params_analyzed": self.params_analyzed,
            "total_tests": self.total_tests,
            "accounts_used": self.accounts_used,
            "confirmed_vulns": self.confirmed_count,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def report_text(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("业务逻辑漏洞扫描报告")
        lines.append("=" * 70)
        lines.append(f"目标: {self.target_url}")
        lines.append(f"分析参数: {self.params_analyzed} | 总测试: {self.total_tests} | "
                      f"确认漏洞: {self.confirmed_count}")
        lines.append("-" * 70)

        if not self.findings:
            lines.append("(未发现业务逻辑漏洞)")
            return "\n".join(lines)

        # 按类型分组
        by_type: Dict[str, List[LogicVulnFinding]] = {}
        for f in self.findings:
            by_type.setdefault(f.vuln_type, []).append(f)

        type_labels = {
            "IDOR": "🔓 越权访问 (IDOR)",
            "PRIVILEGE-ESCALATION": "⬆️ 权限提升",
            "PRICE-TAMPERING": "💰 价格篡改",
            "MASS-ASSIGNMENT": "📦 批量赋值",
            "RACE-CONDITION": "🏁 竞争条件",
        }

        for vtype, findings in by_type.items():
            label = type_labels.get(vtype, vtype)
            lines.append(f"\n{label} ({len(findings)}):")
            for f in findings:
                conf = "✅" if f.confidence == "confirmed" else "⚠️"
                lines.append(f"  {conf} {f.url}")
                lines.append(f"     参数: {f.param} = {f.original_value!r} → {f.test_value!r}")
                lines.append(f"     基线: {f.baseline_status} ({f.baseline_length}b) → "
                              f"测试: {f.test_status} ({f.test_length}b) "
                              f"差异: {f.length_diff:+d}b")
                if f.evidence:
                    lines.append(f"     证据: {f.evidence[:100]}")
                if f.test_account:
                    lines.append(f"     凭据: {f.test_account}")

        return "\n".join(lines)


# ============================================================
#               参数敏感度识别
# ============================================================

# 疑似 ID 参数的模式
ID_PATTERNS = [
    (re.compile(r"(?i)^(id|uid|user_?id|account_?id|order_?id|record_?id|item_?id|doc_?id|msg_?id|post_?id|file_?id|res_?id)$"), "ID"),
    (re.compile(r"(?i)(uuid|guid)"), "UUID"),
    (re.compile(r"(?i)^(num|no|number|seq|index)$"), "SEQUENCE"),
]

# 疑似价格/金额参数
PRICE_PATTERNS = [
    (re.compile(r"(?i)(price|amount|cost|fee|total|subtotal|discount|tax|balance|payment)"), "PRICE"),
]

# 疑似权限/角色参数
ROLE_PATTERNS = [
    (re.compile(r"(?i)(role|admin|is_?admin|is_?staff|permission|privilege|level|type|user_?type|account_?type)"), "ROLE"),
]

# 疑似状态参数
STATUS_PATTERNS = [
    (re.compile(r"(?i)(status|state|active|enabled|verified|approved|paid|shipped)"), "STATUS"),
]


def classify_param(name: str, value: str) -> Optional[str]:
    """
    判断参数是否敏感 (可能是业务逻辑攻击目标).

    Returns:
        参数类型 ("ID" / "PRICE" / "ROLE" / "STATUS") 或 None
    """
    for pattern, ptype in (ID_PATTERNS + PRICE_PATTERNS + ROLE_PATTERNS + STATUS_PATTERNS):
        if pattern.search(name):
            return ptype
    # 值是纯数字也可能是 ID
    if value.isdigit() and len(value) <= 10:
        return "ID"
    return None


def generate_test_values(param_type: str, original_value: str) -> List[str]:
    """根据参数类型生成测试值"""
    if param_type == "ID":
        tests = []
        try:
            num = int(original_value)
            tests.append(str(num + 1))    # +1
            tests.append(str(num - 1))    # -1
            tests.append(str(num + 100))  # +100
            tests.append("1")             # 最小 ID
            tests.append("999999")        # 大 ID
        except ValueError:
            tests.extend(["1", "0", "admin", "root"])
        return tests

    elif param_type == "PRICE":
        return ["0", "0.01", "-1", "99999999", original_value + "00"]

    elif param_type == "ROLE":
        return ["admin", "administrator", "root", "superuser", "1", "staff"]

    elif param_type == "STATUS":
        return ["1", "0", "true", "false", "approved", "paid", "active"]

    return []


# ============================================================
#               业务逻辑漏洞检测引擎
# ============================================================

class LogicVulnScanner:
    """
    业务逻辑漏洞检测引擎.

    用法:
        scanner = LogicVulnScanner(engine)

        # 基本越权检测 (单账户, 参数变异)
        result = await scanner.scan_url(
            url="https://target.com/api/orders/1001",
            params={"order_id": "1001"},
        )

        # 多账户越权检测 (A 的 token 访问 B 的资源)
        result = await scanner.scan_idor(
            url="https://target.com/api/orders/{id}",
            accounts={
                "user_a": {"Cookie": "session=aaa"},
                "user_b": {"Cookie": "session=bbb"},
            },
        )
    """

    def __init__(self, engine):
        self.engine = engine

    def _get_burp(self) -> SimpleBurp:
        """获取 HTTP 客户端 (每次新建, 在 to_thread 内调用)"""
        return create_bridge_burp(self.engine, delay=0.0)

    # ============================================================
    #               scan_url: 单 URL 参数变异
    # ============================================================

    async def scan_url(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> LogicScanResult:
        """
        对单个 URL 做参数变异检测.

        自动识别 URL 路径和参数里的 ID/价格/角色,
        逐个变异, 对比响应差异.

        Args:
            url:     目标 URL
            params:  查询参数 (可选)
            method:  HTTP 方法
            headers: 请求头
            body:    请求体
        """
        result = LogicScanResult(target_url=url)
        result.accounts_used = ["default"]

        # 收集所有参数 (URL 路径 + query + body)
        all_params = {}
        # URL 路径里的数字段 (/orders/1001 -> path_id=1001)
        path_ids = re.findall(r"/(\d+)(?:/|$|\?)", url)
        for i, pid in enumerate(path_ids):
            all_params[f"path_id_{i}"] = pid

        # query 参数
        if params:
            all_params.update(params)

        # body 参数 (简单的 key=value 解析)
        if body and "=" in body:
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    all_params[k] = v

        if not all_params:
            return result

        result.params_analyzed = len(all_params)

        # 逐个参数检测
        for param_name, param_value in all_params.items():
            ptype = classify_param(param_name, param_value)
            if not ptype:
                continue

            test_values = generate_test_values(ptype, param_value)
            result.total_tests += len(test_values)

            # 基线请求
            def _run_baseline():
                burp = self._get_burp()
                return burp.request(method, url, params=params, headers=headers, data=body)

            try:
                baseline = await asyncio.to_thread(_run_baseline)
            except Exception:
                continue

            # 变异测试
            for test_val in test_values:
                # 构造变异请求
                mutated_params = dict(params or {})
                mutated_body = body
                mutated_url = url

                if param_name.startswith("path_id_"):
                    # 路径 ID 替换
                    idx = int(param_name.split("_")[-1])
                    parts = url.split("/")
                    count = 0
                    for i, part in enumerate(parts):
                        if part.isdigit():
                            if count == idx:
                                parts[i] = test_val
                                break
                            count += 1
                    mutated_url = "/".join(parts)
                elif param_name in mutated_params:
                    mutated_params[param_name] = test_val
                elif body and param_name in body:
                    mutated_body = body.replace(f"{param_name}={param_value}",
                                                f"{param_name}={test_val}")

                def _run_test(u=mutated_url, p=mutated_params, h=headers, b=mutated_body):
                    burp = self._get_burp()
                    return burp.request(method, u, params=p, headers=h, data=b)

                try:
                    test_resp = await asyncio.to_thread(_run_test)
                except Exception:
                    continue

                # 差异分析
                status_changed = (test_resp.status != baseline.status)
                length_diff = test_resp.length - baseline.length

                # 判断是否有趣:
                # - 状态码从 403→200 (越权成功)
                # - 状态码相同但长度显著不同 (返回了不同数据)
                # - 200 且长度相近 (IDOR 可能成功)
                is_interesting = False
                evidence = ""

                if baseline.status in (401, 403) and test_resp.status == 200:
                    is_interesting = True
                    evidence = f"状态码 {baseline.status}→{test_resp.status} (权限绕过)"
                elif (baseline.status == 200 and test_resp.status == 200
                      and abs(length_diff) > 100
                      and "error" not in test_resp.body.lower()[:200]):
                    is_interesting = True
                    evidence = f"200 OK 但长度差异 {length_diff:+d}b (可能返回了不同数据)"
                elif baseline.status == 200 and test_resp.status == 200 and abs(length_diff) < 50:
                    # 长度相近 - 可能 IDOR 成功 (返回了结构相同的其它用户数据)
                    if ptype == "ID":
                        is_interesting = True
                        evidence = f"200 OK 长度相近 ({length_diff:+d}b) - 可能返回了其它用户数据"

                if is_interesting:
                    finding = LogicVulnFinding(
                        vuln_type=_ptype_to_vuln(ptype),
                        url=url,
                        param=param_name,
                        original_value=param_value,
                        test_value=test_val,
                        severity="high" if status_changed else "medium",
                        confidence="confirmed" if status_changed else "probable",
                        baseline_status=baseline.status,
                        baseline_length=baseline.length,
                        test_status=test_resp.status,
                        test_length=test_resp.length,
                        status_changed=status_changed,
                        length_diff=length_diff,
                        evidence=evidence,
                    )
                    result.findings.append(finding)

        return result

    # ============================================================
    #               scan_idor: 多账户越权
    # ============================================================

    async def scan_idor(
        self,
        url: str,
        accounts: Dict[str, Dict[str, str]],
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
    ) -> LogicScanResult:
        """
        多账户越权检测 (IDOR).

        用每个账户的凭据访问同一个 URL, 对比响应.
        如果 user_b 能看到 user_a 的数据 = 水平越权.

        Args:
            url:      目标 URL (含 user_a 的资源 ID)
            accounts: {"user_a": {"Cookie":"..."}, "user_b": {"Cookie":"..."}}
        """
        result = LogicScanResult(target_url=url)
        result.accounts_used = list(accounts.keys())

        if len(accounts) < 2:
            # 单账户: 走参数变异
            headers = list(accounts.values())[0] if accounts else None
            return await self.scan_url(url, params=params, method=method, headers=headers)

        # 用第一个账户建立基线
        account_names = list(accounts.keys())
        baseline_account = account_names[0]
        baseline_headers = accounts[baseline_account]

        def _run_baseline():
            burp = self._get_burp()
            return burp.request(method, url, params=params, headers=baseline_headers)

        try:
            baseline = await asyncio.to_thread(_run_baseline)
        except Exception as e:
            result.findings.append(LogicVulnFinding(
                vuln_type="ERROR", url=url, param="",
                original_value="", test_value="",
                evidence=f"基线请求失败: {e}",
                confidence="possible",
            ))
            return result

        result.total_tests = len(accounts) - 1

        # 用其它账户访问同一资源
        for acct_name in account_names[1:]:
            acct_headers = accounts[acct_name]

            def _run_test(h=acct_headers):
                burp = self._get_burp()
                return burp.request(method, url, params=params, headers=h)

            try:
                test_resp = await asyncio.to_thread(_run_test)
            except Exception:
                continue

            status_changed = (test_resp.status != baseline.status)
            length_diff = test_resp.length - baseline.length

            # 越权判断:
            # - user_b 用自己的 cookie 访问 user_a 的资源, 返回 200 + 数据 = 越权
            # - 返回 403/404 = 安全
            is_idor = False
            evidence = ""

            if test_resp.status == 200 and baseline.status == 200:
                # 都返回 200 - 检查是否返回了相同数据 (越权)
                if abs(length_diff) < 100:
                    is_idor = True
                    evidence = (f"{acct_name} 用自己的凭据访问了 {baseline_account} 的资源, "
                                f"返回 200 + 相似数据 (长度差异 {length_diff:+d}b)")
                elif length_diff < -500:
                    is_idor = True
                    evidence = (f"{acct_name} 访问他人资源返回 200 (长度 {test_resp.length}b, "
                                f"基线 {baseline.length}b)")

            if is_idor:
                result.findings.append(LogicVulnFinding(
                    vuln_type="IDOR",
                    url=url,
                    param="(cookie/token)",
                    original_value=baseline_account,
                    test_value=acct_name,
                    severity="high",
                    confidence="confirmed",
                    baseline_status=baseline.status,
                    baseline_length=baseline.length,
                    test_status=test_resp.status,
                    test_length=test_resp.length,
                    length_diff=length_diff,
                    evidence=evidence,
                    test_account=acct_name,
                ))

        return result

    # ============================================================
    #               scan_race: 竞争条件
    # ============================================================

    async def scan_race(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        concurrency: int = 20,
        rounds: int = 3,
    ) -> LogicScanResult:
        """
        竞争条件检测 (Race Condition).

        同一请求并发发 N 次, 看是否:
        - 重复领取优惠券
        - 重复提现
        - 多次扣减库存

        Args:
            url:         目标 URL
            method:      HTTP 方法 (通常 POST)
            concurrency: 并发数
            rounds:      测试轮次
        """
        result = LogicScanResult(target_url=url)
        result.accounts_used = ["race-test"]

        import aiohttp
        import json as _json

        all_responses = []

        for round_num in range(rounds):
            async with aiohttp.ClientSession() as session:
                tasks = []
                for _ in range(concurrency):
                    if method.upper() == "POST":
                        task = session.post(url, headers=headers, data=body, ssl=False)
                    else:
                        task = session.get(url, headers=headers, ssl=False)
                    tasks.append(task)

                responses = await asyncio.gather(*tasks, return_exceptions=True)
                round_results = []
                for r in responses:
                    if isinstance(r, Exception):
                        round_results.append(("error", 0, str(r)[:50]))
                    else:
                        status = r.status
                        text = await r.text()
                        length = len(text)
                        round_results.append((status, length, text[:100]))
                        r.close()
                all_responses.append(round_results)

        # 分析: 如果多次请求都返回"成功"状态, 可能存在竞争条件
        result.total_tests = concurrency * rounds

        for round_num, round_results in enumerate(all_responses):
            success_count = sum(1 for s, l, t in round_results
                               if s == 200 and "error" not in t.lower() and "fail" not in t.lower())
            if success_count > 1:
                # 多个并发请求都"成功" - 竞争条件
                result.findings.append(LogicVulnFinding(
                    vuln_type="RACE-CONDITION",
                    url=url,
                    param="(concurrent)",
                    original_value=f"{concurrency}并发",
                    test_value=f"{success_count}次成功",
                    severity="high" if success_count > 2 else "medium",
                    confidence="confirmed" if success_count > 2 else "probable",
                    evidence=(f"第{round_num+1}轮: {concurrency} 个并发请求中 "
                              f"{success_count} 个返回成功 (竞争条件)"),
                ))
                break

        return result


def _ptype_to_vuln(ptype: str) -> str:
    """参数类型 → 漏洞类型"""
    return {
        "ID": "IDOR",
        "PRICE": "PRICE-TAMPERING",
        "ROLE": "PRIVILEGE-ESCALATION",
        "STATUS": "STATUS-TAMPERING",
    }.get(ptype, "PARAM-TAMPERING")
