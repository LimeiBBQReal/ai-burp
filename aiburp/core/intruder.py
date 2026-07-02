"""
AIBURP Intruder - 批量测试

AI 决定用什么 payload，工具负责批量发送
发现异常可以停下来，让 AI 决定下一步
"""

import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from .models import Request, Response
from .history import History
from .repeater import Repeater


@dataclass
class AttackResult:
    """单个 payload 的测试结果"""
    payload: str
    status: int
    length: int
    time_ms: float
    anomalies: List[str] = field(default_factory=list)
    reflects: bool = False
    
    # 与基线的差异
    status_changed: bool = False
    length_diff: int = 0
    time_diff: float = 0
    
    def to_dict(self) -> Dict:
        return {
            "payload": self.payload,
            "status": self.status,
            "length": self.length,
            "time_ms": self.time_ms,
            "anomalies": self.anomalies,
            "reflects": self.reflects,
            "status_changed": self.status_changed,
            "length_diff": self.length_diff,
            "time_diff": self.time_diff,
        }
    
    @property
    def is_interesting(self) -> bool:
        """是否值得关注"""
        return (
            len(self.anomalies) > 0 or
            self.reflects or
            self.status_changed or
            abs(self.length_diff) > 100 or
            self.time_diff > 2000  # 2秒以上延迟
        )


@dataclass
class AttackReport:
    """攻击报告"""
    request_id: int
    param: str
    total: int
    tested: int
    stopped: bool = False
    stop_reason: str = ""
    
    baseline_status: int = 0
    baseline_length: int = 0
    baseline_time: float = 0
    
    results: List[AttackResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "param": self.param,
            "total": self.total,
            "tested": self.tested,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "baseline": {
                "status": self.baseline_status,
                "length": self.baseline_length,
                "time_ms": self.baseline_time,
            },
            "interesting": [r.to_dict() for r in self.results if r.is_interesting],
            "all_results": [r.to_dict() for r in self.results],
        }
    
    @property
    def interesting_count(self) -> int:
        return sum(1 for r in self.results if r.is_interesting)
    
    @property
    def has_findings(self) -> bool:
        return self.interesting_count > 0


class Intruder:
    """
    批量测试器
    
    用法:
        intruder = Intruder(history)
        
        # 批量测试
        report = intruder.attack(
            request_id=123,
            param="id",
            payloads=["'", "1 OR 1=1", ...],
            stop_on="anomaly",  # 发现异常就停
        )
        
        # 查看结果
        for r in report.results:
            if r.is_interesting:
                print(f"{r.payload}: {r.anomalies}")
    """
    
    def __init__(
        self,
        history: History = None,
        timeout: float = 30.0,
        delay: float = 1.0,
    ):
        self.history = history
        self.repeater = Repeater(
            history=history,
            timeout=timeout,
            delay=delay,
        )
    
    def attack(
        self,
        request: Request = None,
        request_id: int = None,
        param: str = None,
        payloads: List[str] = None,
        stop_on: str = None,
        max_errors: int = 3,
        callback: Callable[[AttackResult], bool] = None,
    ) -> AttackReport:
        """
        批量测试
        
        Args:
            request: Request 对象
            request_id: 从 History 获取请求
            param: 要测试的参数名
            payloads: payload 列表
            stop_on: 停止条件
                - "anomaly": 发现任何异常就停
                - "error": 发现数据库错误就停
                - "reflect": 发现反射就停
                - "block": 被拦截就停
                - None: 不停，测完所有
            max_errors: 连续错误多少次后停止
            callback: 每个结果的回调，返回 False 停止
        
        Returns:
            AttackReport
        """
        # 获取请求
        if request_id and self.history:
            request = self.history.get(request_id)
        
        if not request:
            return AttackReport(
                request_id=request_id or 0,
                param=param or "",
                total=0,
                tested=0,
                stopped=True,
                stop_reason="Request not found",
            )
        
        if not param:
            return AttackReport(
                request_id=request.id or 0,
                param="",
                total=0,
                tested=0,
                stopped=True,
                stop_reason="No param specified",
            )
        
        if not payloads:
            return AttackReport(
                request_id=request.id or 0,
                param=param,
                total=0,
                tested=0,
                stopped=True,
                stop_reason="No payloads provided",
            )
        
        # 获取基线
        baseline = self.repeater.send(request)
        
        report = AttackReport(
            request_id=request.id or 0,
            param=param,
            total=len(payloads),
            tested=0,
            baseline_status=baseline.status,
            baseline_length=baseline.length,
            baseline_time=baseline.time_ms,
        )
        
        # 批量测试
        consecutive_errors = 0
        consecutive_blocks = 0
        
        for i, payload in enumerate(payloads):
            # 发送测试请求
            modified = request.with_param(param, payload)
            resp = self.repeater.send(modified)
            
            # 构建结果
            result = AttackResult(
                payload=payload,
                status=resp.status,
                length=resp.length,
                time_ms=resp.time_ms,
                anomalies=resp.anomalies,
                reflects=payload in resp.body,
                status_changed=resp.status != baseline.status,
                length_diff=resp.length - baseline.length,
                time_diff=resp.time_ms - baseline.time_ms,
            )
            
            report.results.append(result)
            report.tested = i + 1
            
            # 回调
            if callback and not callback(result):
                report.stopped = True
                report.stop_reason = "Stopped by callback"
                break
            
            # 检查停止条件
            should_stop, reason = self._check_stop(
                result, stop_on, consecutive_errors, consecutive_blocks, max_errors
            )
            
            if should_stop:
                report.stopped = True
                report.stop_reason = reason
                break
            
            # 更新连续计数
            if resp.status == 0:
                consecutive_errors += 1
            else:
                consecutive_errors = 0
            
            if "blocked" in resp.anomalies:
                consecutive_blocks += 1
                # 被拦截后增加延迟
                time.sleep(self.repeater.delay * 2)
            else:
                consecutive_blocks = 0
        
        return report
    
    def attack_multiple_params(
        self,
        request: Request = None,
        request_id: int = None,
        params: List[str] = None,
        payloads: List[str] = None,
        stop_on: str = "anomaly",
    ) -> Dict[str, AttackReport]:
        """
        测试多个参数
        返回 {param: report}
        """
        if request_id and self.history:
            request = self.history.get(request_id)
        
        if not request:
            return {}
        
        if not params:
            params = request.all_param_names
        
        results = {}
        for param in params:
            report = self.attack(
                request=request,
                param=param,
                payloads=payloads,
                stop_on=stop_on,
            )
            results[param] = report
            
            # 如果发现有趣的结果，可以提前返回让 AI 决定
            if report.has_findings:
                break
        
        return results
    
    def _check_stop(
        self,
        result: AttackResult,
        stop_on: str,
        consecutive_errors: int,
        consecutive_blocks: int,
        max_errors: int,
    ) -> tuple:
        """检查是否应该停止"""
        
        # 连续错误太多
        if consecutive_errors >= max_errors:
            return True, f"Too many consecutive errors ({consecutive_errors})"
        
        # 连续被拦截太多
        if consecutive_blocks >= 3:
            return True, "Blocked by WAF (3 consecutive blocks)"
        
        if not stop_on:
            return False, ""
        
        if stop_on == "anomaly" and result.is_interesting:
            return True, f"Found anomaly: {result.anomalies or 'interesting response'}"
        
        if stop_on == "error":
            error_types = ["mysql_error", "postgresql_error", "mssql_error", 
                         "oracle_error", "sqlite_error", "access_error", "sql_error"]
            if any(a in error_types for a in result.anomalies):
                return True, f"Found database error: {result.anomalies}"
        
        if stop_on == "reflect" and result.reflects:
            return True, "Payload reflected in response"
        
        if stop_on == "block" and "blocked" in result.anomalies:
            return True, "Request blocked"
        
        return False, ""
    
    # ==================== 给 AI 用的接口 ====================
    
    def quick_test(
        self,
        request_id: int,
        param: str,
        test_type: str = "sqli",
    ) -> Dict:
        """
        快速测试（内置 payload）
        
        Args:
            request_id: 请求 ID
            param: 参数名
            test_type: 测试类型 (sqli, xss, ssti, lfi)
        
        Returns:
            结构化结果给 AI
        """
        # 内置的快速测试 payload
        quick_payloads = {
            "sqli": [
                "'",
                "\"",
                "' OR '1'='1",
                "1 AND 1=1",
                "1 AND 1=2",
                "' AND '1'='1",
                "' AND '1'='2",
                "1; SELECT 1--",
                "' UNION SELECT NULL--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "{{7*7}}",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{7*7}",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd",
                "..\\..\\..\\windows\\win.ini",
            ],
        }
        
        payloads = quick_payloads.get(test_type, quick_payloads["sqli"])
        
        report = self.attack(
            request_id=request_id,
            param=param,
            payloads=payloads,
            stop_on="anomaly",
        )
        
        return report.to_dict()
    
    def close(self):
        self.repeater.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
