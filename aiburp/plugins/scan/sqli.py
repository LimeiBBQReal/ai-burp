"""SQL 注入检测插件 - 支持全部 13 个字典"""
import re
import time
from typing import Dict, List, Optional
from .. import ScanPlugin, PluginResult
from ...core.models import Request, Finding as CoreFinding
from ...core.repeater import Repeater
from ...core.payload_loader import get_loader


def make_finding(vuln_type: str, confidence: str, evidence: str, payload: str,
                 param: str, request: Request, details: Dict = None) -> CoreFinding:
    return CoreFinding(
        type=vuln_type, confidence=confidence, title=f"{vuln_type.upper()} in {param}",
        description=evidence, url=request.url, method=request.method,
        param=param, payload=payload, request=request.to_raw(), evidence=evidence,
    )


class SQLiPlugin(ScanPlugin):
    """SQL 注入检测 - 支持全部字典"""
    
    name = "sqli"
    description = "SQL 注入检测"
    
    # 支持的所有字典 (对应 payloads/sqli/ 下的文件)
    DICT_MAP = {
        "quick": "quick",              # 快速检测 (7)
        "detection": "detection",      # 基础检测 (186)
        "auth_bypass": "auth_bypass",  # 登录绕过 (167)
        "time_based": "time_based",    # 时间盲注 (135)
        "error_based": "error_based",  # 报错注入 (81)
        "union": "union",              # UNION注入 (36)
        "stacked": "stacked",          # 堆叠查询 (17)
        "oob": "oob",                  # 外带注入 (14)
        "waf_bypass": "waf_bypass",    # WAF绕过 (131)
        "no_space": "no_space",        # 无空格 (20)
        "no_quotes": "no_quotes",      # 无引号 (15)
        "no_comma": "no_comma",        # 无逗号 (15)
        "exotic": "exotic",            # 特殊技巧 (155)
        "payloadbox": "payloadbox_generic",  # PayloadBox Generic SQLi (200+)
    }
    
    methods = list(DICT_MAP.keys()) + ["all"]
    
    ERROR_PATTERNS = {
        "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"You have an error in your SQL syntax"],
        "mssql": [r"Microsoft.*ODBC", r"SQL Server", r"Unclosed quotation mark"],
        "postgresql": [r"PostgreSQL.*ERROR", r"pg_query", r"ERROR:\s+syntax error"],
        "oracle": [r"ORA-\d{5}", r"Oracle.*Driver"],
        "sqlite": [r"SQLite.*error", r"sqlite3_"],
        "generic": [r"syntax error", r"query failed"],
    }
    
    def __init__(self):
        self.repeater = Repeater()
        self.loader = get_loader()
        self.delay = 0.3
        self.time_threshold = 2500
    
    def get_payloads(self, method: str = "quick") -> List[str]:
        """获取指定字典的 payload"""
        if method == "all":
            return self.loader.load_merged("sqli")
        dict_name = self.DICT_MAP.get(method, "quick")
        return self.loader.load("sqli", dict_name)
    
    def test(self, request: Request, param: str, method: str = "quick", **options) -> PluginResult:
        findings = []
        data = {"method": method, "payloads_tested": 0}
        
        try:
            payloads = self.get_payloads(method)
            max_payloads = options.get("max_payloads", 50)
            
            baseline = self._get_baseline(request)
            
            for payload in payloads[:max_payloads]:
                data["payloads_tested"] += 1
                test_request = request.with_param(param, payload)
                result = self.repeater.send(test_request)
                
                if not result["success"]:
                    continue
                
                body = result["response"].get("body", "")
                time_ms = result["response"].get("time_ms", 0)
                
                # 检测数据库错误
                db_type = self._detect_db_error(body)
                if db_type:
                    findings.append(make_finding("sqli_error", "confirmed",
                        f"{db_type} error detected", payload, param, test_request))
                    break
                
                # 检测时间延迟
                if time_ms > baseline["time_ms"] + self.time_threshold:
                    findings.append(make_finding("sqli_time", "likely",
                        f"Time delay {time_ms - baseline['time_ms']:.0f}ms", payload, param, test_request))
                    break
                
                time.sleep(self.delay)
            
            return PluginResult(success=True, findings=findings, data=data)
        except Exception as e:
            return PluginResult(success=False, findings=findings, data=data, error=str(e))
    
    def _get_baseline(self, request: Request) -> Dict:
        result = self.repeater.send(request)
        if result["success"]:
            return {"time_ms": result["response"].get("time_ms", 0), "length": result["response"].get("length", 0)}
        return {"time_ms": 0, "length": 0}
    
    def _detect_db_error(self, body: str) -> Optional[str]:
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.I):
                    return db_type
        return None
