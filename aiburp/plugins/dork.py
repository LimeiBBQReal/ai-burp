"""
AI-Burp Dork 搜索模块

支持:
- Google Dorks 生成
- Shodan 搜索 (需要 API Key)
- Fofa 搜索 (需要 API Key)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import os


@dataclass
class DorkResult:
    """Dork 搜索结果"""
    engine: str
    query: str
    results: List[Dict] = field(default_factory=list)
    total: int = 0
    error: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "engine": self.engine,
            "query": self.query,
            "results": self.results,
            "total": self.total,
            "error": self.error
        }


class DorkSearcher:
    """Dork 搜索器"""
    
    # Google Dork 模板
    GOOGLE_DORKS = {
        "admin_login": [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:login',
            'site:{domain} inurl:wp-admin',
            'site:{domain} inurl:administrator',
            'site:{domain} intitle:"admin" OR intitle:"login"',
        ],
        "sensitive_files": [
            'site:{domain} ext:sql OR ext:db OR ext:mdb',
            'site:{domain} ext:log',
            'site:{domain} ext:conf OR ext:config',
            'site:{domain} ext:bak OR ext:backup',
            'site:{domain} ext:env',
        ],
        "exposed_docs": [
            'site:{domain} ext:pdf OR ext:doc OR ext:xls',
            'site:{domain} filetype:pdf "confidential"',
            'site:{domain} filetype:xls "password"',
        ],
        "api_endpoints": [
            'site:{domain} inurl:api',
            'site:{domain} inurl:v1 OR inurl:v2',
            'site:{domain} inurl:graphql',
            'site:{domain} inurl:swagger OR inurl:api-docs',
        ],
        "error_pages": [
            'site:{domain} "error" OR "exception" OR "warning"',
            'site:{domain} "sql syntax" OR "mysql" OR "postgresql"',
            'site:{domain} "stack trace" OR "traceback"',
        ],
    }
    
    def __init__(self):
        self.shodan_key = os.getenv("SHODAN_API_KEY", "")
        self.fofa_email = os.getenv("FOFA_EMAIL", "")
        self.fofa_key = os.getenv("FOFA_API_KEY", "")
    
    def generate_google_dorks(self, domain: str, category: str = None) -> List[str]:
        """生成 Google Dorks"""
        dorks = []
        
        if category and category in self.GOOGLE_DORKS:
            templates = self.GOOGLE_DORKS[category]
        else:
            # 所有分类
            templates = []
            for cat_dorks in self.GOOGLE_DORKS.values():
                templates.extend(cat_dorks)
        
        for template in templates:
            dorks.append(template.format(domain=domain))
        
        return dorks
    
    def shodan_search(self, query: str, limit: int = 100) -> DorkResult:
        """Shodan 搜索"""
        if not self.shodan_key:
            return DorkResult(
                engine="shodan",
                query=query,
                error="未配置 SHODAN_API_KEY 环境变量"
            )
        
        try:
            import httpx
            
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                "key": self.shodan_key,
                "query": query,
                "limit": limit
            }
            
            r = httpx.get(url, params=params, timeout=30)
            data = r.json()
            
            if "error" in data:
                return DorkResult(
                    engine="shodan",
                    query=query,
                    error=data["error"]
                )
            
            results = []
            for match in data.get("matches", []):
                results.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "hostnames": match.get("hostnames", []),
                    "product": match.get("product"),
                    "version": match.get("version"),
                })
            
            return DorkResult(
                engine="shodan",
                query=query,
                results=results,
                total=data.get("total", len(results))
            )
            
        except Exception as e:
            return DorkResult(
                engine="shodan",
                query=query,
                error=str(e)
            )
    
    def fofa_search(self, query: str, limit: int = 100) -> DorkResult:
        """Fofa 搜索"""
        if not self.fofa_email or not self.fofa_key:
            return DorkResult(
                engine="fofa",
                query=query,
                error="未配置 FOFA_EMAIL 和 FOFA_API_KEY 环境变量"
            )
        
        try:
            import httpx
            import base64
            
            url = "https://fofa.info/api/v1/search/all"
            params = {
                "email": self.fofa_email,
                "key": self.fofa_key,
                "qbase64": base64.b64encode(query.encode()).decode(),
                "size": limit
            }
            
            r = httpx.get(url, params=params, timeout=30)
            data = r.json()
            
            if data.get("error"):
                return DorkResult(
                    engine="fofa",
                    query=query,
                    error=data.get("errmsg", "Unknown error")
                )
            
            results = []
            for item in data.get("results", []):
                if len(item) >= 3:
                    results.append({
                        "host": item[0],
                        "ip": item[1],
                        "port": item[2] if len(item) > 2 else "",
                    })
            
            return DorkResult(
                engine="fofa",
                query=query,
                results=results,
                total=data.get("size", len(results))
            )
            
        except Exception as e:
            return DorkResult(
                engine="fofa",
                query=query,
                error=str(e)
            )
    
    def report(self, result: DorkResult) -> str:
        """生成报告"""
        lines = [
            "=" * 60,
            f"🔍 {result.engine.upper()} 搜索结果",
            "=" * 60,
            f"查询: {result.query}",
            f"结果: {result.total} 条",
            ""
        ]
        
        if result.error:
            lines.append(f"❌ 错误: {result.error}")
        elif result.results:
            for i, r in enumerate(result.results[:20], 1):
                if result.engine == "shodan":
                    lines.append(f"  {i}. {r['ip']}:{r['port']}")
                    if r.get('org'):
                        lines.append(f"     组织: {r['org']}")
                    if r.get('product'):
                        lines.append(f"     产品: {r['product']} {r.get('version', '')}")
                else:
                    lines.append(f"  {i}. {r['host']}")
                    lines.append(f"     IP: {r['ip']}:{r['port']}")
                lines.append("")
            
            if len(result.results) > 20:
                lines.append(f"  ... 还有 {len(result.results) - 20} 条结果")
        else:
            lines.append("⚠️ 无结果")
        
        lines.append("=" * 60)
        return "\n".join(lines)
