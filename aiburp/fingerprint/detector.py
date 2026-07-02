"""
技术栈检测器

基于 Wappalyzer 指纹库检测网站技术栈
"""

import re
import requests
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse
from .wappalyzer import WappalyzerDB, Technology


@dataclass
class TechMatch:
    """技术匹配结果"""
    name: str
    version: str = ""
    confidence: int = 100
    categories: List[str] = field(default_factory=list)
    match_type: str = ""  # header, cookie, html, meta, script, url
    match_detail: str = ""


@dataclass
class TechResult:
    """检测结果"""
    url: str
    technologies: List[TechMatch] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    error: str = ""
    
    @property
    def tech_names(self) -> List[str]:
        """技术名称列表"""
        return [t.name for t in self.technologies]
    
    @property
    def category_names(self) -> List[str]:
        """分类名称列表"""
        cats = set()
        for t in self.technologies:
            cats.update(t.categories)
        return list(cats)
    
    def has_tech(self, name: str) -> bool:
        """是否包含指定技术"""
        return name.lower() in [t.name.lower() for t in self.technologies]
    
    def get_version(self, name: str) -> Optional[str]:
        """获取技术版本"""
        for t in self.technologies:
            if t.name.lower() == name.lower() and t.version:
                return t.version
        return None
    
    def to_dict(self) -> Dict:
        """转为字典"""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "technologies": [
                {
                    "name": t.name,
                    "version": t.version,
                    "categories": t.categories,
                    "confidence": t.confidence
                }
                for t in self.technologies
            ],
            "headers": self.headers,
            "error": self.error
        }
    
    def __str__(self) -> str:
        if self.error:
            return f"❌ {self.url}: {self.error}"
        
        techs = []
        for t in self.technologies:
            if t.version:
                techs.append(f"{t.name} {t.version}")
            else:
                techs.append(t.name)
        
        return f"[{self.status_code}] {self.url}\n  技术栈: {', '.join(techs) if techs else '未识别'}"


class TechDetector:
    """技术栈检测器"""
    
    def __init__(self, db_path: str = None, timeout: int = 10):
        self.db = WappalyzerDB(db_path)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
    
    def detect(self, url: str, follow_redirects: bool = True) -> TechResult:
        """
        检测网站技术栈
        
        Args:
            url: 目标 URL
            follow_redirects: 是否跟随重定向
        
        Returns:
            TechResult 检测结果
        """
        result = TechResult(url=url)
        
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=follow_redirects
            )
            
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.cookies = {c.name: c.value for c in resp.cookies}
            
            # 检测技术
            matches = self._analyze(resp)
            
            # 解析 implies (依赖关系)
            all_matches = self._resolve_implies(matches)
            
            result.technologies = all_matches
            
        except requests.exceptions.Timeout:
            result.error = "请求超时"
        except requests.exceptions.ConnectionError:
            result.error = "连接失败"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def detect_from_response(self, url: str, headers: Dict, body: str, 
                             cookies: Dict = None) -> TechResult:
        """
        从已有响应检测技术栈
        
        Args:
            url: URL
            headers: 响应头
            body: 响应体
            cookies: Cookie
        
        Returns:
            TechResult 检测结果
        """
        result = TechResult(url=url)
        result.headers = headers
        result.cookies = cookies or {}
        
        # 构造模拟响应
        class MockResponse:
            def __init__(self, url, headers, text, cookies):
                self.url = url
                self.headers = headers
                self.text = text
                self.cookies = type('Cookies', (), {'items': lambda: cookies.items()})()
        
        mock_resp = MockResponse(url, headers, body, result.cookies)
        
        matches = self._analyze(mock_resp)
        all_matches = self._resolve_implies(matches)
        result.technologies = all_matches
        
        return result
    
    def _analyze(self, resp) -> List[TechMatch]:
        """分析响应"""
        matches = []
        
        for name, tech in self.db.technologies.items():
            match = self._match_tech(tech, resp)
            if match:
                matches.append(match)
        
        return matches
    
    def _match_tech(self, tech: Technology, resp) -> Optional[TechMatch]:
        """匹配单个技术"""
        matched = False
        version = ""
        match_type = ""
        match_detail = ""
        
        # 1. 检查 Headers
        for header_name, pattern in tech.headers.items():
            header_value = resp.headers.get(header_name, "")
            if header_value:
                if not pattern:
                    matched = True
                    match_type = "header"
                    match_detail = f"{header_name}: {header_value[:50]}"
                else:
                    try:
                        m = re.search(pattern, header_value, re.IGNORECASE)
                        if m:
                            matched = True
                            match_type = "header"
                            match_detail = f"{header_name}: {header_value[:50]}"
                            if m.groups():
                                version = m.group(1) or ""
                    except:
                        pass
        
        # 2. 检查 Cookies
        if not matched:
            cookies = {}
            if hasattr(resp, 'cookies'):
                try:
                    cookies = {c.name: c.value for c in resp.cookies}
                except:
                    try:
                        cookies = dict(resp.cookies.items())
                    except:
                        pass
            
            for cookie_name, pattern in tech.cookies.items():
                if cookie_name in cookies:
                    matched = True
                    match_type = "cookie"
                    match_detail = f"Cookie: {cookie_name}"
                    break
        
        # 3. 检查 HTML
        if not matched and hasattr(resp, 'text'):
            html = resp.text
            for pattern in tech.html:
                try:
                    m = re.search(pattern, html, re.IGNORECASE)
                    if m:
                        matched = True
                        match_type = "html"
                        match_detail = f"HTML pattern: {pattern[:30]}..."
                        if m.groups():
                            version = m.group(1) or ""
                        break
                except:
                    pass
        
        # 4. 检查 Meta 标签
        if not matched and hasattr(resp, 'text'):
            html = resp.text
            for meta_name, pattern in tech.meta.items():
                # 查找 meta 标签
                meta_pattern = rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']+)["\']'
                try:
                    m = re.search(meta_pattern, html, re.IGNORECASE)
                    if m:
                        content = m.group(1)
                        if not pattern:
                            matched = True
                            match_type = "meta"
                            match_detail = f"Meta {meta_name}: {content[:30]}"
                        else:
                            m2 = re.search(pattern, content, re.IGNORECASE)
                            if m2:
                                matched = True
                                match_type = "meta"
                                match_detail = f"Meta {meta_name}: {content[:30]}"
                                if m2.groups():
                                    version = m2.group(1) or ""
                except:
                    pass
        
        # 5. 检查 Scripts
        if not matched and hasattr(resp, 'text'):
            html = resp.text
            for pattern in tech.scripts:
                try:
                    # 查找 script src
                    script_pattern = rf'<script[^>]+src=["\']([^"\']*{pattern}[^"\']*)["\']'
                    m = re.search(script_pattern, html, re.IGNORECASE)
                    if m:
                        matched = True
                        match_type = "script"
                        match_detail = f"Script: {m.group(1)[:50]}"
                        # 尝试提取版本
                        vm = re.search(pattern, m.group(1), re.IGNORECASE)
                        if vm and vm.groups():
                            version = vm.group(1) or ""
                        break
                except:
                    pass
        
        # 6. 检查 URL
        if not matched:
            for pattern in tech.url:
                try:
                    if re.search(pattern, resp.url, re.IGNORECASE):
                        matched = True
                        match_type = "url"
                        match_detail = f"URL pattern: {pattern}"
                        break
                except:
                    pass
        
        if matched:
            categories = [self.db.get_category_name(c) for c in tech.categories]
            return TechMatch(
                name=tech.name,
                version=version,
                categories=categories,
                match_type=match_type,
                match_detail=match_detail
            )
        
        return None
    
    def _resolve_implies(self, matches: List[TechMatch]) -> List[TechMatch]:
        """解析依赖关系"""
        all_names = {m.name for m in matches}
        result = list(matches)
        
        # 迭代解析 implies
        changed = True
        while changed:
            changed = False
            for match in list(result):
                tech = self.db.get_tech(match.name)
                if tech:
                    for implied in tech.implies:
                        if implied not in all_names:
                            implied_tech = self.db.get_tech(implied)
                            if implied_tech:
                                categories = [self.db.get_category_name(c) for c in implied_tech.categories]
                                result.append(TechMatch(
                                    name=implied,
                                    categories=categories,
                                    confidence=50,
                                    match_type="implied",
                                    match_detail=f"Implied by {match.name}"
                                ))
                                all_names.add(implied)
                                changed = True
        
        return result
    
    def batch_detect(self, urls: List[str], threads: int = 5) -> List[TechResult]:
        """
        批量检测
        
        Args:
            urls: URL 列表
            threads: 线程数
        
        Returns:
            检测结果列表
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.detect, url): url for url in urls}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    url = futures[future]
                    results.append(TechResult(url=url, error=str(e)))
        
        return results
    
    def report(self, results: List[TechResult]) -> str:
        """生成报告"""
        lines = ["=" * 60, "🔍 技术栈检测报告", "=" * 60, ""]
        
        # 统计
        tech_count = {}
        for r in results:
            for t in r.technologies:
                tech_count[t.name] = tech_count.get(t.name, 0) + 1
        
        lines.append(f"📊 扫描目标: {len(results)} 个")
        lines.append(f"📊 识别技术: {len(tech_count)} 种")
        lines.append("")
        
        # 技术统计
        if tech_count:
            lines.append("🏷️ 技术分布:")
            for tech, count in sorted(tech_count.items(), key=lambda x: -x[1])[:15]:
                lines.append(f"  {tech}: {count}")
            lines.append("")
        
        # 详细结果
        lines.append("📋 详细结果:")
        for r in results:
            lines.append(str(r))
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


# 命令行入口
if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("用法: python detector.py <url>")
        print("      python detector.py <url1> <url2> ...")
        sys.exit(1)
    
    detector = TechDetector()
    
    if len(sys.argv) == 2:
        result = detector.detect(sys.argv[1])
        print(result)
        print()
        print("详细信息:")
        for t in result.technologies:
            print(f"  - {t.name}")
            if t.version:
                print(f"    版本: {t.version}")
            print(f"    分类: {', '.join(t.categories)}")
            print(f"    匹配: {t.match_type} - {t.match_detail}")
    else:
        results = detector.batch_detect(sys.argv[1:])
        print(detector.report(results))
