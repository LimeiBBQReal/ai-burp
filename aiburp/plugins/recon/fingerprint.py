"""
指纹识别插件

包装现有的 aiburp/fingerprint/ 模块
基于 Wappalyzer 指纹库
"""
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

# 尝试导入现有指纹模块
try:
    from ...fingerprint.detector import TechDetector, TechResult, TechMatch
    HAS_WAPPALYZER = True
except ImportError:
    HAS_WAPPALYZER = False


@dataclass
class Fingerprint:
    name: str
    version: str = ""
    category: str = ""
    confidence: float = 0.0


class FingerprintPlugin:
    """
    指纹识别插件
    
    使用 Wappalyzer 指纹库检测技术栈
    
    使用示例:
        fp = FingerprintPlugin()
        result = fp.detect("https://example.com")
        print(result["technologies"])
    """
    
    name = "fingerprint"
    description = "技术栈指纹识别 (Wappalyzer)"
    
    def __init__(self):
        self._detector = None
    
    @property
    def detector(self):
        if self._detector is None:
            if HAS_WAPPALYZER:
                self._detector = TechDetector()
            else:
                self._detector = None
        return self._detector
    
    def detect(self, url: str = None, response=None) -> Dict:
        """
        检测技术栈
        
        Args:
            url: 目标 URL
            response: 已有的响应对象 (可选)
        
        Returns:
            检测结果字典
        """
        results = {
            "url": url,
            "technologies": [],
            "categories": [],
            "fingerprints": [],
            "raw_headers": {},
            "error": None,
        }
        
        # 使用 Wappalyzer 检测
        if self.detector and url:
            try:
                tech_result = self.detector.detect(url)
                
                results["technologies"] = tech_result.tech_names
                results["categories"] = tech_result.category_names
                results["raw_headers"] = tech_result.headers
                
                for t in tech_result.technologies:
                    results["fingerprints"].append(Fingerprint(
                        name=t.name,
                        version=t.version,
                        category=", ".join(t.categories),
                        confidence=t.confidence / 100.0,
                    ))
                
                if tech_result.error:
                    results["error"] = tech_result.error
                    
            except Exception as e:
                results["error"] = str(e)
        
        # 如果没有 Wappalyzer，使用简化检测
        elif response:
            results = self._simple_detect(response)
        
        return results
    
    def detect_from_response(self, url: str, headers: Dict, body: str) -> Dict:
        """从已有响应检测"""
        if self.detector:
            try:
                tech_result = self.detector.detect_from_response(url, headers, body)
                return {
                    "url": url,
                    "technologies": tech_result.tech_names,
                    "categories": tech_result.category_names,
                    "fingerprints": [
                        Fingerprint(name=t.name, version=t.version, 
                                   category=", ".join(t.categories),
                                   confidence=t.confidence / 100.0)
                        for t in tech_result.technologies
                    ],
                }
            except Exception as e:
                return {"url": url, "error": str(e), "technologies": []}
        
        return self._simple_detect_from_data(headers, body)
    
    def _simple_detect(self, response) -> Dict:
        """简化检测 (无 Wappalyzer 时使用)"""
        results = {"fingerprints": [], "technologies": []}
        
        if not response:
            return results
        
        headers_str = str(response.headers).lower() if response.headers else ""
        body = response.body.lower() if response.body else ""
        
        # 简单签名
        SIGNATURES = {
            "nginx": {"headers": ["nginx"]},
            "apache": {"headers": ["apache"]},
            "iis": {"headers": ["iis", "asp.net"]},
            "php": {"headers": ["x-powered-by: php"]},
            "wordpress": {"body": ["wp-content", "wp-includes"]},
            "drupal": {"body": ["drupal"]},
            "laravel": {"headers": ["laravel_session"]},
            "django": {"headers": ["csrftoken"]},
            "react": {"body": ["react", "data-reactroot"]},
            "vue": {"body": ["vue.js", "v-cloak"]},
            "angular": {"body": ["ng-version", "ng-app"]},
            "jquery": {"body": ["jquery"]},
            "cloudflare": {"headers": ["cf-ray"]},
        }
        
        for tech, sigs in SIGNATURES.items():
            confidence = 0.0
            for h in sigs.get("headers", []):
                if h in headers_str:
                    confidence += 0.5
            for b in sigs.get("body", []):
                if b in body:
                    confidence += 0.3
            
            if confidence > 0:
                results["fingerprints"].append(Fingerprint(name=tech, confidence=min(confidence, 1.0)))
                results["technologies"].append(tech)
        
        return results
    
    def _simple_detect_from_data(self, headers: Dict, body: str) -> Dict:
        """从数据简化检测"""
        class MockResponse:
            def __init__(self, h, b):
                self.headers = h
                self.body = b
        
        return self._simple_detect(MockResponse(headers, body))
    
    def detect_version(self, tech: str, response) -> str:
        """检测特定技术的版本"""
        patterns = {
            "nginx": r"nginx/(\d+\.\d+\.\d+)",
            "apache": r"Apache/(\d+\.\d+\.\d+)",
            "php": r"PHP/(\d+\.\d+\.\d+)",
            "jquery": r"jquery[.-](\d+\.\d+\.\d+)",
            "bootstrap": r"bootstrap[.-](\d+\.\d+\.\d+)",
        }
        
        if tech.lower() in patterns and response:
            text = str(response.headers) + (response.body or "")
            match = re.search(patterns[tech.lower()], text, re.I)
            if match:
                return match.group(1)
        return ""
    
    def batch_detect(self, urls: List[str], threads: int = 5) -> List[Dict]:
        """批量检测"""
        if self.detector:
            results = self.detector.batch_detect(urls, threads)
            return [
                {
                    "url": r.url,
                    "technologies": r.tech_names,
                    "categories": r.category_names,
                    "error": r.error,
                }
                for r in results
            ]
        
        # 无 Wappalyzer 时串行检测
        return [self.detect(url) for url in urls]
