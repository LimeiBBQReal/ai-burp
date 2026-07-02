"""
目录/参数发现插件

所有发现的路径都记录到 History，payload 从字典加载
"""

from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import requests
import urllib3
urllib3.disable_warnings()

from ...plugins import AuxPlugin, PluginResult
from ...core.history import History
from ...core.models import Request, Response
from ...core.payload_loader import get_loader


class DiscoveryPlugin(AuxPlugin):
    """目录发现插件 - 支持全部 7 个 discovery 字典"""
    
    name = "discovery"
    description = "目录/文件发现，流量记录到History"
    
    # 支持的所有字典 (对应 payloads/discovery/ 下的文件)
    DICT_MAP = {
        "quick": "dirs_quick",           # 快速扫描 (30)
        "common": "dirs_common",         # 常见目录 (139)
        "medium": "dirs_medium",         # 中等字典 (355)
        "asp": "dirs_asp",               # ASP目录 (185)
        "sensitive": "dirs_sensitive",   # 敏感文件 (216)
        "api": "api_endpoints",          # API端点 (223)
        "swagger": "swagger_docs",       # Swagger文档 (40)
    }
    
    def __init__(self, history: History = None):
        self.history = history
        self.loader = get_loader()
    
    def _get_paths(self, wordlist: str = "quick") -> List[str]:
        """从字典加载路径"""
        if wordlist == "all":
            return self.loader.load_merged("discovery")
        name = self.DICT_MAP.get(wordlist, "dirs_quick")
        return self.loader.load("discovery", name)
    
    def execute(self, url: str = "", wordlist: str = "quick",
                extensions: List[str] = None, threads: int = 10, **kwargs) -> PluginResult:
        if not url:
            return PluginResult(success=False, error="URL is required")
        
        paths = self._get_paths(wordlist)
        if not paths:
            return PluginResult(success=False, error=f"Wordlist '{wordlist}' not found")
        
        if extensions:
            extended = []
            for path in paths:
                extended.append(path)
                if "." not in path:
                    for ext in extensions:
                        extended.append(f"{path}{ext}")
            paths = extended
        
        base_url = url.rstrip("/")
        results = {"found": [], "auth_required": [], "forbidden": [], "sensitive": []}
        
        # 获取 404 基线
        try:
            resp_404 = requests.get(f"{base_url}/nonexistent_12345", timeout=10, verify=False)
            baseline_404_len = len(resp_404.text) if resp_404.status_code == 404 else 0
        except:
            baseline_404_len = 0
        
        def test_path(path: str) -> Optional[Dict]:
            test_url = f"{base_url}/{path.lstrip('/')}"
            try:
                resp = requests.get(test_url, headers={"User-Agent": "Mozilla/5.0"},
                                    timeout=10, verify=False, allow_redirects=False)
                
                if resp.status_code == 404:
                    return None
                
                if resp.status_code == 200 and baseline_404_len > 0:
                    if abs(len(resp.text) - baseline_404_len) < 50:
                        return None
                
                if self.history:
                    req = Request(method="GET", url=test_url, headers={"User-Agent": "Mozilla/5.0"})
                    req.response = Response(status=resp.status_code, headers=dict(resp.headers),
                                            body=resp.text[:5000], time_ms=resp.elapsed.total_seconds() * 1000)
                    req.tags = ["recon", "discovery"]
                    self.history.add(req)
                
                title = ""
                match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
                if match:
                    title = match.group(1).strip()[:50]
                
                return {
                    "path": path, "url": test_url, "status": resp.status_code,
                    "length": len(resp.text), "title": title,
                    "server": resp.headers.get("Server", ""),
                    "redirect": resp.headers.get("Location", ""),
                }
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(test_path, p): p for p in paths}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    status = result["status"]
                    if status == 200:
                        results["found"].append(result)
                    elif status == 401:
                        results["auth_required"].append(result)
                    elif status == 403:
                        results["forbidden"].append(result)
                    elif status in [301, 302]:
                        results["found"].append(result)
                    
                    if self._is_sensitive(result["path"]):
                        results["sensitive"].append(result)
        
        return PluginResult(
            success=True,
            data={
                "url": url, "paths_tested": len(paths),
                "found": results["found"], "auth_required": results["auth_required"],
                "forbidden": results["forbidden"], "sensitive": results["sensitive"],
            }
        )
    
    def _is_sensitive(self, path: str) -> bool:
        sensitive_patterns = [".git", ".svn", ".env", "config", "backup",
                             ".sql", ".bak", "admin", "phpinfo", "swagger"]
        path_lower = path.lower()
        return any(p in path_lower for p in sensitive_patterns)


class ParamDiscoverPlugin(AuxPlugin):
    """参数发现插件 - 支持全部 2 个 api 字典"""
    
    name = "param_discover"
    description = "隐藏参数发现"
    
    # 支持的所有字典 (对应 payloads/api/ 下的文件)
    DICT_MAP = {
        "common": "params_common",       # 常见参数 (251)
        "sensitive": "params_sensitive", # 敏感参数 (314)
    }
    
    def __init__(self, history: History = None):
        self.history = history
        self.loader = get_loader()
    
    def _get_params(self, wordlist: str = "common") -> List[str]:
        """从字典加载参数名"""
        if wordlist == "all":
            return self.loader.load_merged("api")
        name = self.DICT_MAP.get(wordlist, "params_common")
        return self.loader.load("api", name)
    
    def execute(self, url: str = "", method: str = "GET",
                params: List[str] = None, **kwargs) -> PluginResult:
        if not url:
            return PluginResult(success=False, error="URL is required")
        
        test_params = params or self._get_params("common")
        
        try:
            baseline = requests.request(method, url, headers={"User-Agent": "Mozilla/5.0"},
                                        timeout=10, verify=False)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception as e:
            return PluginResult(success=False, error=str(e))
        
        found_params = []
        
        for param in test_params:
            try:
                if method.upper() == "GET":
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}=test123"
                    resp = requests.get(test_url, headers={"User-Agent": "Mozilla/5.0"},
                                        timeout=10, verify=False)
                else:
                    resp = requests.post(url, data={param: "test123"},
                                         headers={"User-Agent": "Mozilla/5.0"},
                                         timeout=10, verify=False)
                
                if resp.status_code != baseline_status:
                    found_params.append({"param": param, "reason": f"状态码变化: {baseline_status} -> {resp.status_code}"})
                elif abs(len(resp.text) - baseline_len) > 100:
                    found_params.append({"param": param, "reason": f"响应大小变化: {baseline_len} -> {len(resp.text)}"})
                elif param.lower() in resp.text.lower() and param.lower() not in baseline.text.lower():
                    found_params.append({"param": param, "reason": "参数名出现在响应中"})
            except:
                pass
        
        return PluginResult(
            success=True,
            data={"url": url, "method": method, "params_tested": len(test_params), "found_params": found_params}
        )
