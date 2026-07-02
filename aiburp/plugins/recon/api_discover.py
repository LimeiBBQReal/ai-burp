"""API 自动发现插件 (Swagger/GraphQL/OpenAPI)"""
import re
import json
from typing import Dict, List
import requests
import urllib3
urllib3.disable_warnings()

from ...plugins import AuxPlugin, PluginResult
from ...core.payload_loader import get_loader


class APIDiscoverPlugin(AuxPlugin):
    """API 发现插件"""
    
    name = "api_discover"
    description = "API 发现 (Swagger/GraphQL/OpenAPI)"
    
    def __init__(self, history=None):
        self.history = history
        self.loader = get_loader()
    
    def _get_paths(self, api_type: str = "swagger") -> List[str]:
        """从字典加载 API 路径"""
        # 尝试加载 swagger_docs.txt
        paths = self.loader.load("discovery", "swagger_docs")
        if paths:
            return paths
        
        # 尝试加载 api_endpoints.txt
        paths = self.loader.load("discovery", "api_endpoints")
        if paths:
            return paths
        
        return []
    
    def execute(self, url: str = "", timeout: int = 5, **kwargs) -> PluginResult:
        if not url:
            return PluginResult(success=False, error="URL is required")
        
        results = self.discover(url, timeout)
        return PluginResult(success=True, data=results)
    
    def discover(self, base_url: str, timeout: int = 5) -> Dict:
        results = {"swagger": [], "graphql": [], "openapi_spec": None, "endpoints": []}
        base_url = base_url.rstrip("/")
        
        # 从字典加载路径
        swagger_paths = self._get_paths("swagger")
        
        # 如果字典为空，使用内置路径
        if not swagger_paths:
            swagger_paths = [
                "/swagger.json", "/swagger/v1/swagger.json", "/api/swagger.json",
                "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/api-docs.json",
                "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
                "/docs", "/redoc", "/.well-known/openapi.json",
            ]
        
        graphql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query", "/gql"]
        
        # Swagger/OpenAPI
        for path in swagger_paths:
            try:
                resp = requests.get(f"{base_url}{path}", timeout=timeout, verify=False)
                if resp.status_code == 200:
                    results["swagger"].append({"path": path, "status": 200})
                    if path.endswith(".json"):
                        try:
                            spec = resp.json()
                            results["openapi_spec"] = spec
                            results["endpoints"] = self._extract_endpoints(spec)
                        except:
                            pass
            except:
                pass
        
        # GraphQL
        for path in graphql_paths:
            try:
                resp = requests.get(f"{base_url}{path}", timeout=timeout, verify=False)
                if resp.status_code in [200, 400]:
                    results["graphql"].append({"path": path, "status": resp.status_code})
                
                intro = requests.post(f"{base_url}{path}",
                                      json={"query": "{__schema{types{name}}}"},
                                      timeout=timeout, verify=False)
                if intro.status_code == 200 and "__schema" in intro.text:
                    results["graphql"].append({"path": path, "introspection": True})
            except:
                pass
        
        return results
    
    def _extract_endpoints(self, spec: Dict) -> List[Dict]:
        endpoints = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    endpoints.append({
                        "path": path, "method": method.upper(),
                        "params": [p.get("name") for p in details.get("parameters", [])],
                        "summary": details.get("summary", "")
                    })
        return endpoints
    
    def introspect_graphql(self, url: str) -> Dict:
        query = '''{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name } } } } } }'''
        try:
            resp = requests.post(url, json={"query": query}, timeout=10, verify=False)
            if resp.status_code == 200:
                return resp.json()
        except:
            pass
        return {}
