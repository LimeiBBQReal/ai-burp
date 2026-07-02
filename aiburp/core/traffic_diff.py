"""
AIBURP TrafficDiff - 历史流量对比分析器

核心功能:
1. 对比同一 URL 的历史请求，发现参数变化
2. 发现隐藏参数和条件参数
3. 检测响应变化和异常
4. 跨端点分析，发现验证不一致

赏金猎人思维:
- 历史流量是金矿，隐藏着被遗忘的参数
- 不一致的参数可能是条件功能的入口
- 响应变化暗示不同的代码路径
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from urllib.parse import urlparse
from datetime import datetime

from .models import Request, Response


# ============================================================
# 数据模型
# ============================================================

@dataclass
class ParamVariation:
    """
    参数变化记录
    
    跟踪单个参数在历史请求中的变化情况
    """
    name: str
    variation_type: str  # new, removed, value_changed, observed
    first_seen: str  # timestamp
    last_seen: str  # timestamp
    values_seen: List[str] = field(default_factory=list)
    occurrence_count: int = 0
    total_requests: int = 0
    insight: str = ""
    
    @property
    def occurrence_rate(self) -> float:
        """出现率"""
        if self.total_requests == 0:
            return 0.0
        return self.occurrence_count / self.total_requests
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "variation_type": self.variation_type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "values_seen": self.values_seen,
            "occurrence_count": self.occurrence_count,
            "total_requests": self.total_requests,
            "occurrence_rate": self.occurrence_rate,
            "insight": self.insight,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class ResponseVariation:
    """
    响应变化记录
    
    跟踪响应在历史请求中的变化情况
    """
    variation_type: str  # length, status, new_field, error_change, timing
    details: Dict = field(default_factory=dict)
    first_seen: str = ""
    insight: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "variation_type": self.variation_type,
            "details": self.details,
            "first_seen": self.first_seen,
            "insight": self.insight,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class TrafficDiffResult:
    """
    流量对比结果
    
    包含对同一 URL 历史请求的完整分析
    """
    url: str
    total_requests: int
    time_range: Tuple[str, str] = ("", "")  # (earliest, latest)
    
    # 参数变化
    param_variations: List[ParamVariation] = field(default_factory=list)
    all_params_ever_seen: List[str] = field(default_factory=list)
    inconsistent_params: List[str] = field(default_factory=list)  # 有时出现有时不出现
    
    # 响应变化
    response_variations: List[ResponseVariation] = field(default_factory=list)
    
    # 时间线
    timeline: List[Dict] = field(default_factory=list)
    
    # 异常
    anomalies: List[Dict] = field(default_factory=list)
    
    # 利用建议
    exploitation_suggestions: List[str] = field(default_factory=list)
    
    # 赏金猎人洞察
    hunter_insights: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "total_requests": self.total_requests,
            "time_range": {
                "earliest": self.time_range[0],
                "latest": self.time_range[1],
            },
            "param_variations": [p.to_dict() for p in self.param_variations],
            "all_params_ever_seen": self.all_params_ever_seen,
            "inconsistent_params": self.inconsistent_params,
            "response_variations": [r.to_dict() for r in self.response_variations],
            "timeline": self.timeline,
            "anomalies": self.anomalies,
            "exploitation_suggestions": self.exploitation_suggestions,
            "hunter_insights": self.hunter_insights,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class CrossEndpointResult:
    """
    跨端点分析结果
    
    比较多个端点的参数使用情况，发现不一致
    """
    endpoints: List[str] = field(default_factory=list)
    
    # 参数差异
    params_only_in: Dict[str, List[str]] = field(default_factory=dict)  # endpoint -> params
    common_params: List[str] = field(default_factory=list)
    
    # 验证差异
    validation_differences: List[Dict] = field(default_factory=list)
    
    # 潜在问题
    potential_issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "endpoints": self.endpoints,
            "params_only_in": self.params_only_in,
            "common_params": self.common_params,
            "validation_differences": self.validation_differences,
            "potential_issues": self.potential_issues,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)



# ============================================================
# TrafficDiff 主类
# ============================================================

class TrafficDiff:
    """
    历史流量对比分析器
    
    核心功能:
    1. diff_by_url() - 对比同一 URL 的所有历史请求
    2. discover_hidden_params() - 发现隐藏参数
    3. find_anomalies() - 检测异常请求
    4. cross_endpoint_analysis() - 跨端点分析
    
    用法:
        diff = TrafficDiff(history)
        
        # 对比历史流量
        result = diff.diff_by_url("https://example.com/api/users")
        
        # 发现隐藏参数
        hidden = diff.discover_hidden_params("https://example.com/api/users")
        
        # 跨端点分析
        cross = diff.cross_endpoint_analysis(["/api/users", "/api/admin"])
    """
    
    def __init__(self, history=None):
        """
        初始化 TrafficDiff
        
        Args:
            history: History 实例，用于查询历史请求
        """
        self.history = history
    
    # ==================== 核心方法 ====================
    
    def diff_by_url(self, url: str) -> TrafficDiffResult:
        """
        对比同一 URL 的所有历史请求
        
        发现:
        1. 参数变化 (新增、删除、值模式变化)
        2. 响应变化 (长度、状态码、新字段、错误信息)
        3. 时间线分析
        4. 异常检测
        
        Args:
            url: 要分析的 URL
        
        Returns:
            TrafficDiffResult 包含完整分析结果
        """
        if not self.history:
            return TrafficDiffResult(url=url, total_requests=0)
        
        # 获取该 URL 的所有历史请求
        parsed = urlparse(url)
        requests = self.history.list(path=parsed.path, limit=1000)
        
        if not requests:
            return TrafficDiffResult(url=url, total_requests=0)
        
        # 按时间排序
        sorted_requests = sorted(requests, key=lambda r: r.timestamp or "")
        
        result = TrafficDiffResult(
            url=url,
            total_requests=len(requests),
            time_range=(
                sorted_requests[0].timestamp if sorted_requests else "",
                sorted_requests[-1].timestamp if sorted_requests else "",
            ),
        )
        
        # 分析参数变化
        result.param_variations = self._analyze_param_variations(sorted_requests)
        result.all_params_ever_seen = self._collect_all_params(sorted_requests)
        result.inconsistent_params = self._find_inconsistent_params(sorted_requests)
        
        # 分析响应变化
        result.response_variations = self._analyze_response_variations(sorted_requests)
        
        # 构建时间线
        result.timeline = self._build_timeline(sorted_requests)
        
        # 检测异常
        result.anomalies = self._detect_anomalies(sorted_requests)
        
        # 生成利用建议
        result.exploitation_suggestions = self._generate_exploitation_suggestions(result)
        
        # 生成赏金猎人洞察
        result.hunter_insights = self._generate_hunter_insights(result)
        
        return result
    
    def discover_hidden_params(self, url: str) -> Dict:
        """
        发现隐藏参数
        
        方法:
        1. 收集所有历史出现过的参数
        2. 识别不一致出现的参数 (条件参数)
        3. 基于相似端点建议参数
        4. 与 JS 分析交叉引用
        
        Args:
            url: 要分析的 URL
        
        Returns:
            包含隐藏参数发现结果的字典
        """
        result = {
            "all_params_seen": [],
            "inconsistent_params": [],
            "suggested_from_similar": [],
            "unreferenced_in_js": [],
            "recommendations": [],
        }
        
        if not self.history:
            return result
        
        # 获取历史请求
        parsed = urlparse(url)
        requests = self.history.list(path=parsed.path, limit=1000)
        
        if not requests:
            return result
        
        # 1. 收集所有参数
        all_params: Set[str] = set()
        param_occurrence: Dict[str, int] = {}
        
        for req in requests:
            params = set(req.params.keys()) | set(req.body_params.keys())
            all_params.update(params)
            for p in params:
                param_occurrence[p] = param_occurrence.get(p, 0) + 1
        
        result["all_params_seen"] = list(all_params)
        
        # 2. 识别不一致参数 (出现率 < 80%)
        total = len(requests)
        for param, count in param_occurrence.items():
            rate = count / total if total > 0 else 0
            if 0 < rate < 0.8:
                result["inconsistent_params"].append({
                    "param": param,
                    "occurrence_rate": rate,
                    "occurrence_count": count,
                    "total_requests": total,
                    "insight": f"参数 {param} 只在 {count}/{total} ({rate*100:.1f}%) 个请求中出现，可能是条件参数"
                })
        
        # 3. 基于相似端点建议
        similar_endpoints = self._find_similar_endpoints(url)
        for endpoint in similar_endpoints:
            endpoint_params = self._get_endpoint_params(endpoint)
            new_params = endpoint_params - all_params
            if new_params:
                result["suggested_from_similar"].append({
                    "endpoint": endpoint,
                    "params": list(new_params),
                    "insight": f"相似端点 {endpoint} 使用了这些参数，当前端点可能也支持"
                })
        
        # 4. 生成建议
        result["recommendations"] = self._generate_param_recommendations(result)
        
        return result
    
    def find_anomalies(self, url: str) -> List[Dict]:
        """
        检测异常请求
        
        异常类型:
        1. 异常参数组合
        2. 意外响应数据
        3. 时间异常
        
        Args:
            url: 要分析的 URL
        
        Returns:
            异常列表
        """
        if not self.history:
            return []
        
        parsed = urlparse(url)
        requests = self.history.list(path=parsed.path, limit=1000)
        
        return self._detect_anomalies(requests)
    
    def cross_endpoint_analysis(self, endpoints: List[str]) -> CrossEndpointResult:
        """
        跨端点分析
        
        发现:
        1. 某端点有但其他端点没有的参数 (可能缺少验证)
        2. 相似端点的不同参数要求
        3. 不一致的验证
        
        Args:
            endpoints: 要分析的端点列表
        
        Returns:
            CrossEndpointResult 包含跨端点分析结果
        """
        result = CrossEndpointResult(endpoints=list(endpoints))
        
        if not self.history or not endpoints:
            return result
        
        # 收集每个端点的参数
        endpoint_params: Dict[str, Set[str]] = {}
        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            path = parsed.path or endpoint
            requests = self.history.list(path=path, limit=100)
            params: Set[str] = set()
            for req in requests:
                params.update(req.params.keys())
                params.update(req.body_params.keys())
            endpoint_params[endpoint] = params
        
        # 找出每个端点独有的参数
        all_params: Set[str] = set()
        for params in endpoint_params.values():
            all_params.update(params)
        
        for endpoint, params in endpoint_params.items():
            other_params: Set[str] = set()
            for e, p in endpoint_params.items():
                if e != endpoint:
                    other_params.update(p)
            unique = params - other_params
            if unique:
                result.params_only_in[endpoint] = list(unique)
        
        # 找出公共参数
        if endpoint_params:
            param_sets = list(endpoint_params.values())
            if param_sets:
                common = param_sets[0].copy()
                for ps in param_sets[1:]:
                    common &= ps
                result.common_params = list(common)
        
        # 检测潜在问题
        auth_keywords = ["auth", "token", "user", "admin", "role", "permission", "session"]
        for endpoint, unique_params in result.params_only_in.items():
            for param in unique_params:
                param_lower = param.lower()
                if any(kw in param_lower for kw in auth_keywords):
                    result.potential_issues.append(
                        f"端点 {endpoint} 有认证参数 {param}，其他端点没有 - 可能存在越权"
                    )
        
        return result

    # ==================== 参数分析方法 ====================
    
    def _analyze_param_variations(self, requests: List[Request]) -> List[ParamVariation]:
        """
        分析参数变化
        
        Args:
            requests: 按时间排序的请求列表
        
        Returns:
            参数变化列表
        """
        if not requests:
            return []
        
        variations = []
        total = len(requests)
        
        # 跟踪参数首次和最后出现
        param_first_seen: Dict[str, str] = {}
        param_last_seen: Dict[str, str] = {}
        param_values: Dict[str, List[str]] = {}
        param_count: Dict[str, int] = {}
        
        for req in requests:
            all_params = {**req.params, **req.body_params}
            for name, value in all_params.items():
                # 首次出现
                if name not in param_first_seen:
                    param_first_seen[name] = req.timestamp or ""
                
                # 最后出现
                param_last_seen[name] = req.timestamp or ""
                
                # 值记录
                if name not in param_values:
                    param_values[name] = []
                str_value = str(value) if value is not None else ""
                if str_value not in param_values[name]:
                    param_values[name].append(str_value)
                
                # 出现次数
                param_count[name] = param_count.get(name, 0) + 1
        
        # 生成变化报告
        for name in param_first_seen:
            values = param_values.get(name, [])
            count = param_count.get(name, 0)
            
            # 确定变化类型
            if len(values) > 1:
                variation_type = "value_changed"
            elif count < total * 0.8:
                variation_type = "inconsistent"
            else:
                variation_type = "observed"
            
            variation = ParamVariation(
                name=name,
                variation_type=variation_type,
                first_seen=param_first_seen[name],
                last_seen=param_last_seen[name],
                values_seen=values[:10],  # 最多10个值
                occurrence_count=count,
                total_requests=total,
            )
            
            # 生成洞察
            if variation_type == "value_changed":
                variation.insight = f"参数 {name} 有 {len(values)} 种不同的值，可能是动态参数"
            elif variation_type == "inconsistent":
                rate = count / total * 100 if total > 0 else 0
                variation.insight = f"参数 {name} 只在 {rate:.1f}% 的请求中出现，可能是条件参数"
            
            variations.append(variation)
        
        return variations
    
    def _collect_all_params(self, requests: List[Request]) -> List[str]:
        """
        收集所有参数名
        
        Args:
            requests: 请求列表
        
        Returns:
            所有参数名列表
        """
        all_params: Set[str] = set()
        for req in requests:
            all_params.update(req.params.keys())
            all_params.update(req.body_params.keys())
        return list(all_params)
    
    def _find_inconsistent_params(self, requests: List[Request]) -> List[str]:
        """
        找出不一致出现的参数
        
        不一致参数: 出现率在 0% 到 80% 之间的参数
        
        Args:
            requests: 请求列表
        
        Returns:
            不一致参数名列表
        """
        if not requests:
            return []
        
        param_count: Dict[str, int] = {}
        total = len(requests)
        
        for req in requests:
            params = set(req.params.keys()) | set(req.body_params.keys())
            for p in params:
                param_count[p] = param_count.get(p, 0) + 1
        
        inconsistent = []
        for param, count in param_count.items():
            rate = count / total if total > 0 else 0
            if 0 < rate < 0.8:
                inconsistent.append(param)
        
        return inconsistent
    
    # ==================== 响应分析方法 ====================
    
    def _analyze_response_variations(self, requests: List[Request]) -> List[ResponseVariation]:
        """
        分析响应变化
        
        Args:
            requests: 请求列表
        
        Returns:
            响应变化列表
        """
        variations = []
        
        lengths: List[int] = []
        statuses: Set[int] = set()
        times: List[float] = []
        
        for req in requests:
            if req.response:
                lengths.append(req.response.length)
                statuses.add(req.response.status)
                if req.response.time_ms:
                    times.append(req.response.time_ms)
        
        # 长度变化
        if lengths:
            length_range = max(lengths) - min(lengths)
            if length_range > 100:
                variations.append(ResponseVariation(
                    variation_type="length",
                    details={
                        "min": min(lengths),
                        "max": max(lengths),
                        "range": length_range,
                        "avg": sum(lengths) / len(lengths),
                    },
                    insight=f"响应长度变化范围 {length_range} 字节，可能有不同的代码路径"
                ))
        
        # 状态码变化
        if len(statuses) > 1:
            variations.append(ResponseVariation(
                variation_type="status",
                details={"statuses": list(statuses)},
                insight=f"发现 {len(statuses)} 种不同的状态码: {sorted(statuses)}"
            ))
        
        # 时间变化
        if times:
            time_range = max(times) - min(times)
            avg_time = sum(times) / len(times)
            if time_range > avg_time * 0.5:  # 变化超过平均值的50%
                variations.append(ResponseVariation(
                    variation_type="timing",
                    details={
                        "min_ms": min(times),
                        "max_ms": max(times),
                        "avg_ms": avg_time,
                        "range_ms": time_range,
                    },
                    insight=f"响应时间变化较大 ({time_range:.0f}ms)，可能有不同的处理逻辑"
                ))
        
        return variations
    
    # ==================== 时间线和异常检测 ====================
    
    def _build_timeline(self, requests: List[Request]) -> List[Dict]:
        """
        构建时间线
        
        Args:
            requests: 按时间排序的请求列表
        
        Returns:
            时间线事件列表
        """
        timeline = []
        seen_params: Set[str] = set()
        
        for req in requests:
            current_params = set(req.params.keys()) | set(req.body_params.keys())
            
            # 新参数
            new_params = current_params - seen_params
            if new_params:
                timeline.append({
                    "timestamp": req.timestamp,
                    "event": "new_params",
                    "params": list(new_params),
                    "request_id": req.id,
                })
            
            # 消失的参数
            removed_params = seen_params - current_params
            if removed_params and seen_params:  # 只有在之前有参数时才记录
                timeline.append({
                    "timestamp": req.timestamp,
                    "event": "removed_params",
                    "params": list(removed_params),
                    "request_id": req.id,
                })
            
            seen_params.update(current_params)
        
        return timeline
    
    def _detect_anomalies(self, requests: List[Request]) -> List[Dict]:
        """
        检测异常
        
        Args:
            requests: 请求列表
        
        Returns:
            异常列表
        """
        anomalies = []
        
        if len(requests) < 3:
            return anomalies
        
        # 计算基线
        lengths = [req.response.length for req in requests if req.response]
        times = [req.response.time_ms for req in requests if req.response and req.response.time_ms]
        
        if not lengths:
            return anomalies
        
        avg_length = sum(lengths) / len(lengths)
        avg_time = sum(times) / len(times) if times else 0
        
        for req in requests:
            if not req.response:
                continue
            
            # 长度异常 (偏离平均值 50% 以上)
            if avg_length > 0 and abs(req.response.length - avg_length) > avg_length * 0.5:
                anomalies.append({
                    "type": "length_anomaly",
                    "request_id": req.id,
                    "url": req.url,
                    "expected": avg_length,
                    "actual": req.response.length,
                    "deviation": abs(req.response.length - avg_length) / avg_length * 100,
                    "insight": "响应长度异常，可能触发了不同的代码路径"
                })
            
            # 时间异常 (超过平均值 3 倍)
            if avg_time > 0 and req.response.time_ms and req.response.time_ms > avg_time * 3:
                anomalies.append({
                    "type": "timing_anomaly",
                    "request_id": req.id,
                    "url": req.url,
                    "expected": avg_time,
                    "actual": req.response.time_ms,
                    "multiplier": req.response.time_ms / avg_time,
                    "insight": "响应时间异常，可能存在时间盲注或不同处理逻辑"
                })
            
            # 响应异常检测
            if req.response.anomalies:
                anomalies.append({
                    "type": "response_anomaly",
                    "request_id": req.id,
                    "url": req.url,
                    "anomalies": req.response.anomalies,
                    "insight": f"响应包含异常: {', '.join(req.response.anomalies)}"
                })
        
        return anomalies

    # ==================== 隐藏参数发现辅助方法 ====================
    
    def _find_similar_endpoints(self, url: str) -> List[str]:
        """
        找到相似端点
        
        Args:
            url: 参考 URL
        
        Returns:
            相似端点路径列表
        """
        if not self.history:
            return []
        
        parsed = urlparse(url)
        path = parsed.path or "/"
        
        # 简单实现: 找同一目录下的其他端点
        path_parts = path.strip("/").split("/")
        if len(path_parts) > 1:
            base_path = "/" + "/".join(path_parts[:-1])
        else:
            base_path = "/"
        
        all_requests = self.history.list(limit=1000)
        similar: Set[str] = set()
        
        for req in all_requests:
            req_path = urlparse(req.url).path or "/"
            # 同一目录下的不同端点
            if req_path.startswith(base_path) and req_path != path:
                similar.add(req_path)
            # 相同深度的端点
            req_parts = req_path.strip("/").split("/")
            if len(req_parts) == len(path_parts) and req_path != path:
                similar.add(req_path)
        
        return list(similar)[:10]  # 最多返回10个
    
    def _get_endpoint_params(self, endpoint: str) -> Set[str]:
        """
        获取端点的所有参数
        
        Args:
            endpoint: 端点路径
        
        Returns:
            参数名集合
        """
        if not self.history:
            return set()
        
        requests = self.history.list(path=endpoint, limit=100)
        params: Set[str] = set()
        for req in requests:
            params.update(req.params.keys())
            params.update(req.body_params.keys())
        return params
    
    def _generate_param_recommendations(self, result: Dict) -> List[str]:
        """
        生成参数建议
        
        Args:
            result: discover_hidden_params 的中间结果
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 基于不一致参数
        for item in result.get("inconsistent_params", []):
            param = item.get("param", "")
            rate = item.get("occurrence_rate", 0)
            recommendations.append(
                f"尝试在所有请求中添加参数 {param} (当前出现率 {rate*100:.1f}%)"
            )
        
        # 基于相似端点
        for item in result.get("suggested_from_similar", []):
            endpoint = item.get("endpoint", "")
            for param in item.get("params", []):
                recommendations.append(
                    f"从相似端点 {endpoint} 发现参数 {param}，尝试添加到当前请求"
                )
        
        return recommendations
    
    # ==================== 利用建议生成 ====================
    
    def _generate_exploitation_suggestions(self, result: TrafficDiffResult) -> List[str]:
        """
        生成利用建议
        
        Args:
            result: TrafficDiffResult 对象
        
        Returns:
            利用建议列表
        """
        suggestions = []
        
        # 基于不一致参数
        for param in result.inconsistent_params:
            suggestions.append(f"测试条件参数 {param}: 尝试在所有请求中添加此参数，观察响应变化")
        
        # 基于参数变化
        for var in result.param_variations:
            if var.variation_type == "value_changed" and len(var.values_seen) > 3:
                suggestions.append(
                    f"参数 {var.name} 有 {len(var.values_seen)} 种值，尝试使用其他请求中的值进行越权测试"
                )
        
        # 基于响应变化
        for var in result.response_variations:
            if var.variation_type == "length":
                suggestions.append(
                    "响应长度变化大，分析不同长度响应的差异，可能泄露额外数据"
                )
            elif var.variation_type == "status":
                statuses = var.details.get("statuses", [])
                if 403 in statuses or 401 in statuses:
                    suggestions.append(
                        "发现认证相关状态码，尝试绕过认证或权限检查"
                    )
            elif var.variation_type == "timing":
                suggestions.append(
                    "响应时间变化大，可能存在时间盲注或条件处理逻辑"
                )
        
        # 基于异常
        for anomaly in result.anomalies:
            if anomaly.get("type") == "timing_anomaly":
                suggestions.append(
                    f"请求 {anomaly.get('request_id')} 响应时间异常，深入分析该请求的参数"
                )
            elif anomaly.get("type") == "response_anomaly":
                anomaly_types = anomaly.get("anomalies", [])
                if any("sql" in a.lower() for a in anomaly_types):
                    suggestions.append(
                        f"请求 {anomaly.get('request_id')} 可能存在 SQL 注入，进一步测试"
                    )
        
        return suggestions
    
    def _generate_hunter_insights(self, result: TrafficDiffResult) -> str:
        """
        生成赏金猎人洞察
        
        Args:
            result: TrafficDiffResult 对象
        
        Returns:
            洞察字符串
        """
        insights = []
        
        if result.inconsistent_params:
            insights.append(
                f"🔍 发现 {len(result.inconsistent_params)} 个不一致参数 - 可能是隐藏功能!"
            )
        
        if result.anomalies:
            insights.append(
                f"⚠️ 检测到 {len(result.anomalies)} 个异常 - 值得深入调查!"
            )
        
        if len(result.all_params_ever_seen) > 10:
            insights.append(
                f"📊 该端点历史上使用过 {len(result.all_params_ever_seen)} 个不同参数"
            )
        
        # 检查高价值参数变化
        high_value_variations = [
            v for v in result.param_variations
            if v.variation_type == "value_changed" and len(v.values_seen) > 5
        ]
        if high_value_variations:
            insights.append(
                f"💡 发现 {len(high_value_variations)} 个高变化参数，可能是动态令牌或会话相关"
            )
        
        # 检查响应变化
        for var in result.response_variations:
            if var.variation_type == "status":
                statuses = var.details.get("statuses", [])
                if 500 in statuses or any(s >= 500 for s in statuses):
                    insights.append("🔥 发现服务器错误响应，可能存在未处理的异常!")
        
        if not insights:
            if result.total_requests < 5:
                return "历史数据较少，建议收集更多流量后再分析"
            return "未发现明显异常，建议手动深入测试"
        
        return " | ".join(insights)
