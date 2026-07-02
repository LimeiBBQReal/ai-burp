"""
Property-Based Tests for Data Models

使用 hypothesis 进行属性测试，验证数据模型的正确性。
"""

import json
import copy
from hypothesis import given, strategies as st, settings

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aiburp.core.models import Request, Response


# ============================================================
# Property 1: Request 序列化往返一致性
# **Validates: Requirements 17.1, 17.5**
# ============================================================

@settings(max_examples=100)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=50),
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20),
    param_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
)
def test_request_serialization_roundtrip(method, path, param_name, param_value):
    """
    Feature: aiburp-v2-refactor, Property 1: Request 序列化往返一致性
    
    For any valid Request object, calling to_dict() then reconstructing
    from dict should produce an equivalent object.
    **Validates: Requirements 17.1, 17.5**
    """
    # Create a request with URL params
    url = f"https://example.com/{path}?{param_name}={param_value}"
    req = Request(method=method, url=url)
    
    # Serialize to dict
    data = req.to_dict()
    
    # Verify key fields are preserved
    assert data["method"] == method
    assert data["url"] == url
    assert param_name in data["params"]
    assert data["params"][param_name] == param_value
    
    # Reconstruct from dict
    reconstructed = Request.from_dict(data)
    
    # Verify equivalence
    assert reconstructed.method == req.method
    assert reconstructed.url == req.url
    assert reconstructed.params == req.params


@settings(max_examples=100)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=30),
)
def test_request_json_roundtrip(method, path):
    """
    Feature: aiburp-v2-refactor, Property 1: Request 序列化往返一致性 (JSON)
    
    For any valid Request object, to_json() should produce valid JSON
    that can be parsed back.
    **Validates: Requirements 17.1**
    """
    url = f"https://example.com/{path}"
    req = Request(method=method, url=url)
    
    # Serialize to JSON
    json_str = req.to_json()
    
    # Should be valid JSON
    data = json.loads(json_str)
    
    # Key fields should be present
    assert data["method"] == method
    assert data["url"] == url


# ============================================================
# Property 7: Request.with_param 不可变性
# **Validates: Requirements 17.5**
# ============================================================

@settings(max_examples=100)
@given(
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20),
    original_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    new_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
)
def test_with_param_immutability_url_params(param_name, original_value, new_value):
    """
    Feature: aiburp-v2-refactor, Property 7: Request.with_param 不可变性
    
    For any Request object and parameter modification, with_param()
    should return a new object without modifying the original.
    **Validates: Requirements 17.5**
    """
    # Create original request with URL param
    url = f"https://example.com/api?{param_name}={original_value}"
    original = Request(method="GET", url=url)
    
    # Store original state
    original_url = original.url
    original_params = dict(original.params)
    
    # Modify with with_param
    modified = original.with_param(param_name, new_value)
    
    # Original should be unchanged
    assert original.url == original_url
    assert original.params == original_params
    assert original.params.get(param_name) == original_value
    
    # Modified should have new value
    assert modified.params.get(param_name) == new_value
    
    # They should be different objects
    assert original is not modified


@settings(max_examples=100)
@given(
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20),
    original_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    new_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
)
def test_with_param_immutability_body_params(param_name, original_value, new_value):
    """
    Feature: aiburp-v2-refactor, Property 7: Request.with_param 不可变性 (Body)
    
    For any Request object with body params, with_param() should return
    a new object without modifying the original body.
    **Validates: Requirements 17.5**
    """
    # Create original request with body param
    body = f"{param_name}={original_value}"
    original = Request(
        method="POST",
        url="https://example.com/api",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body
    )
    
    # Store original state
    original_body = original.body
    original_body_params = dict(original.body_params)
    
    # Modify with with_param
    modified = original.with_param(param_name, new_value)
    
    # Original should be unchanged
    assert original.body == original_body
    assert original.body_params == original_body_params
    assert original.body_params.get(param_name) == original_value
    
    # Modified should have new value
    assert modified.body_params.get(param_name) == new_value
    
    # They should be different objects
    assert original is not modified


@settings(max_examples=100)
@given(
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20),
    original_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    new_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
)
def test_with_param_immutability_json_body(param_name, original_value, new_value):
    """
    Feature: aiburp-v2-refactor, Property 7: Request.with_param 不可变性 (JSON Body)
    
    For any Request object with JSON body, with_param() should return
    a new object without modifying the original JSON body.
    **Validates: Requirements 17.5**
    """
    # Create original request with JSON body
    json_body = json.dumps({param_name: original_value})
    original = Request(
        method="POST",
        url="https://example.com/api",
        headers={"Content-Type": "application/json"},
        body=json_body
    )
    
    # Store original state
    original_body = original.body
    original_json = original.json_body
    
    # Modify with with_param
    modified = original.with_param(param_name, new_value)
    
    # Original should be unchanged
    assert original.body == original_body
    assert original.json_body == original_json
    assert original.json_body.get(param_name) == original_value
    
    # Modified should have new value
    assert modified.json_body.get(param_name) == new_value
    
    # They should be different objects
    assert original is not modified



# ============================================================
# Property 2: Response 异常检测确定性
# **Validates: Requirements 17.7**
# ============================================================

@settings(max_examples=100)
@given(
    status=st.integers(min_value=100, max_value=599),
    body=st.text(min_size=0, max_size=500),
)
def test_response_detect_anomalies_deterministic(status, body):
    """
    Feature: aiburp-v2-refactor, Property 2: Response 异常检测确定性
    
    For any Response object, multiple calls to detect_anomalies()
    should produce the same anomalies list.
    **Validates: Requirements 17.7**
    """
    resp = Response(status=status, body=body)
    
    # First call
    anomalies1 = resp.detect_anomalies()
    
    # Second call
    anomalies2 = resp.detect_anomalies()
    
    # Third call
    anomalies3 = resp.detect_anomalies()
    
    # All calls should produce the same result
    assert anomalies1 == anomalies2
    assert anomalies2 == anomalies3


@settings(max_examples=100)
@given(
    sql_error=st.sampled_from([
        "MySQL error: syntax error",
        "PostgreSQL error",
        "ORA-12345: error",
        "SQLite error",
        "You have an error in your SQL syntax",
        "Warning: mysql_query()",
    ])
)
def test_response_detect_sql_errors(sql_error):
    """
    Feature: aiburp-v2-refactor, Property 2: Response 异常检测确定性 (SQL)
    
    For any Response containing SQL error patterns, detect_anomalies()
    should identify SQL-related anomalies.
    **Validates: Requirements 17.7**
    """
    resp = Response(status=200, body=sql_error)
    anomalies = resp.detect_anomalies()
    
    # Should detect some SQL-related anomaly
    sql_anomalies = [a for a in anomalies if "sql" in a.lower() or "mysql" in a.lower() or "oracle" in a.lower() or "postgresql" in a.lower()]
    assert len(sql_anomalies) > 0, f"Expected SQL anomaly for body: {sql_error}"


@settings(max_examples=100)
@given(
    path_pattern=st.sampled_from([
        "/var/www/html/index.php",
        "C:\\Windows\\System32",
        "/home/user/app",
        "\\inetpub\\wwwroot",
        "/usr/local/bin",
    ])
)
def test_response_detect_path_disclosure(path_pattern):
    """
    Feature: aiburp-v2-refactor, Property 2: Response 异常检测确定性 (Path)
    
    For any Response containing path patterns, detect_anomalies()
    should identify path disclosure.
    **Validates: Requirements 17.7**
    """
    resp = Response(status=200, body=f"Error at {path_pattern}")
    anomalies = resp.detect_anomalies()
    
    assert "path_disclosure" in anomalies


@settings(max_examples=100)
@given(
    status=st.just(403),
)
def test_response_detect_blocked(status):
    """
    Feature: aiburp-v2-refactor, Property 2: Response 异常检测确定性 (Blocked)
    
    For any Response with 403 status, detect_anomalies()
    should identify blocked anomaly.
    **Validates: Requirements 17.7**
    """
    resp = Response(status=status, body="Access denied")
    anomalies = resp.detect_anomalies()
    
    assert "blocked" in anomalies


# ============================================================
# Property 3: History 存储往返一致性
# **Validates: Requirements 8.2, 8.3**
# ============================================================

import tempfile
import shutil
from pathlib import Path

# Import History
from aiburp.core.history import History


@settings(max_examples=100, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=30),
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
    param_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=15),
    status_code=st.integers(min_value=100, max_value=599),
    resp_body=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789 ", min_size=0, max_size=100),
)
def test_history_storage_roundtrip(method, path, param_name, param_value, status_code, resp_body):
    """
    Feature: aiburp-v2-refactor, Property 3: History 存储往返一致性
    
    For any valid Request object, storing it in History with add() and
    retrieving it with get() should produce an equivalent object.
    **Validates: Requirements 8.2, 8.3**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History instance with temp directory
        history = History(project="test_roundtrip", data_dir=Path(temp_dir))
        
        # Create a request with URL params and response
        url = f"https://example.com/{path}?{param_name}={param_value}"
        req = Request(method=method, url=url)
        req.response = Response(status=status_code, body=resp_body)
        
        # Store in history
        req_id = history.add(req)
        
        # Retrieve from history
        retrieved = history.get(req_id)
        
        # Verify the retrieved request matches the original
        assert retrieved is not None
        assert retrieved.id == req_id
        assert retrieved.method == req.method
        assert retrieved.url == req.url
        assert retrieved.host == req.host
        assert retrieved.path == req.path
        assert retrieved.params == req.params
        
        # Verify response is preserved
        assert retrieved.response is not None
        assert retrieved.response.status == req.response.status
        assert retrieved.response.body == req.response.body
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=5, max_size=20),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=20),
)
def test_history_list_filters_correctly(method, host, path):
    """
    Feature: aiburp-v2-refactor, Property 3: History 存储往返一致性 (List)
    
    For any stored Request, list() with matching filters should return
    the request, and list() with non-matching filters should not.
    **Validates: Requirements 8.3**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History instance with temp directory
        history = History(project="test_list", data_dir=Path(temp_dir))
        
        # Create and store a request
        url = f"https://{host}/{path}"
        req = Request(method=method, url=url)
        req_id = history.add(req)
        
        # List with matching method filter
        results = history.list(method=method)
        assert any(r.id == req_id for r in results), f"Request not found with method filter {method}"
        
        # List with matching host filter
        results = history.list(host=host)
        assert any(r.id == req_id for r in results), f"Request not found with host filter {host}"
        
        # List with non-matching method filter should not include our request
        other_method = "OPTIONS" if method != "OPTIONS" else "HEAD"
        results = history.list(method=other_method)
        assert not any(r.id == req_id for r in results), f"Request found with wrong method filter {other_method}"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=50)
@given(
    keyword=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10),
)
def test_history_search_finds_keyword(keyword):
    """
    Feature: aiburp-v2-refactor, Property 3: History 存储往返一致性 (Search)
    
    For any Request containing a keyword in URL or body, search()
    should find that request.
    **Validates: Requirements 8.5**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History instance with temp directory
        history = History(project="test_search", data_dir=Path(temp_dir))
        
        # Create and store a request with keyword in URL
        url = f"https://example.com/api/{keyword}/resource"
        req = Request(method="GET", url=url)
        req_id = history.add(req)
        
        # Search should find the request
        results = history.search(keyword)
        assert any(r.id == req_id for r in results), f"Request not found with keyword search '{keyword}'"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================================
# Property 4: ParamAnalyzer 值模式检测一致性
# **Validates: Requirements 22.2**
# ============================================================

from aiburp.core.param_analyzer import ParamAnalyzer, ParamAnalysis, RequestAnalysis


@settings(max_examples=100)
@given(
    value=st.text(alphabet="0123456789", min_size=1, max_size=9),
)
def test_param_analyzer_numeric_id_detection(value):
    """
    Feature: aiburp-v2-refactor, Property 4: ParamAnalyzer 值模式检测一致性
    
    For any string of 1-9 digits, _detect_value_pattern() should return "numeric_id".
    Note: 10-13 digit numbers are detected as "timestamp" which is correct behavior.
    **Validates: Requirements 22.2**
    """
    analyzer = ParamAnalyzer()
    pattern = analyzer._detect_value_pattern(value)
    
    # Pure digit strings (1-9 digits) should be detected as numeric_id
    # 10-13 digit numbers are detected as timestamp (correct behavior)
    assert pattern == "numeric_id", f"Expected 'numeric_id' for '{value}', got '{pattern}'"


@settings(max_examples=100)
@given(
    uuid_parts=st.tuples(
        st.text(alphabet="0123456789abcdef", min_size=8, max_size=8),
        st.text(alphabet="0123456789abcdef", min_size=4, max_size=4),
        st.text(alphabet="0123456789abcdef", min_size=4, max_size=4),
        st.text(alphabet="0123456789abcdef", min_size=4, max_size=4),
        st.text(alphabet="0123456789abcdef", min_size=12, max_size=12),
    )
)
def test_param_analyzer_uuid_detection(uuid_parts):
    """
    Feature: aiburp-v2-refactor, Property 4: ParamAnalyzer 值模式检测一致性
    
    For any valid UUID format string, _detect_value_pattern() should return "uuid".
    **Validates: Requirements 22.2**
    """
    analyzer = ParamAnalyzer()
    uuid_str = "-".join(uuid_parts)
    pattern = analyzer._detect_value_pattern(uuid_str)
    
    assert pattern == "uuid", f"Expected 'uuid' for '{uuid_str}', got '{pattern}'"


@settings(max_examples=100)
@given(
    url=st.sampled_from([
        "http://example.com",
        "https://example.com/path",
        "http://localhost:8080",
        "https://api.example.com/v1/users",
    ])
)
def test_param_analyzer_url_detection(url):
    """
    Feature: aiburp-v2-refactor, Property 4: ParamAnalyzer 值模式检测一致性
    
    For any URL starting with http:// or https://, _detect_value_pattern() should return "url".
    **Validates: Requirements 22.2**
    """
    analyzer = ParamAnalyzer()
    pattern = analyzer._detect_value_pattern(url)
    
    assert pattern == "url", f"Expected 'url' for '{url}', got '{pattern}'"


@settings(max_examples=100)
@given(
    timestamp=st.integers(min_value=1000000000, max_value=9999999999999),
)
def test_param_analyzer_timestamp_detection(timestamp):
    """
    Feature: aiburp-v2-refactor, Property 4: ParamAnalyzer 值模式检测一致性
    
    For any 10-13 digit number, _detect_value_pattern() should return "timestamp".
    **Validates: Requirements 22.2**
    """
    analyzer = ParamAnalyzer()
    timestamp_str = str(timestamp)
    
    # Only test if it's 10-13 digits
    if 10 <= len(timestamp_str) <= 13:
        pattern = analyzer._detect_value_pattern(timestamp_str)
        assert pattern == "timestamp", f"Expected 'timestamp' for '{timestamp_str}', got '{pattern}'"


@settings(max_examples=100)
@given(
    hash_value=st.text(alphabet="0123456789abcdef", min_size=32, max_size=32),
)
def test_param_analyzer_md5_hash_detection(hash_value):
    """
    Feature: aiburp-v2-refactor, Property 4: ParamAnalyzer 值模式检测一致性
    
    For any 32-character hex string, _detect_value_pattern() should return "hash_md5".
    **Validates: Requirements 22.2**
    """
    analyzer = ParamAnalyzer()
    pattern = analyzer._detect_value_pattern(hash_value)
    
    assert pattern == "hash_md5", f"Expected 'hash_md5' for '{hash_value}', got '{pattern}'"


@settings(max_examples=100)
@given(
    value=st.text(min_size=0, max_size=100),
)
def test_param_analyzer_detection_deterministic(value):
    """
    Feature: aiburp-v2-refactor, Property 4: ParamAnalyzer 值模式检测一致性
    
    For any value, multiple calls to _detect_value_pattern() should return the same result.
    **Validates: Requirements 22.2**
    """
    analyzer = ParamAnalyzer()
    
    # Call multiple times
    pattern1 = analyzer._detect_value_pattern(value)
    pattern2 = analyzer._detect_value_pattern(value)
    pattern3 = analyzer._detect_value_pattern(value)
    
    # All calls should return the same result
    assert pattern1 == pattern2 == pattern3, f"Non-deterministic detection for '{value}'"



# ============================================================
# Property 5: ParamAnalyzer 风险评分边界
# **Validates: Requirements 22.4**
# ============================================================

@settings(max_examples=100)
@given(
    name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20),
    value=st.text(min_size=0, max_size=50),
    pattern=st.sampled_from(["numeric_id", "base64", "jwt", "uuid", "file_path", "url", "json", "xml", "timestamp", "hash_md5", "unknown"]),
)
def test_param_analyzer_risk_score_bounds(name, value, pattern):
    """
    Feature: aiburp-v2-refactor, Property 5: ParamAnalyzer 风险评分边界
    
    For any parameter, _calculate_risk() should return a score between 0 and 100.
    **Validates: Requirements 22.4**
    """
    analyzer = ParamAnalyzer()
    score, factors = analyzer._calculate_risk(name, value, pattern)
    
    # Score should be within bounds
    assert 0 <= score <= 100, f"Risk score {score} out of bounds for name='{name}', pattern='{pattern}'"
    
    # Factors should be a list
    assert isinstance(factors, list), f"Risk factors should be a list, got {type(factors)}"


@settings(max_examples=100)
@given(
    sensitive_name=st.sampled_from(["user_id", "admin", "file", "url", "debug", "role", "callback", "search"]),
    value=st.text(min_size=1, max_size=20),
)
def test_param_analyzer_sensitive_names_increase_risk(sensitive_name, value):
    """
    Feature: aiburp-v2-refactor, Property 5: ParamAnalyzer 风险评分边界
    
    For any sensitive parameter name, _calculate_risk() should return a score > 0.
    **Validates: Requirements 22.4**
    """
    analyzer = ParamAnalyzer()
    score, factors = analyzer._calculate_risk(sensitive_name, value, "unknown")
    
    # Sensitive names should have non-zero risk
    assert score > 0, f"Sensitive name '{sensitive_name}' should have risk > 0, got {score}"
    assert len(factors) > 0, f"Sensitive name '{sensitive_name}' should have risk factors"


@settings(max_examples=100)
@given(
    name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=5, max_size=15),
    risky_pattern=st.sampled_from(["jwt", "file_path", "url", "numeric_id"]),
)
def test_param_analyzer_risky_patterns_increase_risk(name, risky_pattern):
    """
    Feature: aiburp-v2-refactor, Property 5: ParamAnalyzer 风险评分边界
    
    For any risky value pattern, _calculate_risk() should return a score > 0.
    **Validates: Requirements 22.4**
    """
    analyzer = ParamAnalyzer()
    
    # Use a non-sensitive name to isolate pattern risk
    neutral_name = "data" + name  # Prefix to avoid matching sensitive patterns
    score, factors = analyzer._calculate_risk(neutral_name, "test_value", risky_pattern)
    
    # Risky patterns should have non-zero risk
    assert score > 0, f"Risky pattern '{risky_pattern}' should have risk > 0, got {score}"


@settings(max_examples=100)
@given(
    name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20),
    value=st.text(min_size=0, max_size=50),
    pattern=st.sampled_from(["numeric_id", "base64", "jwt", "uuid", "file_path", "url", "unknown"]),
)
def test_param_analyzer_risk_calculation_deterministic(name, value, pattern):
    """
    Feature: aiburp-v2-refactor, Property 5: ParamAnalyzer 风险评分边界
    
    For any parameter, multiple calls to _calculate_risk() should return the same result.
    **Validates: Requirements 22.4**
    """
    analyzer = ParamAnalyzer()
    
    # Call multiple times
    score1, factors1 = analyzer._calculate_risk(name, value, pattern)
    score2, factors2 = analyzer._calculate_risk(name, value, pattern)
    
    # All calls should return the same result
    assert score1 == score2, f"Non-deterministic risk score for name='{name}', pattern='{pattern}'"
    assert factors1 == factors2, f"Non-deterministic risk factors for name='{name}', pattern='{pattern}'"



# ============================================================
# Property 6: TrafficDiff 参数收集完整性
# **Validates: Requirements 23.1, 23.4**
# ============================================================

from aiburp.core.traffic_diff import TrafficDiff, ParamVariation, ResponseVariation, TrafficDiffResult, CrossEndpointResult


@settings(max_examples=100)
@given(
    param_names=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
        min_size=1,
        max_size=5,
        unique=True
    ),
    param_values=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=15),
        min_size=1,
        max_size=5
    ),
)
def test_traffic_diff_collect_all_params_completeness(param_names, param_values):
    """
    Feature: aiburp-v2-refactor, Property 6: TrafficDiff 参数收集完整性
    
    For any list of requests with URL and body parameters, _collect_all_params()
    should return all unique parameter names from all requests.
    **Validates: Requirements 23.1, 23.4**
    """
    # Create requests with various parameters
    requests = []
    all_expected_params = set()
    
    for i, param_name in enumerate(param_names):
        # Alternate between URL params and body params
        value = param_values[i % len(param_values)]
        
        if i % 2 == 0:
            # URL param
            url = f"https://example.com/api?{param_name}={value}"
            req = Request(method="GET", url=url)
        else:
            # Body param
            body = f"{param_name}={value}"
            req = Request(
                method="POST",
                url="https://example.com/api",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body
            )
        
        requests.append(req)
        all_expected_params.add(param_name)
    
    # Create TrafficDiff instance (without history)
    diff = TrafficDiff(history=None)
    
    # Collect all params
    collected = diff._collect_all_params(requests)
    
    # All expected params should be collected
    collected_set = set(collected)
    assert all_expected_params <= collected_set, \
        f"Missing params: {all_expected_params - collected_set}"


@settings(max_examples=100)
@given(
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
    param_value=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=15),
    num_requests=st.integers(min_value=5, max_value=10),
    occurrence_rate=st.floats(min_value=0.1, max_value=0.7),
)
def test_traffic_diff_find_inconsistent_params(param_name, param_value, num_requests, occurrence_rate):
    """
    Feature: aiburp-v2-refactor, Property 6: TrafficDiff 参数收集完整性
    
    For any parameter that appears in less than 80% of requests,
    _find_inconsistent_params() should identify it as inconsistent.
    **Validates: Requirements 23.1, 23.4**
    """
    # Create requests where param appears in only some
    requests = []
    num_with_param = int(num_requests * occurrence_rate)
    
    for i in range(num_requests):
        if i < num_with_param:
            # Request with the param
            url = f"https://example.com/api?{param_name}={param_value}"
        else:
            # Request without the param
            url = "https://example.com/api"
        
        req = Request(method="GET", url=url)
        requests.append(req)
    
    # Create TrafficDiff instance
    diff = TrafficDiff(history=None)
    
    # Find inconsistent params
    inconsistent = diff._find_inconsistent_params(requests)
    
    # If occurrence rate is less than 80%, param should be inconsistent
    actual_rate = num_with_param / num_requests
    if 0 < actual_rate < 0.8:
        assert param_name in inconsistent, \
            f"Param '{param_name}' with {actual_rate*100:.1f}% occurrence should be inconsistent"


@settings(max_examples=100)
@given(
    param_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
    values=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=15),
        min_size=2,
        max_size=5,
        unique=True
    ),
)
def test_traffic_diff_analyze_param_variations_tracks_values(param_name, values):
    """
    Feature: aiburp-v2-refactor, Property 6: TrafficDiff 参数收集完整性
    
    For any parameter with multiple different values across requests,
    _analyze_param_variations() should track all unique values.
    **Validates: Requirements 23.1, 23.4**
    """
    # Create requests with different values for the same param
    requests = []
    for value in values:
        url = f"https://example.com/api?{param_name}={value}"
        req = Request(method="GET", url=url, timestamp=f"2024-01-01T00:00:{len(requests):02d}")
        requests.append(req)
    
    # Create TrafficDiff instance
    diff = TrafficDiff(history=None)
    
    # Analyze param variations
    variations = diff._analyze_param_variations(requests)
    
    # Find the variation for our param
    param_var = None
    for v in variations:
        if v.name == param_name:
            param_var = v
            break
    
    assert param_var is not None, f"Param '{param_name}' should have a variation record"
    
    # All values should be tracked (up to 10)
    expected_values = set(values[:10])
    actual_values = set(param_var.values_seen)
    assert expected_values <= actual_values, \
        f"Missing values: {expected_values - actual_values}"
    
    # Should be marked as value_changed if multiple values
    if len(values) > 1:
        assert param_var.variation_type == "value_changed", \
            f"Param with {len(values)} values should be 'value_changed', got '{param_var.variation_type}'"


@settings(max_examples=100)
@given(
    method=st.sampled_from(["GET", "POST"]),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=20),
)
def test_traffic_diff_result_serialization(method, path):
    """
    Feature: aiburp-v2-refactor, Property 6: TrafficDiff 参数收集完整性
    
    For any TrafficDiffResult, to_dict() and to_json() should produce
    valid serializable output.
    **Validates: Requirements 23.1**
    """
    # Create a TrafficDiffResult
    result = TrafficDiffResult(
        url=f"https://example.com/{path}",
        total_requests=5,
        time_range=("2024-01-01T00:00:00", "2024-01-01T01:00:00"),
        param_variations=[
            ParamVariation(
                name="test_param",
                variation_type="observed",
                first_seen="2024-01-01T00:00:00",
                last_seen="2024-01-01T01:00:00",
                values_seen=["value1", "value2"],
                occurrence_count=5,
                total_requests=5,
            )
        ],
        all_params_ever_seen=["test_param"],
        inconsistent_params=[],
        response_variations=[
            ResponseVariation(
                variation_type="length",
                details={"min": 100, "max": 200},
                insight="Test insight"
            )
        ],
    )
    
    # to_dict should work
    data = result.to_dict()
    assert isinstance(data, dict)
    assert data["url"] == f"https://example.com/{path}"
    assert data["total_requests"] == 5
    
    # to_json should produce valid JSON
    json_str = result.to_json()
    parsed = json.loads(json_str)
    assert parsed["url"] == f"https://example.com/{path}"


@settings(max_examples=100)
@given(
    endpoints=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=3, max_size=15),
        min_size=2,
        max_size=4,
        unique=True
    ),
)
def test_cross_endpoint_result_serialization(endpoints):
    """
    Feature: aiburp-v2-refactor, Property 6: TrafficDiff 参数收集完整性
    
    For any CrossEndpointResult, to_dict() and to_json() should produce
    valid serializable output.
    **Validates: Requirements 23.1**
    """
    # Create a CrossEndpointResult
    result = CrossEndpointResult(
        endpoints=endpoints,
        params_only_in={endpoints[0]: ["unique_param"]},
        common_params=["common_param"],
        potential_issues=["Test issue"],
    )
    
    # to_dict should work
    data = result.to_dict()
    assert isinstance(data, dict)
    assert data["endpoints"] == endpoints
    
    # to_json should produce valid JSON
    json_str = result.to_json()
    parsed = json.loads(json_str)
    assert parsed["endpoints"] == endpoints



# ============================================================
# Property 9: TrafficManager 过滤正确性
# **Validates: Requirements 4.3, 4.4**
# ============================================================

from aiburp.core.traffic_manager import TrafficManager


@settings(max_examples=100, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=5, max_size=20),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=20),
)
def test_traffic_manager_filter_by_method(method, host, path):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any stored Request, filter(method=X) should return only requests
    with that method.
    **Validates: Requirements 4.3, 4.4**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_filter_method", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Create and store requests with different methods
        url = f"https://{host}/{path}"
        req = Request(method=method, url=url)
        req_id = history.add(req)
        
        # Also add a request with a different method
        other_method = "OPTIONS" if method != "OPTIONS" else "HEAD"
        other_req = Request(method=other_method, url=url)
        history.add(other_req)
        
        # Filter by method
        results = traffic.filter(method=method)
        
        # All results should have the specified method
        for r in results:
            assert r.method == method, f"Expected method {method}, got {r.method}"
        
        # Our request should be in the results
        assert any(r.id == req_id for r in results), f"Request not found with method filter {method}"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=5, max_size=15),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=15),
)
def test_traffic_manager_filter_by_host(method, host, path):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any stored Request, filter(host=X) should return only requests
    with that host.
    **Validates: Requirements 4.3, 4.4**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_filter_host", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Create and store a request
        url = f"https://{host}/{path}"
        req = Request(method=method, url=url)
        req_id = history.add(req)
        
        # Also add a request with a different host
        other_host = "other." + host
        other_url = f"https://{other_host}/{path}"
        other_req = Request(method=method, url=other_url)
        history.add(other_req)
        
        # Filter by host
        results = traffic.filter(host=host)
        
        # All results should have the specified host
        for r in results:
            assert r.host == host, f"Expected host {host}, got {r.host}"
        
        # Our request should be in the results
        assert any(r.id == req_id for r in results), f"Request not found with host filter {host}"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST"]),
    path_segment=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10),
)
def test_traffic_manager_filter_by_path_regex(method, path_segment):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any stored Request, filter(path=regex) should return only requests
    whose path matches the regex pattern.
    **Validates: Requirements 4.3, 4.4**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_filter_path", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Create and store a request with the path segment
        url = f"https://example.com/api/{path_segment}/resource"
        req = Request(method=method, url=url)
        req_id = history.add(req)
        
        # Also add a request without the path segment
        other_url = f"https://example.com/other/endpoint"
        other_req = Request(method=method, url=other_url)
        history.add(other_req)
        
        # Filter by path regex
        results = traffic.filter(path=path_segment)
        
        # All results should have the path segment
        for r in results:
            assert path_segment in r.path, f"Expected path to contain {path_segment}, got {r.path}"
        
        # Our request should be in the results
        assert any(r.id == req_id for r in results), f"Request not found with path filter {path_segment}"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100, deadline=None)
@given(
    content_type=st.sampled_from(["application/json", "application/x-www-form-urlencoded", "text/html"]),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=15),
)
def test_traffic_manager_filter_by_content_type(content_type, path):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any stored Request, filter(content_type=X) should return only requests
    with that content type.
    **Validates: Requirements 4.3, 4.4**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_filter_ct", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Create and store a request with the content type
        url = f"https://example.com/{path}"
        req = Request(
            method="POST",
            url=url,
            headers={"Content-Type": content_type},
            body="test=data"
        )
        req_id = history.add(req)
        
        # Also add a request with a different content type
        other_ct = "text/plain" if content_type != "text/plain" else "text/xml"
        other_req = Request(
            method="POST",
            url=url,
            headers={"Content-Type": other_ct},
            body="test=data"
        )
        history.add(other_req)
        
        # Filter by content type (partial match)
        # Extract the main type for matching (e.g., "json" from "application/json")
        match_str = content_type.split("/")[-1]
        results = traffic.filter(content_type=match_str)
        
        # All results should have the content type
        for r in results:
            assert match_str in r.headers.get("Content-Type", "").lower(), \
                f"Expected content type to contain {match_str}, got {r.headers.get('Content-Type', '')}"
        
        # Our request should be in the results
        assert any(r.id == req_id for r in results), f"Request not found with content_type filter {match_str}"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100, deadline=None)
@given(
    n=st.integers(min_value=1, max_value=10),
    num_requests=st.integers(min_value=5, max_value=15),
)
def test_traffic_manager_recent_returns_n_requests(n, num_requests):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any n, recent(n) should return at most n requests.
    **Validates: Requirements 4.1**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_recent", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Add multiple requests
        for i in range(num_requests):
            url = f"https://example.com/api/resource{i}"
            req = Request(method="GET", url=url)
            history.add(req)
        
        # Get recent n requests
        results = traffic.recent(n)
        
        # Should return at most n requests
        expected_count = min(n, num_requests)
        assert len(results) == expected_count, \
            f"Expected {expected_count} requests, got {len(results)}"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=5, max_size=15),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=15),
)
def test_traffic_manager_find_returns_single_or_none(method, host, path):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any filter criteria, find() should return a single Request or None.
    **Validates: Requirements 4.2**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_find", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Create and store a request
        url = f"https://{host}/{path}"
        req = Request(method=method, url=url)
        req_id = history.add(req)
        
        # Find with matching criteria
        result = traffic.find(method=method, host=host)
        
        # Should return a single request
        assert result is not None, "Expected to find a request"
        assert result.method == method
        assert result.host == host
        
        # Find with non-matching criteria
        other_method = "OPTIONS" if method != "OPTIONS" else "HEAD"
        result_none = traffic.find(method=other_method, host=host)
        
        # Should return None
        assert result_none is None, "Expected None for non-matching criteria"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=50, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=5, max_size=15),
)
def test_traffic_manager_clear_removes_all(method, host):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    After calling clear(), the traffic manager should have no requests.
    **Validates: Requirements 4.5**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_clear", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Add some requests
        for i in range(5):
            url = f"https://{host}/api/resource{i}"
            req = Request(method=method, url=url)
            history.add(req)
        
        # Verify requests exist
        assert traffic.count() > 0, "Expected some requests before clear"
        
        # Clear all requests
        traffic.clear()
        
        # Verify no requests remain
        assert traffic.count() == 0, "Expected no requests after clear"
        assert len(traffic.recent(100)) == 0, "Expected empty recent list after clear"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@settings(max_examples=100, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=5, max_size=15),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=15),
)
def test_traffic_manager_filter_combined_criteria(method, host, path):
    """
    Feature: aiburp-v2-refactor, Property 9: TrafficManager 过滤正确性
    
    For any combination of filter criteria, filter() should return only
    requests matching ALL criteria.
    **Validates: Requirements 4.3, 4.4**
    """
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    try:
        # Create History and TrafficManager instances
        history = History(project="test_traffic_combined", data_dir=Path(temp_dir))
        traffic = TrafficManager(history)
        
        # Create and store a request matching all criteria
        url = f"https://{host}/{path}"
        req = Request(method=method, url=url)
        req_id = history.add(req)
        
        # Add requests that match only some criteria
        # Different method
        other_method = "OPTIONS" if method != "OPTIONS" else "HEAD"
        req2 = Request(method=other_method, url=url)
        history.add(req2)
        
        # Different host
        other_url = f"https://other.{host}/{path}"
        req3 = Request(method=method, url=other_url)
        history.add(req3)
        
        # Filter with combined criteria
        results = traffic.filter(method=method, host=host)
        
        # All results should match both criteria
        for r in results:
            assert r.method == method, f"Expected method {method}, got {r.method}"
            assert r.host == host, f"Expected host {host}, got {r.host}"
        
        # Our request should be in the results
        assert any(r.id == req_id for r in results), "Request not found with combined filter"
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)



# ============================================================
# Property 8: Intruder 停止条件正确性
# **Validates: Requirements 7.4, 7.5**
# ============================================================

from aiburp.core.intruder import Intruder, AttackResult, AttackReport


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789'\"", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
    anomaly=st.sampled_from(["sql_error", "mysql_error", "path_disclosure", "stack_trace", "blocked"]),
)
def test_intruder_stop_on_anomaly(payload, status, length, time_ms, anomaly):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any AttackResult with non-empty anomalies, when stop_on="anomaly",
    _check_stop() should return True.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create an AttackResult with anomalies
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[anomaly],
        reflects=False,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with stop_on="anomaly"
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on="anomaly",
        consecutive_errors=0,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should stop because anomalies is non-empty
    assert should_stop is True, f"Expected to stop on anomaly '{anomaly}', but didn't"
    assert "anomaly" in reason.lower() or "interesting" in reason.lower(), \
        f"Stop reason should mention anomaly, got: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
)
def test_intruder_no_stop_without_anomaly(payload, status, length, time_ms):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any AttackResult with empty anomalies and no reflection,
    when stop_on="anomaly", _check_stop() should return False.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create an AttackResult without anomalies
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[],
        reflects=False,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with stop_on="anomaly"
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on="anomaly",
        consecutive_errors=0,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should not stop because anomalies is empty and no reflection
    assert should_stop is False, f"Should not stop without anomalies, but got reason: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
    db_error=st.sampled_from(["mysql_error", "postgresql_error", "mssql_error", "oracle_error", "sqlite_error", "sql_error"]),
)
def test_intruder_stop_on_error(payload, status, length, time_ms, db_error):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any AttackResult with database error anomalies, when stop_on="error",
    _check_stop() should return True.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create an AttackResult with database error
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[db_error],
        reflects=False,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with stop_on="error"
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on="error",
        consecutive_errors=0,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should stop because of database error
    assert should_stop is True, f"Expected to stop on database error '{db_error}', but didn't"
    assert "error" in reason.lower() or "database" in reason.lower(), \
        f"Stop reason should mention error, got: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
)
def test_intruder_stop_on_reflect(payload, status, length, time_ms):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any AttackResult with reflects=True, when stop_on="reflect",
    _check_stop() should return True.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create an AttackResult with reflection
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[],
        reflects=True,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with stop_on="reflect"
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on="reflect",
        consecutive_errors=0,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should stop because of reflection
    assert should_stop is True, f"Expected to stop on reflection, but didn't"
    assert "reflect" in reason.lower(), f"Stop reason should mention reflect, got: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
)
def test_intruder_stop_on_block(payload, status, length, time_ms):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any AttackResult with "blocked" in anomalies, when stop_on="block",
    _check_stop() should return True.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create an AttackResult with blocked anomaly
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=["blocked"],
        reflects=False,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with stop_on="block"
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on="block",
        consecutive_errors=0,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should stop because of block
    assert should_stop is True, f"Expected to stop on block, but didn't"
    assert "block" in reason.lower(), f"Stop reason should mention block, got: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
    anomaly=st.sampled_from(["sql_error", "mysql_error", "path_disclosure", "blocked"]),
)
def test_intruder_no_stop_when_stop_on_none(payload, status, length, time_ms, anomaly):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any AttackResult, when stop_on=None, _check_stop() should return False
    (unless consecutive errors exceed max_errors).
    **Validates: Requirements 7.4, 7.5**
    """
    # Create an AttackResult with anomalies
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[anomaly],
        reflects=True,  # Even with reflection
        status_changed=True,  # Even with status change
        length_diff=1000,
        time_diff=5000,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with stop_on=None
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on=None,
        consecutive_errors=0,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should not stop because stop_on is None
    assert should_stop is False, f"Should not stop when stop_on=None, but got reason: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
    consecutive_errors=st.integers(min_value=3, max_value=10),
)
def test_intruder_stop_on_consecutive_errors(payload, status, length, time_ms, consecutive_errors):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any consecutive_errors >= max_errors, _check_stop() should return True
    regardless of stop_on setting.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create a normal AttackResult
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[],
        reflects=False,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with high consecutive errors
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on=None,
        consecutive_errors=consecutive_errors,
        consecutive_blocks=0,
        max_errors=3,
    )
    
    # Should stop because of consecutive errors
    assert should_stop is True, f"Expected to stop on {consecutive_errors} consecutive errors, but didn't"
    assert "error" in reason.lower(), f"Stop reason should mention errors, got: {reason}"


@settings(max_examples=100)
@given(
    payload=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20),
    status=st.integers(min_value=100, max_value=599),
    length=st.integers(min_value=0, max_value=10000),
    time_ms=st.floats(min_value=0, max_value=10000),
)
def test_intruder_stop_on_consecutive_blocks(payload, status, length, time_ms):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any consecutive_blocks >= 3, _check_stop() should return True
    regardless of stop_on setting.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create a normal AttackResult
    result = AttackResult(
        payload=payload,
        status=status,
        length=length,
        time_ms=time_ms,
        anomalies=[],
        reflects=False,
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Check stop condition with 3 consecutive blocks
    should_stop, reason = intruder._check_stop(
        result=result,
        stop_on=None,
        consecutive_errors=0,
        consecutive_blocks=3,
        max_errors=3,
    )
    
    # Should stop because of consecutive blocks
    assert should_stop is True, f"Expected to stop on 3 consecutive blocks, but didn't"
    assert "block" in reason.lower() or "waf" in reason.lower(), \
        f"Stop reason should mention block/WAF, got: {reason}"


@settings(max_examples=100)
@given(
    stop_on=st.sampled_from(["anomaly", "error", "reflect", "block", None]),
    consecutive_errors=st.integers(min_value=0, max_value=2),
    consecutive_blocks=st.integers(min_value=0, max_value=2),
)
def test_intruder_check_stop_deterministic(stop_on, consecutive_errors, consecutive_blocks):
    """
    Feature: aiburp-v2-refactor, Property 8: Intruder 停止条件正确性
    
    For any inputs, multiple calls to _check_stop() with the same parameters
    should return the same result.
    **Validates: Requirements 7.4, 7.5**
    """
    # Create a normal AttackResult
    result = AttackResult(
        payload="test",
        status=200,
        length=100,
        time_ms=50.0,
        anomalies=["sql_error"] if stop_on in ["anomaly", "error"] else [],
        reflects=stop_on == "reflect",
        status_changed=False,
        length_diff=0,
        time_diff=0,
    )
    
    # Create Intruder instance (without history)
    intruder = Intruder(history=None)
    
    # Call multiple times
    result1 = intruder._check_stop(result, stop_on, consecutive_errors, consecutive_blocks, 3)
    result2 = intruder._check_stop(result, stop_on, consecutive_errors, consecutive_blocks, 3)
    result3 = intruder._check_stop(result, stop_on, consecutive_errors, consecutive_blocks, 3)
    
    # All calls should return the same result
    assert result1 == result2 == result3, \
        f"Non-deterministic _check_stop for stop_on={stop_on}"



# ============================================================
# Property 10: PageView 元素选择器唯一性
# **Validates: Requirements 1.3**
# ============================================================

from aiburp.core.models import PageView, FormInfo, InputInfo, LinkInfo, ButtonInfo


@settings(max_examples=100)
@given(
    num_forms=st.integers(min_value=0, max_value=5),
    num_links=st.integers(min_value=0, max_value=10),
    num_buttons=st.integers(min_value=0, max_value=5),
    num_inputs=st.integers(min_value=0, max_value=5),
)
def test_pageview_all_selectors_returns_list(num_forms, num_links, num_buttons, num_inputs):
    """
    Feature: aiburp-v2-refactor, Property 10: PageView 元素选择器唯一性
    
    For any PageView with elements, all_selectors property should return
    a list of all selectors from all elements.
    **Validates: Requirements 1.3**
    """
    # Create forms with unique selectors
    forms = []
    for i in range(num_forms):
        form_inputs = [
            InputInfo(
                name=f"input_{i}_{j}",
                type="text",
                selector=f"form#{i} input[name='input_{i}_{j}']"
            )
            for j in range(2)
        ]
        forms.append(FormInfo(
            action=f"/submit_{i}",
            method="POST",
            selector=f"form#{i}",
            inputs=form_inputs,
            submit_button=ButtonInfo(
                text="Submit",
                selector=f"form#{i} button[type='submit']",
                type="submit"
            )
        ))
    
    # Create links with unique selectors
    links = [
        LinkInfo(
            text=f"Link {i}",
            href=f"/page_{i}",
            selector=f"a#link_{i}"
        )
        for i in range(num_links)
    ]
    
    # Create buttons with unique selectors
    buttons = [
        ButtonInfo(
            text=f"Button {i}",
            selector=f"button#btn_{i}",
            type="button"
        )
        for i in range(num_buttons)
    ]
    
    # Create standalone inputs with unique selectors
    inputs = [
        InputInfo(
            name=f"standalone_{i}",
            type="text",
            selector=f"input#standalone_{i}"
        )
        for i in range(num_inputs)
    ]
    
    # Create PageView
    page_view = PageView(
        screenshot="",
        title="Test Page",
        url="https://example.com/test",
        forms=forms,
        links=links,
        buttons=buttons,
        inputs=inputs,
    )
    
    # Get all selectors
    all_selectors = page_view.all_selectors
    
    # Should be a list
    assert isinstance(all_selectors, list), f"all_selectors should be a list, got {type(all_selectors)}"
    
    # Calculate expected count
    expected_count = 0
    for form in forms:
        expected_count += 1  # form selector
        expected_count += len(form.inputs)  # input selectors
        if form.submit_button:
            expected_count += 1  # submit button selector
    expected_count += num_links
    expected_count += num_buttons
    expected_count += num_inputs
    
    # Should have the expected number of selectors
    assert len(all_selectors) == expected_count, \
        f"Expected {expected_count} selectors, got {len(all_selectors)}"


@settings(max_examples=100)
@given(
    form_ids=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10),
        min_size=2,
        max_size=5,
        unique=True
    ),
)
def test_pageview_selectors_uniqueness_with_unique_ids(form_ids):
    """
    Feature: aiburp-v2-refactor, Property 10: PageView 元素选择器唯一性
    
    For any PageView where all elements have unique IDs, all_selectors
    should contain no duplicates.
    **Validates: Requirements 1.3**
    """
    # Create forms with unique ID-based selectors
    forms = [
        FormInfo(
            action=f"/submit_{form_id}",
            method="POST",
            selector=f"form#{form_id}",
            inputs=[
                InputInfo(
                    name=f"input_{form_id}",
                    type="text",
                    selector=f"#{form_id}_input"
                )
            ],
            submit_button=ButtonInfo(
                text="Submit",
                selector=f"#{form_id}_submit",
                type="submit"
            )
        )
        for form_id in form_ids
    ]
    
    # Create PageView
    page_view = PageView(
        screenshot="",
        title="Test Page",
        url="https://example.com/test",
        forms=forms,
        links=[],
        buttons=[],
        inputs=[],
    )
    
    # Get all selectors
    all_selectors = page_view.all_selectors
    
    # All selectors should be unique (no duplicates)
    unique_selectors = set(all_selectors)
    assert len(all_selectors) == len(unique_selectors), \
        f"Found duplicate selectors: {[s for s in all_selectors if all_selectors.count(s) > 1]}"


@settings(max_examples=100)
@given(
    link_texts=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=3, max_size=20),
        min_size=2,
        max_size=8,
        unique=True
    ),
)
def test_pageview_link_selectors_are_valid(link_texts):
    """
    Feature: aiburp-v2-refactor, Property 10: PageView 元素选择器唯一性
    
    For any PageView with links, each link should have a non-empty selector.
    **Validates: Requirements 1.3**
    """
    # Create links with text-based selectors
    links = [
        LinkInfo(
            text=text,
            href=f"/page_{i}",
            selector=f"a:has-text('{text[:20]}')" if len(text) <= 20 else f"a#link_{i}"
        )
        for i, text in enumerate(link_texts)
    ]
    
    # Create PageView
    page_view = PageView(
        screenshot="",
        title="Test Page",
        url="https://example.com/test",
        forms=[],
        links=links,
        buttons=[],
        inputs=[],
    )
    
    # Get all selectors
    all_selectors = page_view.all_selectors
    
    # All selectors should be non-empty
    for selector in all_selectors:
        assert selector, "Found empty selector"
        assert len(selector) > 0, "Found empty selector"


@settings(max_examples=100)
@given(
    num_elements=st.integers(min_value=1, max_value=10),
)
def test_pageview_selectors_filter_empty(num_elements):
    """
    Feature: aiburp-v2-refactor, Property 10: PageView 元素选择器唯一性
    
    For any PageView, all_selectors should filter out empty selectors.
    **Validates: Requirements 1.3**
    """
    # Create inputs with some empty selectors
    inputs = []
    for i in range(num_elements):
        if i % 2 == 0:
            # Non-empty selector
            inputs.append(InputInfo(
                name=f"input_{i}",
                type="text",
                selector=f"#input_{i}"
            ))
        else:
            # Empty selector
            inputs.append(InputInfo(
                name=f"input_{i}",
                type="text",
                selector=""
            ))
    
    # Create PageView
    page_view = PageView(
        screenshot="",
        title="Test Page",
        url="https://example.com/test",
        forms=[],
        links=[],
        buttons=[],
        inputs=inputs,
    )
    
    # Get all selectors
    all_selectors = page_view.all_selectors
    
    # Should not contain empty selectors
    assert "" not in all_selectors, "all_selectors should filter out empty selectors"
    
    # Should only contain non-empty selectors
    expected_count = len([i for i in inputs if i.selector])
    assert len(all_selectors) == expected_count, \
        f"Expected {expected_count} non-empty selectors, got {len(all_selectors)}"


@settings(max_examples=100)
@given(
    title=st.text(min_size=0, max_size=50),
    url=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/.", min_size=5, max_size=50),
)
def test_pageview_serialization_roundtrip(title, url):
    """
    Feature: aiburp-v2-refactor, Property 10: PageView 元素选择器唯一性
    
    For any PageView, to_dict() and to_json() should produce valid output
    that preserves key information.
    **Validates: Requirements 1.3**
    """
    # Create a PageView with some elements
    page_view = PageView(
        screenshot="base64_screenshot_data",
        title=title,
        url=f"https://{url}",
        forms=[
            FormInfo(
                action="/submit",
                method="POST",
                selector="form#test",
                inputs=[
                    InputInfo(name="username", type="text", selector="#username")
                ],
            )
        ],
        links=[
            LinkInfo(text="Home", href="/", selector="a#home")
        ],
        buttons=[
            ButtonInfo(text="Click", selector="#btn", type="button")
        ],
        inputs=[
            InputInfo(name="search", type="text", selector="#search")
        ],
    )
    
    # to_dict should work
    data = page_view.to_dict()
    assert isinstance(data, dict)
    assert data["title"] == title
    assert data["url"] == f"https://{url}"
    assert len(data["forms"]) == 1
    assert len(data["links"]) == 1
    assert len(data["buttons"]) == 1
    assert len(data["inputs"]) == 1
    
    # to_json should produce valid JSON
    json_str = page_view.to_json()
    parsed = json.loads(json_str)
    assert parsed["title"] == title
    assert parsed["url"] == f"https://{url}"


@settings(max_examples=100)
@given(
    num_forms=st.integers(min_value=0, max_value=3),
    num_links=st.integers(min_value=0, max_value=5),
)
def test_pageview_str_representation(num_forms, num_links):
    """
    Feature: aiburp-v2-refactor, Property 10: PageView 元素选择器唯一性
    
    For any PageView, __str__() should return a meaningful string representation.
    **Validates: Requirements 1.3**
    """
    # Create PageView
    page_view = PageView(
        screenshot="",
        title="Test Page",
        url="https://example.com/test",
        forms=[FormInfo(selector=f"form#{i}") for i in range(num_forms)],
        links=[LinkInfo(selector=f"a#{i}") for i in range(num_links)],
        buttons=[],
        inputs=[],
    )
    
    # __str__ should work
    str_repr = str(page_view)
    
    # Should contain key information
    assert "Test Page" in str_repr or "PageView" in str_repr
    assert str(num_forms) in str_repr, f"Expected {num_forms} forms in string representation"
    assert str(num_links) in str_repr, f"Expected {num_links} links in string representation"
