"""
AIBURP History - 流量存储

流量是一切的起点
所有请求都存这里，所有操作都从这里取数据
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from .models import Request, Response


class History:
    """
    流量历史管理
    
    用法:
        history = History(project="target_com")
        
        # 添加请求
        req_id = history.add(request)
        
        # 查询
        requests = history.list(host="target.com", method="POST")
        request = history.get(id=123)
        
        # 导入
        history.import_har("export.har")
        history.import_burp("burp.xml")
        
        # 导出
        history.export_json("history.json")
    """
    
    def __init__(self, project: str = "default", data_dir: Path = None):
        self.project = project
        self.data_dir = data_dir or Path.home() / ".aiburp" / project
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.data_dir / "history.db"
        self._init_db()
    
    def _init_db(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT,
                url TEXT,
                host TEXT,
                path TEXT,
                headers TEXT,
                body TEXT,
                timestamp TEXT,
                tags TEXT,
                notes TEXT,
                fingerprint TEXT,
                
                -- 响应
                resp_status INTEGER,
                resp_headers TEXT,
                resp_body TEXT,
                resp_time_ms REAL,
                resp_anomalies TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_host ON requests(host)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_method ON requests(method)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint ON requests(fingerprint)")
        conn.commit()
        conn.close()
    
    # ==================== 基本操作 ====================
    
    def add(self, request: Request) -> int:
        """
        添加请求到历史
        返回请求 ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO requests (
                method, url, host, path, headers, body, 
                timestamp, tags, notes, fingerprint,
                resp_status, resp_headers, resp_body, resp_time_ms, resp_anomalies
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request.method,
            request.url,
            request.host,
            request.path,
            json.dumps(request.headers),
            request.body,
            request.timestamp,
            json.dumps(request.tags),
            request.notes,
            request.fingerprint,
            request.response.status if request.response else None,
            json.dumps(request.response.headers) if request.response else None,
            request.response.body if request.response else None,
            request.response.time_ms if request.response else None,
            json.dumps(request.response.anomalies) if request.response else None,
        ))
        
        req_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return req_id
    
    def get(self, id: int) -> Optional[Request]:
        """获取单个请求"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM requests WHERE id = ?", (id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return self._row_to_request(row)
    
    def list(
        self,
        host: str = None,
        method: str = None,
        path: str = None,
        has_params: bool = None,
        tags: List[str] = None,
        status: int = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Request]:
        """
        查询请求列表
        
        Args:
            host: 筛选 host
            method: 筛选方法
            path: 路径模糊匹配
            has_params: 是否有参数
            tags: 包含的标签
            status: 响应状态码
            limit: 返回数量
            offset: 偏移量
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM requests WHERE 1=1"
        params = []
        
        if host:
            query += " AND host = ?"
            params.append(host)
        
        if method:
            query += " AND method = ?"
            params.append(method.upper())
        
        if path:
            query += " AND path LIKE ?"
            params.append(f"%{path}%")
        
        if has_params is not None:
            if has_params:
                query += " AND (url LIKE '%?%' OR body != '')"
            else:
                query += " AND url NOT LIKE '%?%' AND body = ''"
        
        if tags:
            for tag in tags:
                query += " AND tags LIKE ?"
                params.append(f'%"{tag}"%')
        
        if status:
            query += " AND resp_status = ?"
            params.append(status)
        
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_request(row) for row in rows]
    
    def search(self, keyword: str, limit: int = 50) -> List[Request]:
        """
        全文搜索
        搜索 URL、body、响应中的关键字
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM requests 
            WHERE url LIKE ? OR body LIKE ? OR resp_body LIKE ?
            ORDER BY id DESC LIMIT ?
        """, (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_request(row) for row in rows]
    
    def count(self, host: str = None) -> int:
        """统计请求数量"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if host:
            cursor.execute("SELECT COUNT(*) FROM requests WHERE host = ?", (host,))
        else:
            cursor.execute("SELECT COUNT(*) FROM requests")
        
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def hosts(self) -> List[str]:
        """获取所有 host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT host FROM requests ORDER BY host")
        hosts = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return hosts
    
    def tag(self, id: int, tags: List[str], note: str = None):
        """给请求添加标签"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 获取现有标签
        cursor.execute("SELECT tags FROM requests WHERE id = ?", (id,))
        row = cursor.fetchone()
        if row:
            existing = json.loads(row[0] or "[]")
            new_tags = list(set(existing + tags))
            
            if note:
                cursor.execute(
                    "UPDATE requests SET tags = ?, notes = ? WHERE id = ?",
                    (json.dumps(new_tags), note, id)
                )
            else:
                cursor.execute(
                    "UPDATE requests SET tags = ? WHERE id = ?",
                    (json.dumps(new_tags), id)
                )
        
        conn.commit()
        conn.close()
    
    def delete(self, id: int):
        """删除请求"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM requests WHERE id = ?", (id,))
        conn.commit()
        conn.close()
    
    def clear(self, host: str = None):
        """清空历史"""
        conn = sqlite3.connect(self.db_path)
        if host:
            conn.execute("DELETE FROM requests WHERE host = ?", (host,))
        else:
            conn.execute("DELETE FROM requests")
        conn.commit()
        conn.close()
    
    # ==================== 导入 ====================
    
    def import_har(self, file_path: str) -> int:
        """
        导入 HAR 文件
        返回导入的请求数量
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            har = json.load(f)
        
        count = 0
        for entry in har.get("log", {}).get("entries", []):
            req_data = entry.get("request", {})
            resp_data = entry.get("response", {})
            
            # 构建请求
            headers = {}
            for h in req_data.get("headers", []):
                headers[h["name"]] = h["value"]
            
            body = ""
            if req_data.get("postData"):
                body = req_data["postData"].get("text", "")
            
            request = Request(
                method=req_data.get("method", "GET"),
                url=req_data.get("url", ""),
                headers=headers,
                body=body,
                timestamp=entry.get("startedDateTime", ""),
            )
            
            # 构建响应
            if resp_data:
                resp_headers = {}
                for h in resp_data.get("headers", []):
                    resp_headers[h["name"]] = h["value"]
                
                resp_body = ""
                if resp_data.get("content"):
                    resp_body = resp_data["content"].get("text", "")
                
                request.response = Response(
                    status=resp_data.get("status", 0),
                    headers=resp_headers,
                    body=resp_body,
                    time_ms=entry.get("time", 0),
                )
            
            self.add(request)
            count += 1
        
        return count
    
    def import_burp_xml(self, file_path: str) -> int:
        """
        导入 Burp Suite XML 导出
        """
        import xml.etree.ElementTree as ET
        import base64
        
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        count = 0
        for item in root.findall(".//item"):
            # 请求
            req_elem = item.find("request")
            if req_elem is None:
                continue
            
            req_raw = req_elem.text or ""
            if req_elem.get("base64") == "true":
                req_raw = base64.b64decode(req_raw).decode('utf-8', errors='ignore')
            
            url = item.findtext("url", "")
            host = item.findtext("host", "")
            
            request = Request.from_raw(req_raw, base_url=f"https://{host}")
            request.url = url
            
            # 响应
            resp_elem = item.find("response")
            if resp_elem is not None:
                resp_raw = resp_elem.text or ""
                if resp_elem.get("base64") == "true":
                    resp_raw = base64.b64decode(resp_raw).decode('utf-8', errors='ignore')
                
                # 解析响应
                lines = resp_raw.split("\r\n")
                if lines:
                    status_line = lines[0]
                    parts = status_line.split(" ")
                    status = int(parts[1]) if len(parts) > 1 else 0
                    
                    headers = {}
                    body_start = 0
                    for i, line in enumerate(lines[1:], 1):
                        if not line:
                            body_start = i + 1
                            break
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip()] = v.strip()
                    
                    body = "\r\n".join(lines[body_start:]) if body_start else ""
                    
                    request.response = Response(
                        status=status,
                        headers=headers,
                        body=body,
                    )
            
            self.add(request)
            count += 1
        
        return count
    
    def import_raw(self, file_path: str, base_url: str = "") -> int:
        """导入原始 HTTP 请求文件"""
        with open(file_path, 'r', encoding='utf-8') as f:
            raw = f.read()
        
        request = Request.from_raw(raw, base_url=base_url)
        return self.add(request)
    
    # ==================== 导出 ====================
    
    def export_json(self, file_path: str, host: str = None):
        """导出为 JSON"""
        requests = self.list(host=host, limit=10000)
        data = [req.to_dict() for req in requests]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def export_har(self, file_path: str, host: str = None):
        """导出为 HAR 格式"""
        requests = self.list(host=host, limit=10000)
        
        entries = []
        for req in requests:
            entry = {
                "startedDateTime": req.timestamp,
                "request": {
                    "method": req.method,
                    "url": req.url,
                    "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                    "postData": {"text": req.body} if req.body else None,
                },
                "response": {
                    "status": req.response.status if req.response else 0,
                    "headers": [{"name": k, "value": v} for k, v in (req.response.headers if req.response else {}).items()],
                    "content": {"text": req.response.body if req.response else ""},
                } if req.response else None,
                "time": req.response.time_ms if req.response else 0,
            }
            entries.append(entry)
        
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "AIBURP", "version": "1.0"},
                "entries": entries,
            }
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(har, f, indent=2, ensure_ascii=False)
    
    # ==================== 内部方法 ====================
    
    def _row_to_request(self, row) -> Request:
        """数据库行转 Request 对象"""
        request = Request(
            id=row["id"],
            method=row["method"],
            url=row["url"],
            headers=json.loads(row["headers"] or "{}"),
            body=row["body"] or "",
            timestamp=row["timestamp"] or "",
            tags=json.loads(row["tags"] or "[]"),
            notes=row["notes"] or "",
        )
        
        if row["resp_status"]:
            request.response = Response(
                status=row["resp_status"],
                headers=json.loads(row["resp_headers"] or "{}"),
                body=row["resp_body"] or "",
                time_ms=row["resp_time_ms"] or 0,
                anomalies=json.loads(row["resp_anomalies"] or "[]"),
            )
        
        return request
    
    # ==================== 给 AI 用的接口 ====================
    
    def summary(self) -> Dict:
        """
        返回历史摘要（给 AI 快速了解）
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM requests")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT DISTINCT host FROM requests")
        hosts = [row[0] for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT method, COUNT(*) FROM requests 
            GROUP BY method ORDER BY COUNT(*) DESC
        """)
        methods = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT resp_status, COUNT(*) FROM requests 
            WHERE resp_status IS NOT NULL
            GROUP BY resp_status ORDER BY COUNT(*) DESC
        """)
        statuses = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            "total_requests": total,
            "hosts": hosts,
            "methods": methods,
            "status_codes": statuses,
        }
    
    def to_json_for_ai(self, limit: int = 20) -> str:
        """
        返回 JSON 格式的历史（给 AI 看）
        """
        requests = self.list(limit=limit)
        data = {
            "summary": self.summary(),
            "recent_requests": [
                {
                    "id": req.id,
                    "method": req.method,
                    "url": req.url,
                    "params": req.all_param_names,
                    "status": req.response.status if req.response else None,
                }
                for req in requests
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ==================== 增强功能 ====================
    
    def similar(self, request: Request, threshold: float = 0.7) -> List[Request]:
        """
        找相似请求 (参数结构相似)
        
        Args:
            request: 参考请求
            threshold: 相似度阈值 (0-1)
        
        Returns:
            相似请求列表
        """
        # 获取参考请求的特征
        ref_params = set(request.all_param_names)
        ref_path_parts = request.path.strip("/").split("/")
        
        similar_requests = []
        
        for req in self.list(limit=1000):
            if req.id == request.id:
                continue
            
            # 计算相似度
            score = 0.0
            
            # 1. 参数名相似度
            req_params = set(req.all_param_names)
            if ref_params and req_params:
                param_overlap = len(ref_params & req_params) / max(len(ref_params), len(req_params))
                score += param_overlap * 0.5
            
            # 2. 路径结构相似度
            req_path_parts = req.path.strip("/").split("/")
            if ref_path_parts and req_path_parts:
                # 相同深度
                if len(ref_path_parts) == len(req_path_parts):
                    score += 0.2
                # 相同前缀
                common_prefix = 0
                for a, b in zip(ref_path_parts, req_path_parts):
                    if a == b:
                        common_prefix += 1
                    else:
                        break
                if common_prefix > 0:
                    score += 0.2 * (common_prefix / len(ref_path_parts))
            
            # 3. 方法相同
            if req.method == request.method:
                score += 0.1
            
            if score >= threshold:
                similar_requests.append(req)
        
        return similar_requests
    
    def diff(self, req1: Request, req2: Request) -> Dict:
        """
        对比两个请求/响应
        
        Args:
            req1: 请求1
            req2: 请求2
        
        Returns:
            差异信息
        """
        diff_result = {
            "request_diff": {},
            "response_diff": {},
        }
        
        # 请求差异
        if req1.method != req2.method:
            diff_result["request_diff"]["method"] = [req1.method, req2.method]
        
        if req1.path != req2.path:
            diff_result["request_diff"]["path"] = [req1.path, req2.path]
        
        # 参数差异
        params1 = dict(req1.params)
        params2 = dict(req2.params)
        
        param_diff = {}
        all_keys = set(params1.keys()) | set(params2.keys())
        for key in all_keys:
            v1 = params1.get(key)
            v2 = params2.get(key)
            if v1 != v2:
                param_diff[key] = [v1, v2]
        
        if param_diff:
            diff_result["request_diff"]["params"] = param_diff
        
        # 响应差异
        if req1.response and req2.response:
            resp1, resp2 = req1.response, req2.response
            
            if resp1.status != resp2.status:
                diff_result["response_diff"]["status"] = [resp1.status, resp2.status]
            
            len_diff = abs(len(resp1.body or "") - len(resp2.body or ""))
            if len_diff > 100:
                diff_result["response_diff"]["length_diff"] = len_diff
            
            time_diff = abs((resp1.time_ms or 0) - (resp2.time_ms or 0))
            if time_diff > 500:
                diff_result["response_diff"]["time_diff_ms"] = time_diff
        
        return diff_result
    
    def timeline(self, host: str = None, limit: int = 100) -> List[Dict]:
        """
        按时间线查看请求
        
        Args:
            host: 筛选 host
            limit: 返回数量
        
        Returns:
            时间线数据
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if host:
            cursor.execute("""
                SELECT id, method, url, timestamp, resp_status, tags
                FROM requests WHERE host = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (host, limit))
        else:
            cursor.execute("""
                SELECT id, method, url, timestamp, resp_status, tags
                FROM requests ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        timeline = []
        for row in rows:
            timeline.append({
                "id": row["id"],
                "method": row["method"],
                "url": row["url"],
                "timestamp": row["timestamp"],
                "status": row["resp_status"],
                "tags": json.loads(row["tags"] or "[]"),
            })
        
        return timeline
    
    def attack_surface(self) -> Dict:
        """
        自动识别攻击面
        
        Returns:
            攻击面分析结果
        """
        requests = self.list(limit=5000)
        
        surface = {
            "endpoints": {},  # path -> {methods, params, status_codes}
            "params_by_type": {
                "id_params": [],      # 可能的 IDOR
                "file_params": [],    # 可能的 LFI/Path Traversal
                "url_params": [],     # 可能的 SSRF
                "search_params": [],  # 可能的 SQLi/XSS
                "auth_params": [],    # 认证相关
            },
            "interesting_responses": [],
            "potential_vulns": [],
        }
        
        # 参数名模式
        id_patterns = ["id", "uid", "pid", "user_id", "product_id", "order_id", "doc_id"]
        file_patterns = ["file", "path", "document", "folder", "dir", "src", "source"]
        url_patterns = ["url", "link", "redirect", "callback", "next", "return", "goto"]
        search_patterns = ["q", "query", "search", "keyword", "s", "term", "filter"]
        auth_patterns = ["token", "key", "api_key", "auth", "session", "jwt", "password"]
        
        for req in requests:
            # 分析端点
            path = req.path.split("?")[0]
            if path not in surface["endpoints"]:
                surface["endpoints"][path] = {
                    "methods": set(),
                    "params": set(),
                    "status_codes": set(),
                }
            
            surface["endpoints"][path]["methods"].add(req.method)
            surface["endpoints"][path]["params"].update(req.all_param_names)
            if req.response:
                surface["endpoints"][path]["status_codes"].add(req.response.status)
            
            # 分析参数
            for param in req.all_param_names:
                param_lower = param.lower()
                param_info = {"param": param, "url": req.url, "id": req.id}
                
                if any(p in param_lower for p in id_patterns):
                    surface["params_by_type"]["id_params"].append(param_info)
                elif any(p in param_lower for p in file_patterns):
                    surface["params_by_type"]["file_params"].append(param_info)
                elif any(p in param_lower for p in url_patterns):
                    surface["params_by_type"]["url_params"].append(param_info)
                elif any(p in param_lower for p in search_patterns):
                    surface["params_by_type"]["search_params"].append(param_info)
                elif any(p in param_lower for p in auth_patterns):
                    surface["params_by_type"]["auth_params"].append(param_info)
            
            # 分析响应
            if req.response:
                # 错误信息泄露
                body_lower = (req.response.body or "").lower()
                if any(err in body_lower for err in ["error", "exception", "stack trace", "sql", "syntax"]):
                    surface["interesting_responses"].append({
                        "id": req.id,
                        "url": req.url,
                        "reason": "可能的错误信息泄露",
                    })
                
                # 敏感信息
                if any(s in body_lower for s in ["password", "secret", "api_key", "token"]):
                    surface["interesting_responses"].append({
                        "id": req.id,
                        "url": req.url,
                        "reason": "可能的敏感信息泄露",
                    })
        
        # 转换 set 为 list (JSON 序列化)
        for path, info in surface["endpoints"].items():
            info["methods"] = list(info["methods"])
            info["params"] = list(info["params"])
            info["status_codes"] = list(info["status_codes"])
        
        # 去重
        for key in surface["params_by_type"]:
            seen = set()
            unique = []
            for item in surface["params_by_type"][key]:
                if item["param"] not in seen:
                    seen.add(item["param"])
                    unique.append(item)
            surface["params_by_type"][key] = unique[:20]  # 限制数量
        
        surface["interesting_responses"] = surface["interesting_responses"][:20]
        
        return surface
    
    def dedupe(self) -> int:
        """
        去重 (删除相同指纹的请求)
        
        Returns:
            删除的请求数量
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 找出重复的指纹
        cursor.execute("""
            SELECT fingerprint, COUNT(*) as cnt, MIN(id) as keep_id
            FROM requests
            WHERE fingerprint IS NOT NULL AND fingerprint != ''
            GROUP BY fingerprint
            HAVING cnt > 1
        """)
        
        duplicates = cursor.fetchall()
        deleted = 0
        
        for fingerprint, count, keep_id in duplicates:
            cursor.execute("""
                DELETE FROM requests
                WHERE fingerprint = ? AND id != ?
            """, (fingerprint, keep_id))
            deleted += count - 1
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def stats(self) -> Dict:
        """
        统计信息
        
        Returns:
            详细统计
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # 总数
        cursor.execute("SELECT COUNT(*) FROM requests")
        stats["total_requests"] = cursor.fetchone()[0]
        
        # 按 host 统计
        cursor.execute("""
            SELECT host, COUNT(*) FROM requests
            GROUP BY host ORDER BY COUNT(*) DESC LIMIT 20
        """)
        stats["by_host"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 按方法统计
        cursor.execute("""
            SELECT method, COUNT(*) FROM requests
            GROUP BY method ORDER BY COUNT(*) DESC
        """)
        stats["by_method"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 按状态码统计
        cursor.execute("""
            SELECT resp_status, COUNT(*) FROM requests
            WHERE resp_status IS NOT NULL
            GROUP BY resp_status ORDER BY COUNT(*) DESC
        """)
        stats["by_status"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 按标签统计
        cursor.execute("SELECT tags FROM requests WHERE tags IS NOT NULL")
        tag_counts = {}
        for row in cursor.fetchall():
            tags = json.loads(row[0] or "[]")
            for tag in tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        stats["by_tag"] = dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:20])
        
        # 有参数的请求
        cursor.execute("""
            SELECT COUNT(*) FROM requests
            WHERE url LIKE '%?%' OR body != ''
        """)
        stats["with_params"] = cursor.fetchone()[0]
        
        conn.close()
        
        return stats
