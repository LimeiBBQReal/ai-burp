
import logging
import datetime
import json
import os
import uuid
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class ContextItem:
    def __init__(self, id: str, content: str, type: str, metadata: dict, timestamp: datetime.datetime = None):
        self.id = id
        self.content = content
        self.type = type
        self.metadata = metadata
        self.timestamp = timestamp or datetime.datetime.now()

    def to_dict(self):
        return {
            "id": self.id,
            "content": self.content,
            "type": self.type,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            id=data["id"],
            content=data["content"],
            type=data["type"],
            metadata=data["metadata"],
            timestamp=datetime.datetime.fromisoformat(data["timestamp"])
        )

class MemoryManager:
    """
    RAG Memory Manager. 
    Uses mem0 if available, otherwise falls back to local JSON storage.
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.use_mem0 = False
        self.mem0_client = None
        self.local_memory: List[ContextItem] = []
        self.fallback_file = f".audit/memory_{project_id}.json"
        
        try:
            # Try importing mem0
            # Note: The user mentioned mem0ai as the package name in design doc
            from mem0 import Memory
            self.mem0_client = Memory()
            self.use_mem0 = True
            logger.info("Successfully initialized mem0 for memory management.")
        except ImportError:
            logger.warning("mem0 package not found. Using local JSON fallback for memory.")
            self._ensure_audit_dir()
            self._load_fallback()

    def _ensure_audit_dir(self):
        if not os.path.exists(".audit"):
            os.makedirs(".audit")

    def _load_fallback(self):
        if os.path.exists(self.fallback_file):
            try:
                with open(self.fallback_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.local_memory = [ContextItem.from_dict(item) for item in data]
            except Exception as e:
                logger.error(f"Failed to load memory fallback: {e}")

    def _save_fallback(self):
        try:
            data = [item.to_dict() for item in self.local_memory]
            with open(self.fallback_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save memory fallback: {e}")

    def _add(self, content: str, type: str, metadata: dict) -> str:
        """Internal add method handling both mem0 and fallback"""
        # Ensure project_id and type are in metadata
        metadata['project_id'] = self.project_id
        metadata['type'] = type
        
        if self.use_mem0:
            # mem0 add
            # mem0 signature: add(messages, user_id=..., metadata=...)
            # We map project_id to user_id for isolation
            self.mem0_client.add(content, user_id=self.project_id, metadata=metadata)
            # return a placeholder ID or try to get it if mem0 returns it
            return str(uuid.uuid4()) 
        else:
            # Fallback
            item_id = str(uuid.uuid4())
            item = ContextItem(item_id, content, type, metadata)
            self.local_memory.append(item)
            self._save_fallback()
            return item_id

    def add_code(self, content: str, file: str, line: int, **kwargs) -> str:
        metadata = kwargs
        metadata.update({'file': file, 'line': line})
        return self._add(content, "code", metadata)

    def add_finding(self, content: str, severity: str, file: str, line: int, **kwargs) -> str:
        metadata = kwargs
        metadata.update({'severity': severity, 'file': file, 'line': line})
        return self._add(content, "finding", metadata)

    def add_exploration(self, path: str, result: str, reason: str, **kwargs) -> str:
        metadata = kwargs
        metadata.update({'path': path, 'result': result, 'reason': reason})
        return self._add(content=f"Path: {path}, Result: {result}, Reason: {reason}", type="exploration", metadata=metadata)

    def add_instruction(self, content: str, priority: str = "normal", **kwargs) -> str:
        metadata = kwargs
        metadata.update({'priority': priority})
        return self._add(content, "instruction", metadata)

    def search(self, query: str, type: str = None, limit: int = 10) -> List[ContextItem]:
        if self.use_mem0:
            # mem0 search
            # mem0 signature: search(query, user_id=..., limit=...)
            results = self.mem0_client.search(query, user_id=self.project_id, limit=limit)
            # Convert mem0 results to ContextItem
            # mem0 result usually has 'memory', 'metadata', etc.
            # Assuming mem0 returns a list of dictionaries
            items = []
            for r in results:
                # Check if type matches if specified
                meta = r.get('metadata', {})
                if type and meta.get('type') != type:
                    continue
                    
                items.append(ContextItem(
                    id=r.get('id', 'unknown'),
                    content=r.get('memory', ''),
                    type=meta.get('type', 'unknown'),
                    metadata=meta,
                    timestamp=datetime.datetime.now() # mem0 might not return timestamp directly easily
                ))
            return items
        else:
            # Naive local search
            results = []
            query_lower = query.lower()
            for item in self.local_memory:
                if type and item.type != type:
                    continue
                if query_lower in item.content.lower():
                    results.append(item)
            return results[:limit]

    def get_all(self, type: str = None) -> List[ContextItem]:
        if self.use_mem0:
            # mem0.get_all(user_id=...)
            results = self.mem0_client.get_all(user_id=self.project_id)
            items = []
            for r in results:
                meta = r.get('metadata', {})
                if type and meta.get('type') != type:
                    continue
                items.append(ContextItem(
                    id=r.get('id', 'unknown'),
                    content=r.get('memory', ''),
                    type=meta.get('type', 'unknown'),
                    metadata=meta,
                    timestamp=datetime.datetime.now()
                ))
            return items
        else:
            if type:
                return [i for i in self.local_memory if i.type == type]
            return self.local_memory

    def format_for_prompt(self, items: List[ContextItem]) -> str:
        lines = []
        for item in items:
            meta_str = ", ".join([f"{k}={v}" for k, v in item.metadata.items() if k != 'project_id' and k != 'type'])
            lines.append(f"- [{item.type.upper()}] {item.content} ({meta_str})")
        return "\n".join(lines)

    def clear(self, type: str = None):
        if self.use_mem0:
             # mem0 might define delete_all or similar
             # For now, just pass
             pass
        else:
            if type:
                self.local_memory = [i for i in self.local_memory if i.type != type]
            else:
                self.local_memory = []
            self._save_fallback()

