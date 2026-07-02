
import os
import json
import datetime
import uuid
from typing import Dict, List, Optional, Any
from aiburp.prompts import PromptTemplates
from aiburp.memory import MemoryManager
# Import core tools
from aiburp import SmartBurp

class SecurityOrchestrator:
    """
    Security Orchestrator for AI-Burp.
    Coordinates between LLM (via Prompts), RAG Memory, and Security Tools.
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.audit_dir = ".audit"
        self.state_file = os.path.join(self.audit_dir, f"{project_id}.json")
        
        # Initialize components
        self.memory = MemoryManager(project_id)
        self.burp = SmartBurp() # Assuming SmartBurp can be instantiated without args for now
        
        # Ensure audit dir exists
        if not os.path.exists(self.audit_dir):
            os.makedirs(self.audit_dir)
            
        # Load or initialize state
        self.state = self.load_state()

    def load_state(self) -> Dict:
        """Load project state from JSON file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading state: {e}")
                
        # Return default empty state
        return {
            "meta": {
                "project_id": self.project_id,
                "created": datetime.datetime.now().isoformat(),
                "last_updated": datetime.datetime.now().isoformat(),
                "status": "initialized"
            },
            "target": {},
            "progress": {
                "phase": "init",
                "current_task": "Initialization",
                "completed_tasks": []
            },
            "findings": [],
            "exploration": {
                "tried": [],
                "pending": []
            }
        }

    def save_state(self, state: Dict = None) -> None:
        """Save current state to JSON file."""
        if state:
            self.state = state
        
        # Update timestamp
        self.state["meta"]["last_updated"] = datetime.datetime.now().isoformat()
        
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving state: {e}")

    def set_target(self, type: str, **kwargs) -> None:
        """Set or update the audit target."""
        self.state["target"] = {
            "type": type,
            **kwargs
        }
        self.save_state()

    # ========== Prompt Generation ==========

    def generate_recovery_prompt(self) -> str:
        """Generate a prompt to recover context for a new session."""
        
        # 1. Gather data from State
        target = self.state.get("target", {})
        progress = self.state.get("progress", {})
        findings = self.state.get("findings", [])
        exploration = self.state.get("exploration", {})
        
        # Format lists for template
        completed_tasks_block = "\n".join([f"✅ {t}" for t in progress.get("completed_tasks", [])])
        if not completed_tasks_block: completed_tasks_block = "(暂无)"

        findings_block = ""
        for i, f in enumerate(findings, 1):
            findings_block += f"{i}. [{f.get('severity', 'info')}] {f.get('title', 'Unknown')} ({f.get('location', '')})\n"
            findings_block += f"   - {f.get('details', '')}\n"
        if not findings_block: findings_block = "(暂无)"

        explorations_block = ""
        for e in exploration.get("tried", []):
            explorations_block += f"❌ {e.get('path')} - {e.get('reason')}\n"
        if not explorations_block: explorations_block = "(暂无)"

        pending_block = "\n".join([f"- [ ] {p}" for p in exploration.get("pending", [])])
        if not pending_block: pending_block = "(暂无)"

        # 2. Gather data from Memory (RAG)
        # Get 'code' type memory items
        code_items = self.memory.get_all(type="code")
        context_chunks_block = self.memory.format_for_prompt(code_items)
        if not context_chunks_block: context_chunks_block = "(暂无)"

        # 3. Fill Template
        prompt = PromptTemplates.TASK_RECOVERY.format(
            project_name=self.project_id,
            target_type=target.get("type", "Unknown"),
            version=target.get("version", "Unknown"),
            goal=target.get("goal", "Security Audit"),
            phase=progress.get("phase", "Unknown"),
            current_task=progress.get("current_task", "None"),
            last_updated=self.state["meta"]["last_updated"],
            completed_tasks_block=completed_tasks_block,
            findings_block=findings_block,
            explorations_block=explorations_block,
            pending_block=pending_block,
            context_chunks_block=context_chunks_block
        )
        
        return prompt

    def generate_researcher_prompt(self) -> str:
        return PromptTemplates.RESEARCHER_ROLE

    # ========== Finding Management ==========

    def add_finding(self, finding: Dict) -> str:
        """Add a finding to state and memory."""
        finding_id = finding.get("id") or str(uuid.uuid4())
        finding["id"] = finding_id
        
        # Add to state
        self.state["findings"].append(finding)
        self.save_state()
        
        # Add to memory
        self.memory.add_finding(
            content=finding.get("title", ""),
            severity=finding.get("severity", "info"),
            file=finding.get("location", ""),
            line=finding.get("line", 0),
            **finding
        )
        
        return finding_id

    # ========== Progress Management ==========

    def update_progress(self, task: str, status: str) -> None:
        """Update current task and add to completed if done."""
        if status == "completed":
            self.state["progress"]["completed_tasks"].append(task)
        elif status == "started":
            self.state["progress"]["current_task"] = task
        self.save_state()

    def add_exploration(self, path: str, result: str, reason: str) -> None:
        """Record an exploration attempt."""
        entry = {"path": path, "result": result, "reason": reason}
        self.state["exploration"]["tried"].append(entry)
        self.save_state()
        
        self.memory.add_exploration(path, result, reason)

    # ========== AI-Burp Integration (Proxies) ==========

    async def run_scan(self, target: str):
        """Run vulnerability scan using AI-Burp."""
        # Use simple sync wrapper if AsyncBurp is complex to invoke here directly,
        # or assume caller handles async loop.
        # For now, just a placeholder linking to burp
        pass

