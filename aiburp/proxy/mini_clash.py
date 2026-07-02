"""
mini_clash.py — 适合大模型使用的简易 Clash
封装 mihomo 二进制, 提供简洁 API, 无 GUI, 无 TUN, 无复杂规则

核心设计:
- 入站: SOCKS5 + HTTP (mixed-port)
- 出站: 复用 mihomo 的全协议栈 (hysteria2/anytls/trojan/vless/ws 等)
- 路由: global 模式 (所有流量走选中节点), 不做规则匹配
- 控制: Python API + 可选 HTTP API

使用方式:
    from mini_clash import MiniClash
    mc = MiniClash(config_path="filtered_proxies.yaml")
    mc.start()
    mc.list_nodes()              # 列出所有节点
    mc.switch_node("JP-Narita-...")  # 切换节点
    mc.test_delay("JP-Narita-...")   # 测试延迟
    mc.get_exit_ip()             # 查出口 IP
    # 使用代理: socks5://127.0.0.1:7890 或 http://127.0.0.1:7890
    mc.stop()
"""
import os
import sys
import json
import time
import yaml
import shutil
import socket
import subprocess
import urllib.parse
import requests
from typing import Optional, List, Dict, Any


# mihomo 二进制路径 (自动查找)
def find_mihomo_binary() -> str:
    """自动查找 mihomo 二进制"""
    # 1. 环境变量
    env_path = os.environ.get("MIHOMO_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    # 2. 常见路径
    candidates = [
        r"E:\Program Files\Clash Party\resources\sidecar\mihomo.exe",
        r"E:\Program Files\Clash Party\resources\sidecar\mihomo-alpha.exe",
        r"E:\Program Files\Clash Party\resources\sidecar\mihomo-smart.exe",
        "/usr/local/bin/mihomo",
        "/usr/bin/mihomo",
        "mihomo",  # PATH
    ]
    for c in candidates:
        if os.path.isfile(c) or shutil.which(c):
            return c
    raise FileNotFoundError("mihomo binary not found, set MIHOMO_PATH env var")


class MiniClash:
    """简易 Clash: 封装 mihomo, 提供大模型友好的 API"""

    def __init__(
        self,
        config_path: Optional[str] = None,
        mixed_port: int = 7890,
        ctrl_port: int = 9090,
        work_dir: Optional[str] = None,
        mihomo_path: Optional[str] = None,
        auto_port: bool = True,
    ):
        """
        Args:
            config_path: YAML 配置文件路径 (Clash 格式). None 则不加载.
            mixed_port: SOCKS5+HTTP 混合端口. auto_port=True 时自动找空闲端口.
            ctrl_port: mihomo API 控制端口. auto_port=True 时自动找空闲端口.
            work_dir: mihomo 工作目录 (存配置/缓存). None 则用临时目录.
            mihomo_path: mihomo 二进制路径. None 则自动查找.
            auto_port: True 时自动找空闲端口, 避免冲突.
        """
        self.config_path = config_path
        self.mixed_port = self._find_free_port() if auto_port else mixed_port
        self.ctrl_port = self._find_free_port() if auto_port else ctrl_port
        self.work_dir = work_dir or os.path.join(
            tempfile.gettempdir() if (tempfile := __import__("tempfile")) else ".",
            f"mini_clash_{os.getpid()}"
        )
        self.mihomo_path = mihomo_path or find_mihomo_binary()
        self.proc: Optional[subprocess.Popen] = None
        self._base_url = f"http://127.0.0.1:{self.ctrl_port}"
        self._original_config: Optional[dict] = None
        # 默认用 socks5h (远程 DNS 解析), 避免 DNS 泄漏和本地解析问题
        self._proxy_url = f"socks5h://127.0.0.1:{self.mixed_port}"
        self._http_proxy_url = f"http://127.0.0.1:{self.mixed_port}"

    @staticmethod
    def _find_free_port() -> int:
        """找一个空闲端口"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    @staticmethod
    def _is_port_free(port: int) -> bool:
        """检查端口是否空闲"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return True
        except OSError:
            return False

    def _prepare_config(self) -> str:
        """准备 mihomo 配置文件 (覆盖端口, global 模式, 简化规则)"""
        if self.config_path and os.path.isfile(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
        else:
            config = {}
        self._original_config = config

        # 覆盖关键字段
        config["mixed-port"] = self.mixed_port
        config["external-controller"] = f"127.0.0.1:{self.ctrl_port}"
        config["mode"] = "global"
        config["log-level"] = "warning"
        config["allow-lan"] = False
        # 不启用 TUN (大模型不需要)
        config.pop("tun", None)

        # 简化 DNS (不用 fake-ip, 避免复杂)
        config["dns"] = {
            "enable": True,
            "ipv6": False,
            "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"],
        }

        # 确保 proxy-groups 有 GLOBAL 组
        proxies = config.get("proxies", [])
        if proxies:
            all_names = [p.get("name", "") for p in proxies]
            proxy_groups = config.get("proxy-groups", [])
            # 检查是否已有 GLOBAL 组
            has_global = any(g.get("name") == "GLOBAL" for g in proxy_groups)
            if not has_global:
                proxy_groups.insert(0, {
                    "name": "GLOBAL",
                    "type": "select",
                    "proxies": all_names + ["DIRECT"],
                })
            config["proxy-groups"] = proxy_groups
            # 简化 rules
            config["rules"] = ["MATCH,GLOBAL"]

        os.makedirs(self.work_dir, exist_ok=True)
        config_file = os.path.join(self.work_dir, "config.yaml")
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        return config_file

    def start(self, timeout: float = 10.0) -> bool:
        """启动 mihomo 实例"""
        if self.proc is not None and self.proc.poll() is None:
            print(f"[!] mihomo already running")
            return True

        config_file = self._prepare_config()
        print(f"[*] starting mini-clash:")
        print(f"    mixed-port: {self.mixed_port} (socks5+http)")
        print(f"    ctrl-port:  {self.ctrl_port} (api)")
        print(f"    work-dir:   {self.work_dir}")
        print(f"    config:     {config_file}")

        self.proc = subprocess.Popen(
            [self.mihomo_path, "-f", config_file, "-d", self.work_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )

        # 等待 mihomo 就绪
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                # 进程已退出
                out = self.proc.stdout.read().decode("utf-8", errors="replace") if self.proc.stdout else ""
                print(f"[!] mihomo exited early:\n{out[:500]}")
                return False
            try:
                r = requests.get(f"{self._base_url}/version", timeout=1)
                if r.status_code == 200:
                    v = r.json().get("version", "?")
                    print(f"[+] mihomo ready (version: {v})")
                    return True
            except Exception:
                pass
            time.sleep(0.3)

        print(f"[!] mihomo start timeout ({timeout}s)")
        self.stop()
        return False

    def stop(self) -> bool:
        """停止 mihomo 实例"""
        if self.proc is None:
            return True
        if self.proc.poll() is None:
            print(f"[*] stopping mihomo...")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        self.proc = None
        print(f"[+] mihomo stopped")
        return True

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    # ============ API ============

    def _api_get(self, path: str, timeout: float = 5.0) -> Optional[Any]:
        """GET mihomo API"""
        try:
            r = requests.get(f"{self._base_url}{path}", timeout=timeout)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    def _api_put(self, path: str, json_body: dict, timeout: float = 5.0) -> bool:
        """PUT mihomo API"""
        try:
            r = requests.put(f"{self._base_url}{path}", json=json_body, timeout=timeout)
            return r.status_code in (200, 204)
        except Exception:
            return False

    def list_nodes(self) -> List[Dict[str, Any]]:
        """列出所有节点 (返回 [{name, type, server, port}, ...])"""
        data = self._api_get("/proxies")
        if not data:
            return []
        proxies = data.get("proxies", {})
        nodes = []
        for name, info in proxies.items():
            # 跳过特殊组 (DIRECT/REJECT/GLOBAL 等)
            if name in ("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"):
                continue
            if info.get("type") in ("Selector", "URLTest", "Fallback", "LoadBalance"):
                continue
            nodes.append({
                "name": name,
                "type": info.get("type", ""),
                "server": info.get("server", "") if isinstance(info.get("server"), str) else "",
                "port": info.get("port", 0) if isinstance(info.get("port"), int) else 0,
            })
        return nodes

    def list_groups(self) -> List[Dict[str, Any]]:
        """列出所有代理组 (返回 [{name, type, now, all}, ...])"""
        data = self._api_get("/proxies")
        if not data:
            return []
        proxies = data.get("proxies", {})
        groups = []
        for name, info in proxies.items():
            if info.get("type") in ("Selector", "URLTest", "Fallback", "LoadBalance"):
                groups.append({
                    "name": name,
                    "type": info.get("type", ""),
                    "now": info.get("now", ""),
                    "all": info.get("all", []),
                })
        return groups

    def switch_node(self, node_name: str, group: str = "GLOBAL") -> bool:
        """切换节点 (默认切换 GLOBAL 组)"""
        encoded = urllib.parse.quote(group, safe="")
        ok = self._api_put(f"/proxies/{encoded}", {"name": node_name})
        if ok:
            print(f"[+] switched {group} -> {node_name}")
        else:
            print(f"[!] switch failed: {group} -> {node_name}")
        return ok

    def get_current_node(self, group: str = "GLOBAL") -> str:
        """获取当前选中节点"""
        encoded = urllib.parse.quote(group, safe="")
        data = self._api_get(f"/proxies/{encoded}")
        if data:
            return data.get("now", "")
        return ""

    def test_delay(self, node_name: str, url: str = "http://www.gstatic.com/generate_204",
                   timeout: int = 5000) -> int:
        """测试节点延迟 (ms), 返回 -1 表示失败"""
        encoded = urllib.parse.quote(node_name, safe="")
        test_url = urllib.parse.quote(url, safe="")
        try:
            r = requests.get(
                f"{self._base_url}/proxies/{encoded}/delay?url={test_url}&timeout={timeout}",
                timeout=timeout / 1000 + 3,
            )
            if r.status_code == 200:
                return r.json().get("delay", -1)
        except Exception:
            pass
        return -1

    def test_all_delay(self, url: str = "http://www.gstatic.com/generate_204",
                       timeout: int = 5000) -> Dict[str, int]:
        """测试所有节点延迟, 返回 {name: delay_ms}, -1 表示失败"""
        nodes = self.list_nodes()
        results = {}
        for i, n in enumerate(nodes, 1):
            name = n["name"]
            delay = self.test_delay(name, url, timeout)
            results[name] = delay
            status = f"{delay}ms" if delay > 0 else "FAIL"
            print(f"  [{i}/{len(nodes)}] {status:>8}  {name}")
        return results

    def get_exit_ip(self, timeout: float = 10.0) -> Optional[Dict[str, str]]:
        """通过代理访问 ip-api 获取出口 IP 信息"""
        try:
            r = requests.get(
                "http://ip-api.com/json",
                proxies={"http": self._proxy_url, "https": self._proxy_url},
                timeout=timeout,
            )
            if r.status_code == 200:
                j = r.json()
                return {
                    "ip": j.get("query", ""),
                    "country": j.get("country", ""),
                    "countryCode": j.get("countryCode", ""),
                    "region": j.get("regionName", ""),
                    "city": j.get("city", ""),
                    "isp": j.get("isp", ""),
                }
        except Exception as e:
            print(f"[!] get_exit_ip failed: {e}")
        return None

    def proxy_url(self, scheme: str = "socks5h") -> str:
        """返回代理 URL (供 requests/curl 等使用)
        默认 socks5h (远程 DNS 解析), 可选 socks5/http
        """
        return f"{scheme}://127.0.0.1:{self.mixed_port}"

    def fetch(self, url: str, timeout: float = 30.0, **kwargs) -> requests.Response:
        """通过代理访问 URL (便捷方法)"""
        proxies = {"http": self._proxy_url, "https": self._proxy_url}
        return requests.get(url, proxies=proxies, timeout=timeout, **kwargs)

    def reload_config(self, config_path: str) -> bool:
        """重新加载配置文件"""
        self.config_path = config_path
        config_file = self._prepare_config()
        # 用 mihomo API 热加载
        ok = self._api_put("/configs", {"path": config_file})
        if ok:
            print(f"[+] config reloaded: {config_path}")
        else:
            # 热加载失败, 重启
            print(f"[!] hot reload failed, restarting...")
            self.stop()
            return self.start()
        return ok

    def status(self) -> Dict[str, Any]:
        """获取 mini-clash 状态"""
        running = self.proc is not None and self.proc.poll() is None
        version = None
        if running:
            v = self._api_get("/version")
            version = v.get("version") if v else None
        return {
            "running": running,
            "version": version,
            "mixed_port": self.mixed_port,
            "ctrl_port": self.ctrl_port,
            "proxy_url": self._proxy_url,
            "http_proxy_url": self._http_proxy_url,
            "current_node": self.get_current_node() if running else "",
            "config_path": self.config_path,
        }


# ============ CLI 入口 (方便命令行使用) ============

def main():
    import argparse
    parser = argparse.ArgumentParser(description="mini-clash: 适合大模型使用的简易 Clash")
    parser.add_argument("-f", "--config", help="YAML 配置文件路径")
    parser.add_argument("-p", "--port", type=int, default=0, help="混合端口 (0=自动)")
    parser.add_argument("--ctrl", type=int, default=0, help="API 控制端口 (0=自动)")
    parser.add_argument("--node", help="启动后切换到指定节点")
    parser.add_argument("--test", action="store_true", help="测试所有节点延迟后退出")
    parser.add_argument("--ip", action="store_true", help="查出口 IP 后退出")
    parser.add_argument("--list", action="store_true", help="列出所有节点后退出")
    parser.add_argument("--keep", action="store_true", help="保持运行 (不退出)")
    args = parser.parse_args()

    mc = MiniClash(
        config_path=args.config,
        mixed_port=args.port if args.port > 0 else 7890,
        ctrl_port=args.ctrl if args.ctrl > 0 else 9090,
        auto_port=(args.port == 0 or args.ctrl == 0),
    )

    if not mc.start():
        sys.exit(1)

    try:
        if args.list:
            nodes = mc.list_nodes()
            print(f"\n[*] {len(nodes)} nodes:")
            for n in nodes:
                print(f"  {n['name']}  ({n['type']}, {n['server']}:{n['port']})")

        if args.node:
            mc.switch_node(args.node)

        if args.test:
            print(f"\n[*] testing all nodes delay...")
            results = mc.test_all_delay()
            ok = sum(1 for v in results.values() if v > 0)
            print(f"\n[*] {ok}/{len(results)} nodes OK")

        if args.ip:
            ip_info = mc.get_exit_ip()
            if ip_info:
                print(f"\n[*] exit IP: {ip_info['ip']} ({ip_info['country']}/{ip_info['city']}, {ip_info['isp']})")

        if args.keep:
            current = mc.get_current_node()
            print(f"\n[*] mini-clash running, proxy: {mc.proxy_url()}")
            print(f"[*] current node: {current}")
            print(f"[*] press Ctrl+C to stop...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print()
    finally:
        mc.stop()


if __name__ == "__main__":
    main()
