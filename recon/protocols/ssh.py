"""
Recon Pipeline V2 - SSH 协议探测
"""
from .base import BaseProtocolProbe, ProbeResult


class SSHProbe(BaseProtocolProbe):
    """SSH 协议探测"""

    protocol_name = "ssh"
    default_ports = [22, 2222, 22222]
    max_concurrency = 20

    @property
    def probe_packet(self) -> bytes:
        # SSH 协议先发送自己的版本标识
        return b"SSH-2.0-ReconBot_1.0\r\n"

    def parse_response(self, response: bytes) -> ProbeResult:
        try:
            banner = response.decode('utf-8', errors='ignore').strip()
            if banner.startswith("SSH-"):
                # 解析 SSH 版本和软件
                parts = banner.split('-')
                if len(parts) >= 3:
                    version = parts[1]
                    software = parts[2]
                    return ProbeResult(
                        protocol="ssh",
                        is_match=True,
                        confidence=1.0,
                        banner=banner,
                        version=software,
                        config={"ssh_version": version, "software": software},
                    )
                return ProbeResult(
                    protocol="ssh",
                    is_match=True,
                    confidence=1.0,
                    banner=banner,
                )
        except:
            pass

        return ProbeResult(protocol="ssh", is_match=False, confidence=0)
