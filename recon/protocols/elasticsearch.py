"""
Recon Pipeline V2 - Elasticsearch 协议探测

检测未授权访问和版本信息。
"""
from .base import BaseProtocolProbe, ProbeResult


class ElasticsearchProbe(BaseProtocolProbe):
    """Elasticsearch 协议探测"""

    protocol_name = "elasticsearch"
    default_ports = [9200, 9300]
    max_concurrency = 30

    @property
    def probe_packet(self) -> bytes:
        # HTTP GET / 请求（Elasticsearch 使用 HTTP 协议）
        return b"GET / HTTP/1.0\r\nHost: probe\r\nAccept: */*\r\n\r\n"

    def parse_response(self, response: bytes) -> ProbeResult:
        try:
            text = response.decode('utf-8', errors='ignore')

            # 检查是否是 Elasticsearch 的 JSON 响应
            if '"cluster_name"' in text or '"number"' in text:
                import re

                # 提取版本号
                version = ""
                match = re.search(r'"number"\s*:\s*"(\d+\.\d+\.\d+)"', text)
                if match:
                    version = match.group(1)

                # 提取集群名称
                cluster = ""
                match = re.search(r'"cluster_name"\s*:\s*"([^"]+)"', text)
                if match:
                    cluster = match.group(1)

                return ProbeResult(
                    protocol="elasticsearch",
                    is_match=True,
                    confidence=1.0,
                    banner=f"ES {version}".strip(),
                    version=version,
                    config={
                        "cluster_name": cluster,
                        "unauthenticated": True,
                    },
                )

            # HTTP 200 且包含 tagline
            if "HTTP/" in text and "know" in text.lower():
                return ProbeResult(
                    protocol="elasticsearch",
                    is_match=True,
                    confidence=0.9,
                    banner="Elasticsearch",
                )
        except:
            pass

        return ProbeResult(protocol="elasticsearch", is_match=False, confidence=0)
