from .base import BaseProtocolProbe, ProbeResult

class SMTPProbe(BaseProtocolProbe):
    protocol_name = 'smtp'
    default_ports = [25, 465, 587]
    max_concurrency = 20

    @property
    def probe_packet(self) -> bytes:
        return b''

    def parse_response(self, response: bytes) -> ProbeResult:
        try:
            text = response.decode('utf-8', errors='ignore').strip()
            if text.startswith('220'):
                banner = text[4:].strip()
                if banner.startswith('-'):
                    banner = banner[1:].strip()
                return ProbeResult(protocol='smtp', is_match=True, confidence=1.0, banner=banner, config={'welcome': text})
        except:
            pass
        return ProbeResult(protocol='smtp', is_match=False, confidence=0)
