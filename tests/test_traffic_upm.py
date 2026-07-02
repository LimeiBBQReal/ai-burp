"""
V4 统一协议模型 (UPM) 数据结构测试.

覆盖 review 发现的问题:
    - B1: _inject_into_request 的 dict/bytes 分支
    - B4: text/body 不一致检测
    - S4: to_dict/to_json 序列化 (含 bytes raw)
    - R3: bytes payload 不被 repr 化
"""

import json
import warnings
import pytest

from aiburp.traffic import TrafficRequest, TrafficResponse
from aiburp.traffic.base import ProtocolAdapter


class TestTrafficRequest:
    """TrafficRequest 数据结构"""

    def test_basic_creation(self):
        req = TrafficRequest(protocol="tcp", target="x:1", payload=b"data")
        assert req.protocol == "tcp"
        assert req.target == "x:1"
        assert req.payload == b"data"

    def test_with_payload_chain(self):
        """链式 with_payload 返回新请求 (不改原对象)"""
        base = TrafficRequest(protocol="tcp", target="x:1", payload="hello § world")
        new = base.with_payload("injected")
        assert base.payload == "hello § world"  # 原对象不变
        assert new.payload == "injected"
        assert new.target == base.target


class TestInjectIntoRequest:
    """B1: _inject_into_request 的类型分支"""

    def test_str_payload_with_marker(self):
        base = TrafficRequest(protocol="tcp", target="x", payload="CMD § END")
        req = ProtocolAdapter._inject_into_request(base, "PAYLOAD", "§")
        assert req.payload == "CMD PAYLOAD END"

    def test_bytes_payload_with_marker(self):
        """bytes payload 保持 bytes 类型 (不被 str 化)"""
        # § 的 UTF-8 是 \xc2\xa7, bytes 字面量必须用 ASCII
        base = TrafficRequest(protocol="tcp", target="x", payload=b"CMD \xc2\xa7 END")
        req = ProtocolAdapter._inject_into_request(base, "PAYLOAD", "§")
        assert isinstance(req.payload, bytes)
        assert b"PAYLOAD" in req.payload

    def test_bytes_payload_preserves_type(self):
        """R3: bytes 不变成 'b\\'...\\'' repr 字符串"""
        base = TrafficRequest(protocol="tcp", target="x", payload=b"hello \xc2\xa7 world")
        req = ProtocolAdapter._inject_into_request(base, "X", "§")
        assert req.payload == b"hello X world"
        assert not req.payload.startswith(b"b'")

    def test_dict_payload_raises(self):
        """dict payload 不支持, 抛 TypeError"""
        base = TrafficRequest(protocol="http", target="x", payload={"a": 1})
        with pytest.raises(TypeError, match="dict"):
            ProtocolAdapter._inject_into_request(base, "Y", "§")

    def test_marker_not_in_payload_keeps_original(self):
        """marker 不在 payload 里时, 保持原值不变"""
        base = TrafficRequest(protocol="tcp", target="x", payload="hello")
        req = ProtocolAdapter._inject_into_request(base, "Y", "§")
        assert req.payload == "Y"  # 默认用传入值

    def test_target_marker_replaced(self):
        base = TrafficRequest(protocol="http", target="x/§/y", payload=None)
        req = ProtocolAdapter._inject_into_request(base, "PATH", "§")
        assert req.target == "x/PATH/y"


class TestTrafficResponse:
    """TrafficResponse + B4/S4/R3"""

    def test_text_body_sync_text_only(self):
        r = TrafficResponse(text="hello")
        assert r.body == "hello"

    def test_text_body_sync_body_only(self):
        r = TrafficResponse(body="world")
        assert r.text == "world"

    def test_text_body_consistent(self):
        """text == body 时不报警"""
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            r = TrafficResponse(text="x", body="x")
            assert r.text == "x"

    def test_text_body_inconsistent_warns(self):
        """B4: text != body 时告警, 以 text 为准"""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            r = TrafficResponse(text="aaa", body="bbb")
            assert len(w) == 1
            assert "不一致" in str(w[0].message)
            assert r.body == "aaa"  # 以 text 为准

    def test_is_interesting_various(self):
        assert TrafficResponse(error="x").is_interesting
        assert TrafficResponse(blocked=True).is_interesting
        assert TrafficResponse(reflects=True).is_interesting
        assert TrafficResponse(banner="ssh").is_interesting
        assert not TrafficResponse().is_interesting

    def test_to_dict_json_serializable(self):
        """S4: to_dict/to_json 必须可 json.dumps"""
        r = TrafficResponse(
            protocol="tcp", ok=True, status=1,
            text="hello", banner="ssh",
            raw=b"binary\x00data",
            tags=["SSH"], anomalies=["x"],
        )
        d = r.to_dict()
        # 标准 json.dumps 必须成功 (raw 用 base64)
        j = json.dumps(d)
        d2 = json.loads(j)
        assert d2["protocol"] == "tcp"
        assert d2["ok"] is True
        assert d2["raw_b64"].startswith("b64:")

    def test_to_dict_excludes_raw_when_disabled(self):
        r = TrafficResponse(raw=b"x")
        d = r.to_dict(include_raw=False)
        assert "raw_b64" not in d

    def test_to_dict_next_steps_default_empty(self):
        """next_steps 默认空列表 (没经过 IntentAnalyzer)"""
        r = TrafficResponse()
        assert r.to_dict()["next_steps"] == []

    def test_payload_str_for_bytes(self):
        """R3: TCP _payload_str 对 bytes 不产生 repr"""
        from aiburp.traffic.adapters import TcpAdapter
        assert TcpAdapter._payload_str(b"hello") == "hello"
        assert TcpAdapter._payload_str(None) == ""
        assert "b'" not in TcpAdapter._payload_str(b"\xff\xfe")
