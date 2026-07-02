"""
Auto-generated from Nuclei template: redis-ping-test
CVE: N/A
Severity: critical


"""

import requests
import re
from urllib.parse import urljoin
from ..poc_manager import POCInfo, POCResult, POCLevel, Severity



import re
import asyncio


def _run_async(coro):
    """
    在同步上下文运行协程.
    若当前线程已有运行中的 event loop (如 Agent 模式), 抛 RuntimeError
    提示调用方改用 await _check_redis_ping_test_async() —— 避免跨 loop 创建 adapter.
    抛错前会先 close 协程, 防止 'coroutine was never awaited' 警告.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行中的 loop, 正常用 asyncio.run
        return asyncio.run(coro)
    # 走到这里说明检测到运行中的 loop - 先关闭协程再抛错
    coro.close()
    raise RuntimeError(
        "已存在运行中的 event loop. 请改用 await _check_redis_ping_test_async(target, timeout) "
        "或在新线程中调用同步版本."
    )


async def _check_redis_ping_test_async(target: str, timeout: float = 5):
    """async 原生实现, 供 async 调用方直接 await."""
    from aiburp.traffic.adapters import TcpAdapter
    from aiburp.traffic import TrafficRequest
    async with TcpAdapter(timeout=timeout) as adapter:
        req = TrafficRequest(protocol="tcp", target=target, payload='PING\r\n')
        return await adapter.send(req)


def check_redis_ping_test(target: str, **kwargs) -> "POCResult":
    """检测 Redis PING Test (TCP, sync wrapper)"""
    resp = _run_async(_check_redis_ping_test_async(target, kwargs.get("timeout", 5)))

    if not resp.ok:
        return POCResult(poc_id='redis-ping-test', name='Redis PING Test', vulnerable=False)

    matches = []

    match_0 = any(w in resp.text for w in ['PONG'])
    matches.append(match_0)
    if any(matches):
        return POCResult(
            poc_id='redis-ping-test',
            name='Redis PING Test',
            vulnerable=True,
            severity=Severity.CRITICAL,
            evidence=f'TCP banner/text 命中',
            details={'banner': resp.banner, 'text': resp.text[:200]}
        )
    return POCResult(poc_id='redis-ping-test', name='Redis PING Test', vulnerable=False)


# POC 注册信息
POC_INFO = POCInfo(
    id='redis-ping-test',
    name='Redis PING Test',
    level=POCLevel.L2_NUCLEI_AUTO,
    severity=Severity.CRITICAL,
    cve=None,
    tags=['redis', 'unauth'],
    description='',
    check_func=check_redis_ping_test
)
