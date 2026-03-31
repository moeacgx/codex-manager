"""
本地动态代理服务（轮询端口范围）
"""

import os
import threading
from typing import List


class DynamicProxyService:
    """按端口范围轮询生成代理 URL"""

    def __init__(self, host: str, ports: List[int], scheme: str = "socks5"):
        self._host = host
        self._ports = ports
        self._scheme = scheme
        self._lock = threading.Lock()
        self._index = 0

    def next_proxy(self) -> str:
        with self._lock:
            port = self._ports[self._index]
            self._index = (self._index + 1) % len(self._ports)
        return f"{self._scheme}://{self._host}:{port}"


def parse_port_range(range_value: str) -> List[int]:
    """解析端口范围，格式如 12001-12005"""
    if not range_value:
        raise ValueError("端口范围不能为空")

    parts = range_value.split("-")
    if len(parts) != 2:
        raise ValueError("端口范围格式应为 start-end")

    start = int(parts[0].strip())
    end = int(parts[1].strip())
    if start <= 0 or end <= 0:
        raise ValueError("端口必须为正整数")
    if end < start:
        raise ValueError("端口范围结束必须大于等于起始")

    return list(range(start, end + 1))


_local_service = None
_local_lock = threading.Lock()


def get_local_proxy_service() -> DynamicProxyService:
    """获取本地动态代理服务实例"""
    global _local_service
    with _local_lock:
        if _local_service is not None:
            return _local_service

        host = os.getenv("LOCAL_PROXY_HOST", "127.0.0.1")
        scheme = os.getenv("LOCAL_PROXY_SCHEME", "socks5")
        port_range = os.getenv("LOCAL_PROXY_PORT_RANGE", "12001-12005")
        ports = parse_port_range(port_range)
        _local_service = DynamicProxyService(host=host, ports=ports, scheme=scheme)
        return _local_service
