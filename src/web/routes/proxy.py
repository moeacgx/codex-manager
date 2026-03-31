"""本地动态代理 API"""

import os
from fastapi import APIRouter, HTTPException

from ...core.dynamic_proxy_service import DynamicProxyService, parse_port_range

router = APIRouter()

_proxy_service = None


def _get_proxy_service() -> DynamicProxyService:
    global _proxy_service
    if _proxy_service is not None:
        return _proxy_service

    host = os.getenv("LOCAL_PROXY_HOST", "127.0.0.1")
    scheme = os.getenv("LOCAL_PROXY_SCHEME", "socks5")
    port_range = os.getenv("LOCAL_PROXY_PORT_RANGE", "12001-12005")

    try:
        ports = parse_port_range(port_range)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _proxy_service = DynamicProxyService(host=host, ports=ports, scheme=scheme)
    return _proxy_service


@router.get("/dynamic")
async def get_dynamic_proxy():
    service = _get_proxy_service()
    return {"proxy": service.next_proxy()}
