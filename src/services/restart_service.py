"""
应用重启服务
"""

import logging
import os
import threading
from typing import Callable

logger = logging.getLogger(__name__)


class AppRestartService:
    """简单的进程重启请求器（依赖外部守护进程/容器重启）"""

    def __init__(self, exit_func: Callable[[int], None] | None = None):
        self._exit_func = exit_func or os._exit
        self._lock = threading.Lock()
        self._requested = False
        self._reason = ""

    @property
    def restart_requested(self) -> bool:
        return self._requested

    @property
    def restart_reason(self) -> str:
        return self._reason

    def request_restart(self, delay_seconds: int, reason: str) -> None:
        delay = max(1, int(delay_seconds or 1))
        with self._lock:
            if self._requested:
                return
            self._requested = True
            self._reason = (reason or "").strip()
            timer = threading.Timer(delay, self._perform_restart)
            timer.daemon = True
            timer.start()
        logger.warning("已请求应用重启：delay=%s reason=%s", delay, self._reason or "manual")

    def _perform_restart(self) -> None:
        logger.warning("应用即将退出，等待外部进程管理器重启")
        self._exit_func(0)
