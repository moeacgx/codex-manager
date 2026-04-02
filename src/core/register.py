"""
旧版 HTTP OAuth/Session 注册引擎（已退役）。

项目现已统一为 Playwright 浏览器通道（BrowserRegistrationEngine）。
本文件仅保留：
1) RegistrationResult 数据结构（供浏览器引擎复用）
2) JWT 账号 ID 提取工具函数
3) RegistrationEngine 兼容壳（防止旧调用直接崩溃）
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Optional
from zoneinfo import ZoneInfo

from ..services.base import BaseEmailService

logger = logging.getLogger(__name__)
_SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")


def _extract_account_id_from_jwt(token: str) -> str:
    """从 JWT 中尝试提取 chatgpt_account_id。"""
    if not token or token.count(".") < 2:
        return ""
    payload_b64 = token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        claims = json.loads(payload.decode("utf-8"))
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = (
            auth_claims.get("chatgpt_account_id")
            or claims.get("chatgpt_account_id")
            or claims.get("account_id")
        )
        return str(account_id or "").strip()
    except Exception:
        return ""


@dataclass
class RegistrationResult:
    success: bool
    email: str = ""
    password: str = ""
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""
    error_message: str = ""
    logs: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    source: str = "register"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """兼容旧测试/旧调用的轻量结构。"""

    success: bool
    page_type: str = ""
    is_existing_account: bool = False
    response_data: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""


class _CookieJar:
    """最小 CookieJar 兼容实现（满足 set/get 调用）。"""

    def __init__(self) -> None:
        self._data: Dict[str, str] = {}

    def set(self, name: str, value: str, **_: Any) -> None:
        self._data[str(name)] = str(value)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self._data.get(str(name), default)


class _LegacySession:
    """兼容旧调用的最小 Session 壳，仅保留 cookies。"""

    def __init__(self) -> None:
        self.cookies = _CookieJar()

    def close(self) -> None:
        return None


class RegistrationEngine:
    """
    旧版注册引擎兼容壳。

    注意：旧的 OAuth/Session HTTP 流程已物理移除，本类不再执行注册逻辑。
    """

    LEGACY_REMOVED_MESSAGE = (
        "RegistrationEngine 已退役：旧 OAuth/Session HTTP 流程已移除，"
        "请改用 BrowserRegistrationEngine（Playwright 浏览器通道）。"
    )

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        token_mode: str = "browser_http_only",
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger
        self.task_uuid = task_uuid
        self.token_mode = (token_mode or "browser_http_only").strip().lower()

        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None
        self.logs: list = []

        # 兼容 pending_oauth 旧调用（会向 cookies 写入会话值）。
        self.session = _LegacySession()
        self._oauth_session_token = ""

        self._log(self.LEGACY_REMOVED_MESSAGE, "warning")

    def _log(self, message: str, level: str = "info") -> None:
        ts = datetime.now(_SHANGHAI_TZ).strftime("%H:%M:%S")
        line = f"[{ts}] {message}"
        self.logs.append(line)
        if self.callback_logger:
            try:
                self.callback_logger(line)
            except Exception:
                pass
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _get_session_cookie(self) -> str:
        token = self._oauth_session_token or self.session_token or ""
        if token:
            return str(token)
        try:
            return str(self.session.cookies.get("__Secure-next-auth.session-token") or "")
        except Exception:
            return ""

    def get_oauth_tokens(self) -> Optional[Dict[str, Any]]:
        self._log(
            "已拦截旧 get_oauth_tokens 调用：当前版本仅支持 Playwright 浏览器注册流程。",
            "warning",
        )
        return None

    def run(self) -> RegistrationResult:
        msg = (
            "旧注册引擎已禁用：请使用 BrowserRegistrationEngine。"
            "（token_mode 请使用 browser_http_only / browser_http_first / browser）"
        )
        self._log(msg, "error")
        return RegistrationResult(
            success=False,
            email=self.email or "",
            password=self.password or "",
            session_token=self._get_session_cookie(),
            error_message=msg,
            logs=list(self.logs),
            metadata={
                "token_mode": "browser_http_only",
                "legacy_engine_removed": True,
                "registered_at": datetime.now(_SHANGHAI_TZ).isoformat(),
            },
            source="register",
        )

    def save_to_database(self, result: RegistrationResult) -> bool:
        self._log("旧引擎不再负责入库，当前调用已忽略。", "warning")
        return False
