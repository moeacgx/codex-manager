"""
注册流程引擎
从 main.py 中提取并重构的注册流程
加入了 123.py 的模拟浏览器并发注册流程
"""

import re
import json
import time
import logging
import os
import secrets
import string
import random
import uuid
import hashlib
import base64
import html
import threading
import inspect
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, unquote

from curl_cffi import requests as cffi_requests
from curl_cffi.requests.models import Response

from .openai.oauth import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings

logger = logging.getLogger(__name__)

_OAUTH_RATE_LIMIT_UNTIL_TS: float = 0.0
_OAUTH_RATE_LIMIT_LOCK = threading.Lock()

# ================= Chrome Fingerprints =================
_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]

def _random_chrome_version():
    profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


def _get_shared_delay_profile() -> tuple[float, float, float]:
    """
    与 Playwright 通道共用节流环境变量：
    - BROWSER_DELAY_MULTIPLIER
    - BROWSER_DELAY_MIN
    - BROWSER_DELAY_MAX
    """
    try:
        multiplier = float(os.environ.get("BROWSER_DELAY_MULTIPLIER", "1.0"))
    except Exception:
        multiplier = 1.0
    try:
        delay_min = float(os.environ.get("BROWSER_DELAY_MIN", "0"))
    except Exception:
        delay_min = 0.0
    try:
        delay_max = float(os.environ.get("BROWSER_DELAY_MAX", "0"))
    except Exception:
        delay_max = 0.0

    if multiplier <= 0:
        multiplier = 1.0
    if delay_min < 0:
        delay_min = 0.0
    if delay_max < 0:
        delay_max = 0.0
    return multiplier, delay_min, delay_max


def _apply_shared_delay(seconds: float) -> float:
    multiplier, delay_min, delay_max = _get_shared_delay_profile()
    value = max(0.0, float(seconds)) * multiplier
    if delay_min > 0:
        value = max(value, delay_min)
    if delay_max > 0:
        value = min(value, delay_max)
    return max(0.0, value)


def _sleep_shared_delay(seconds: float) -> None:
    time.sleep(_apply_shared_delay(seconds))


def _random_delay(low=0.3, high=1.0):
    multiplier, delay_min, delay_max = _get_shared_delay_profile()
    try:
        low = float(low) * multiplier
        high = float(high) * multiplier
    except Exception:
        low = float(low)
        high = float(high)

    if delay_min > 0:
        low = max(low, delay_min)
    if delay_max > 0:
        high = min(high, delay_max)
    if high < low:
        high = low
    time.sleep(random.uniform(low, high))


def _make_trace_headers():
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": tp, "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
    }


def _generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge

def _extract_code_from_url(url: str):
    if not url:
        return None
    normalized_url = html.unescape(str(url)).replace("\\u0026", "&").replace("&amp;", "&")
    if "code=" not in normalized_url:
        return None
    try:
        code = parse_qs(urlparse(normalized_url).query).get("code", [None])[0]
        if code:
            return code
    except Exception:
        pass
    try:
        match = re.search(r"[?&]code=([^&#]+)", normalized_url)
        if match:
            return unquote(match.group(1))
    except Exception:
        return None
    return None


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
        account_id = auth_claims.get("chatgpt_account_id") or claims.get("chatgpt_account_id") or claims.get("account_id")
        return str(account_id or "").strip()
    except Exception:
        return ""

# ================= SentinelTokenGenerator =================
class SentinelTokenGenerator:
    """纯 Python 版本 sentinel token 生成器（PoW）"""
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or "Mozilla/5.0"
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    def _get_config(self):
        now_str = time.strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
            time.gmtime(),
        )
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop = random.choice([
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ])
        nav_val = f"{nav_prop}-undefined"

        return [
            "1920x1080", now_str, 4294705152, random.random(), self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js", None, None,
            "en-US", "en-US,en", random.random(), nav_val,
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now, self.sid, "", random.choice([4, 8, 12, 16]), time_origin,
        ]

    @staticmethod
    def _base64_encode(data):
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed if seed is not None else self.requirements_seed
        difficulty = str(difficulty or "0")
        start_time = time.time()
        config = self._get_config()

        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        data = self._base64_encode(config)
        return "gAAAAAC" + data


def fetch_sentinel_challenge(session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None):
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {
        "p": generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    kwargs = {"data": json.dumps(req_body), "headers": headers, "timeout": 20}
    if impersonate:
        kwargs["impersonate"] = impersonate

    try:
        resp = session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None

def build_sentinel_token(session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None):
    challenge = fetch_sentinel_challenge(session, device_id, flow=flow, user_agent=user_agent, sec_ch_ua=sec_ch_ua, impersonate=impersonate)
    if not challenge: return None
    c_value = challenge.get("token", "")
    if not c_value: return None
    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(seed=pow_data.get("seed"), difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = generator.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow}, separators=(",", ":"))


# ================= Core Registration Classes =================

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
    logs: list = None
    metadata: dict = None
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
    """提交授权入口表单的结果"""
    success: bool
    page_type: str = ""
    is_existing_account: bool = False
    response_data: Dict[str, Any] = None
    error_message: str = ""

class OAuthPhoneRequiredError(RuntimeError):
    """OAuth 流程被手机号校验拦截。"""

class RegistrationEngine:
    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        token_mode: str = "session",
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger
        self.task_uuid = task_uuid
        self.token_mode = (token_mode or "session").strip().lower()
        if self.token_mode not in ("session", "oauth"):
            self.token_mode = "session"

        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.session = self._create_registration_session()

        self.device_id = str(uuid.uuid4())
        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        self.auth_session_logging_id = str(uuid.uuid4())

        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None
        self._used_verification_codes: set[str] = set()
        self._callback_url = None
        self._final_callback_url = None
        self._oauth_login_did: str = ""
        self._oauth_login_sentinel: str = ""

        self.BASE = "https://chatgpt.com"
        self.AUTH = "https://auth.openai.com"

        settings = get_settings()
        self.oauth_client_id = settings.openai_client_id
        self.oauth_redirect_uri = settings.openai_redirect_uri
        self.oauth_issuer = settings.openai_auth_url.split('/oauth/')[0] if settings.openai_auth_url else "https://auth.openai.com"
        self._oauth_session_token = ""

        # 请求超时与重试
        try:
            self.request_timeout = max(20, min(60, int(settings.registration_timeout or 60)))
        except Exception:
            self.request_timeout = 60
        try:
            self.request_retries = max(1, int(settings.registration_max_retries or 3))
        except Exception:
            self.request_retries = 3
        try:
            self.oauth_rate_limit_cooldown_seconds = max(
                0, int(settings.oauth_rate_limit_cooldown_seconds or 0)
            )
        except Exception:
            self.oauth_rate_limit_cooldown_seconds = 0
        try:
            self.oauth_rate_limit_backoff_base_seconds = max(
                1, int(settings.oauth_rate_limit_backoff_base_seconds or 6)
            )
        except Exception:
            self.oauth_rate_limit_backoff_base_seconds = 6
        try:
            self.oauth_rate_limit_backoff_max_seconds = max(
                self.oauth_rate_limit_backoff_base_seconds,
                int(settings.oauth_rate_limit_backoff_max_seconds or 60),
            )
        except Exception:
            self.oauth_rate_limit_backoff_max_seconds = 60

        def _env_bool(name: str, default: bool) -> bool:
            raw = str(os.environ.get(name, "")).strip().lower()
            if not raw:
                return default
            return raw in ("1", "true", "yes", "on")

        def _env_int(name: str, default: int, minimum: int = 1, maximum: int = 20) -> int:
            raw = str(os.environ.get(name, "")).strip()
            if not raw:
                return default
            try:
                return max(minimum, min(maximum, int(raw)))
            except Exception:
                return default

        # OAuth 执行策略（默认精简，减少无效步骤和限流概率）
        self.oauth_enable_session_reuse = _env_bool("OAUTH_ENABLE_SESSION_REUSE", False)
        self.oauth_session_reuse_max_attempts = _env_int(
            "OAUTH_SESSION_REUSE_MAX_ATTEMPTS",
            1,
            minimum=1,
            maximum=6,
        )
        self.oauth_login_max_attempts = _env_int(
            "OAUTH_LOGIN_MAX_ATTEMPTS",
            2,
            minimum=1,
            maximum=6,
        )
        self.oauth_enable_redirect_chain_fallback = _env_bool(
            "OAUTH_ENABLE_REDIRECT_CHAIN_FALLBACK",
            False,
        )
        self.oauth_enable_legacy_consent_payloads = _env_bool(
            "OAUTH_ENABLE_LEGACY_CONSENT_PAYLOADS",
            False,
        )
        # 是否启用 workspace / authorize-continue 旁路兜底。
        # 默认关闭：优先遵循真实 Consent「继续 -> 回调」链路，避免误判。
        self.oauth_enable_workspace_fallback = _env_bool(
            "OAUTH_ENABLE_WORKSPACE_FALLBACK",
            False,
        )
        # HTTP OAuth 日志控制（默认安静模式，避免刷屏）
        self.http_oauth_quiet = _env_bool("HTTP_OAUTH_QUIET", True)
        self.http_oauth_verbose_trace = _env_bool("HTTP_OAUTH_VERBOSE_TRACE", False)
        self.http_request_retry_verbose = _env_bool("HTTP_REQUEST_RETRY_VERBOSE", False)

    def _oauth_trace_enabled(self) -> bool:
        return bool(getattr(self, "http_oauth_verbose_trace", False))

    def _oauth_quiet_enabled(self) -> bool:
        return bool(getattr(self, "http_oauth_quiet", True)) and not self._oauth_trace_enabled()

    def _is_http_oauth_noise_message(self, message: str) -> bool:
        text = str(message or "")
        if not text:
            return False
        noisy_keywords = (
            "Cookie诊断",
            "Cookie候选值",
            "响应探测",
            "响应片段",
            "OAuth 跟随跳转[",
            "OAuth 候选回跳[",
            "OAuth Authorize 入口Location",
            "OAuth Consent 入口响应",
            "Consent 表单解析",
            "Consent API 兜底状态",
            "Consent API 兜底[",
            "OAuth 最终重定向兜底",
            "OAuth 授权码提取失败诊断",
        )
        return any(keyword in text for keyword in noisy_keywords)

    def _log(self, message: str, level: str = "info"):
        if self._oauth_quiet_enabled() and self._is_http_oauth_noise_message(message):
            logger.debug(f"[HTTP_OAUTH_QUIET] {message}")
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        if level == "debug" and not self._oauth_trace_enabled():
            logger.debug(log_message)
            return
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")
        if level == "error":
            logger.error(log_message)
        elif level == "warning":
            logger.warning(log_message)
        elif level == "debug":
            logger.debug(log_message)
        else:
            logger.info(log_message)

    def _default_session_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.ua,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
        }

    def _create_registration_session(self) -> cffi_requests.Session:
        session = cffi_requests.Session(impersonate=self.impersonate)
        if self.proxy_url:
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        session.headers.update(self._default_session_headers())
        return session

    def _copy_session_cookies(self, source: Any, target: Any) -> None:
        if source is None or target is None:
            return
        copied = 0
        try:
            src_jar = getattr(source, "jar", None)
            if src_jar is not None:
                for item in list(src_jar):
                    name = str(getattr(item, "name", "") or "").strip()
                    value = str(getattr(item, "value", "") or "")
                    if not name:
                        continue
                    domain = str(getattr(item, "domain", "") or "").strip()
                    path = str(getattr(item, "path", "") or "/").strip() or "/"
                    if domain:
                        target.set(name, value, domain=domain, path=path)
                    else:
                        target.set(name, value, path=path)
                    copied += 1
        except Exception:
            copied = 0

        if copied > 0:
            return

        # 兼容简化 Cookie 容器（例如单测中的 dict）
        try:
            for name, value in list(getattr(source, "items", lambda: [])()):
                name_str = str(name or "").strip()
                if not name_str:
                    continue
                target.set(name_str, str(value or ""))
        except Exception:
            pass

    def _is_retryable_transport_error(self, err: Exception) -> bool:
        text = str(err or "").lower()
        if not text:
            return False
        keywords = (
            "curl: (28)",
            "operation timed out",
            "curl: (35)",
            "tls connect error",
            "connection timed out",
            "connection reset",
            "failed to perform",
            "recv failure",
            "send failure",
            "empty reply from server",
        )
        return any(k in text for k in keywords)

    def _recreate_session_keep_cookies(self, reason: str = "") -> None:
        old_session = self.session
        try:
            new_session = self._create_registration_session()
            self._copy_session_cookies(getattr(old_session, "cookies", None), new_session.cookies)
            # 确保核心 did cookie 始终存在
            if getattr(self, "device_id", None):
                did = str(self.device_id).strip()
                if did:
                    new_session.cookies.set("oai-did", did, domain="chatgpt.com")
                    new_session.cookies.set("oai-did", did, domain=".auth.openai.com")
                    new_session.cookies.set("oai-did", did, domain="auth.openai.com")
            self.session = new_session
            if reason:
                level = "warning" if self._oauth_trace_enabled() else "debug"
                self._log(f"检测到网络抖动，已重建 HTTP 会话: {reason}", level)
        except Exception as e:
            self._log(f"重建 HTTP 会话失败: {e}", "warning")
        finally:
            try:
                if old_session is not None:
                    old_session.close()
            except Exception:
                pass

    @staticmethod
    def _short_log_text(value: Any, limit: int = 220) -> str:
        text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
        if len(text) <= limit:
            return text
        return text[: max(20, limit)] + "..."

    def _iter_session_cookie_items(self, session: Any) -> list[tuple[str, str]]:
        items: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        try:
            jar = getattr(getattr(session, "cookies", None), "jar", None)
            if jar is not None:
                for item in list(jar):
                    name = str(getattr(item, "name", "") or "").strip()
                    value = str(getattr(item, "value", "") or "")
                    if not name:
                        continue
                    pair = (name, value)
                    if pair in seen:
                        continue
                    seen.add(pair)
                    items.append(pair)
        except Exception:
            pass
        if items:
            return items

        try:
            cookie_obj = getattr(session, "cookies", None)
            if cookie_obj is None:
                return items
            for name, value in list(getattr(cookie_obj, "items", lambda: [])()):
                name_str = str(name or "").strip()
                value_str = str(value or "")
                if not name_str:
                    continue
                pair = (name_str, value_str)
                if pair in seen:
                    continue
                seen.add(pair)
                items.append(pair)
        except Exception:
            pass
        return items

    def _oauth_debug_cookie_snapshot(self, session: Any, stage: str, *, max_names: int = 40) -> None:
        if not self._oauth_trace_enabled():
            return
        try:
            items = self._iter_session_cookie_items(session)
            if not items:
                self._log(f"{stage} Cookie诊断: 未读取到任何 Cookie", "warning")
                return

            names = sorted({name for name, _ in items})
            self._log(
                f"{stage} Cookie诊断: total={len(items)}, names={', '.join(names[:max_names])}",
                "warning",
            )

            candidate_values: list[str] = []
            for name, raw_value in items:
                lname = name.lower()
                if (
                    "callback" not in lname
                    and "redirect" not in lname
                    and "session" not in lname
                    and lname not in ("oai-client-auth-info", "oai-client-auth-session", "unified_session_manifest")
                ):
                    continue
                decoded = str(raw_value or "")
                try:
                    decoded = unquote(decoded)
                except Exception:
                    pass
                code = _extract_code_from_url(decoded)
                marker = f"code_len={len(code)}" if code else "code=none"
                candidate_values.append(
                    f"{name}({marker}): {self._short_log_text(decoded, 180)}"
                )
            if candidate_values:
                self._log(
                    f"{stage} Cookie候选值: {' | '.join(candidate_values[:6])}",
                    "warning",
                )
        except Exception as e:
            self._log(f"{stage} Cookie诊断异常: {e}", "warning")

    def _oauth_debug_response_probe(
        self,
        stage: str,
        resp: Optional[Response],
        *,
        response_text: str = "",
        redirect_uri: str = "",
    ) -> None:
        if not self._oauth_trace_enabled():
            return
        if resp is None:
            self._log(f"{stage} 响应探测: 响应为空", "warning")
            return
        try:
            text = response_text if isinstance(response_text, str) and response_text else (resp.text or "")
            loc = str(resp.headers.get("Location", "") or "").strip()
            content_type = str(resp.headers.get("Content-Type", "") or "").strip()
            callback_url = self._extract_redirect_from_html(text, redirect_uri or self.oauth_redirect_uri)
            nav_url = self._extract_navigation_url_from_html(text, base_url=str(resp.url))
            self._log(
                (
                    f"{stage} 响应探测: status={resp.status_code}, "
                    f"url={self._short_log_text(str(resp.url), 140)}, "
                    f"location={self._short_log_text(loc, 140) or '-'}, "
                    f"content_type={self._short_log_text(content_type, 80) or '-'}, "
                    f"text_len={len(text)}, "
                    f"callback={self._short_log_text(callback_url, 140) or '-'}, "
                    f"nav={self._short_log_text(nav_url, 140) or '-'}"
                ),
                "warning",
            )
            if text:
                self._log(
                    f"{stage} 响应片段: {self._short_log_text(text, 260)}",
                    "warning",
                )
        except Exception as e:
            self._log(f"{stage} 响应探测异常: {e}", "warning")

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        label: str = "",
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[Response]:
        """带重试的 HTTP 请求封装，防止 curl 超时直接中断流程。"""
        timeout_val = int(timeout or self.request_timeout or 30)
        retry_val = int(retries or self.request_retries or 1)
        last_err: Optional[Exception] = None

        for attempt in range(1, retry_val + 1):
            try:
                return self.session.request(method, url, timeout=timeout_val, **kwargs)
            except Exception as e:
                last_err = e
                if attempt < retry_val:
                    err_message = (
                        f"{label}请求异常: {e} (第 {attempt}/{retry_val} 次)"
                        if label
                        else f"请求异常: {e} (第 {attempt}/{retry_val} 次)"
                    )
                    if self.http_request_retry_verbose or self._oauth_trace_enabled():
                        self._log(err_message, "warning")
                    else:
                        self._log(err_message, "debug")
                if self._is_retryable_transport_error(e) and attempt < retry_val:
                    self._recreate_session_keep_cookies(reason=f"{label or method.upper()} 第{attempt}次异常")
                if attempt < retry_val:
                    _sleep_shared_delay(min(2.0 * attempt, 6.0))

        if last_err:
            if label:
                self._log(f"{label}请求最终失败: {last_err}", "error")
            else:
                self._log(f"请求最终失败: {last_err}", "error")
        return None

    def _oauth_is_rate_limited(self, message: str) -> bool:
        text = str(message or "").lower()
        if not text:
            return False
        return "429" in text or "rate limit" in text or "too many requests" in text

    def _oauth_compute_backoff_seconds(self, attempt: int) -> int:
        attempt_idx = max(1, int(attempt or 1))
        base = max(1, int(self.oauth_rate_limit_backoff_base_seconds or 1))
        upper = max(base, int(self.oauth_rate_limit_backoff_max_seconds or base))
        return min(upper, base * attempt_idx)

    def _oauth_apply_global_cooldown(self, seconds: int) -> float:
        if seconds <= 0:
            return 0.0
        global _OAUTH_RATE_LIMIT_UNTIL_TS
        target_until = time.time() + float(seconds)
        with _OAUTH_RATE_LIMIT_LOCK:
            if target_until > _OAUTH_RATE_LIMIT_UNTIL_TS:
                _OAUTH_RATE_LIMIT_UNTIL_TS = target_until
            remaining = max(0.0, _OAUTH_RATE_LIMIT_UNTIL_TS - time.time())
        return remaining

    def _oauth_wait_global_cooldown_if_needed(self) -> None:
        with _OAUTH_RATE_LIMIT_LOCK:
            remaining = max(0.0, _OAUTH_RATE_LIMIT_UNTIL_TS - time.time())
        if remaining <= 0:
            return
        wait_seconds = max(1, int(remaining))
        self._log(f"检测到 OAuth 全局冷却，等待 {wait_seconds}s 后继续", "warning")
        _sleep_shared_delay(remaining)

    def _oauth_handle_rate_limit(self, attempt: int, *, stage: str = "OAuth") -> None:
        backoff_seconds = self._oauth_compute_backoff_seconds(attempt)
        cooldown_seconds = max(backoff_seconds, int(self.oauth_rate_limit_cooldown_seconds or 0))
        remaining = self._oauth_apply_global_cooldown(cooldown_seconds)
        global_cooldown = max(backoff_seconds, int(remaining))
        self._log(
            f"{stage} 命中限流，已设置全局冷却 {global_cooldown}s（本次退避={backoff_seconds}s）",
            "warning",
        )
        if backoff_seconds > 0:
            _sleep_shared_delay(backoff_seconds)

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        return ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _create_email(self) -> bool:
        try:
            self.email_info = self.email_service.create_email()
            if not self.email_info or "email" not in self.email_info:
                return False
            self.email = self.email_info["email"]
            return True
        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def wait_for_verification_email(self, timeout=120):
        self._log("等待验证码邮件...")
        email_id = self.email_info.get("service_id") if self.email_info else None
        exclude_codes = sorted(
            {
                str(code).strip()
                for code in (self._used_verification_codes or set())
                if str(code or "").strip()
            }
        )
        if exclude_codes:
            self._log("本轮取件将跳过已取过的验证码: " + ", ".join(exclude_codes))

        kwargs = {
            "email": self.email,
            "email_id": email_id,
            "timeout": timeout,
            "pattern": OTP_CODE_PATTERN,
            "otp_sent_at": self._otp_sent_at,
        }
        try:
            params = inspect.signature(self.email_service.get_verification_code).parameters
            if "exclude_codes" in params:
                kwargs["exclude_codes"] = exclude_codes
        except Exception:
            pass

        code = self.email_service.get_verification_code(**kwargs)
        if code:
            self._used_verification_codes.add(str(code).strip())
        return code

    # ======== HTTP Flows ========

    def visit_homepage(self):
        url = f"{self.BASE}/"
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._log(f"Visit homepage -> {r.status_code}")

    def get_csrf(self) -> str:
        url = f"{self.BASE}/api/auth/csrf"
        r = self.session.get(url, headers={"Accept": "application/json", "Referer": f"{self.BASE}/"})
        data = r.json()
        token = data.get("csrfToken", "")
        self._log(f"Get CSRF -> {r.status_code}")
        if not token: raise Exception("Failed to get CSRF token")
        return token

    def signin(self, email: str, csrf: str) -> str:
        url = f"{self.BASE}/api/auth/signin/openai"
        params = {
            "prompt": "login", "ext-oai-did": self.device_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "screen_hint": "login_or_signup", "login_hint": email,
        }
        form_data = {"callbackUrl": f"{self.BASE}/", "csrfToken": csrf, "json": "true"}
        r = self.session.post(url, params=params, data=form_data, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json", "Referer": f"{self.BASE}/", "Origin": self.BASE,
        })
        data = r.json()
        authorize_url = data.get("url", "")
        self._log(f"Signin -> {r.status_code}")
        if not authorize_url: raise Exception("Failed to get authorize URL")
        return authorize_url

    def authorize(self, url: str) -> str:
        r = self._request_with_retry(
            "get",
            url,
            label="Authorize",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{self.BASE}/",
                "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
        )
        if r is None:
            raise Exception("Authorize 请求失败")
        final_url = str(r.url)
        self._log(f"Authorize -> {r.status_code}")
        return final_url

    def _fetch_sentinel_tokens(self):
        sentinel_token = build_sentinel_token(
            self.session, self.device_id, flow="authorize_continue",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        so_token = build_sentinel_token(
            self.session, self.device_id, flow="oauth_create_account",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        return sentinel_token, so_token

    def register(self, email: str, password: str, sentinel_token: str = None):
        url = f"{self.AUTH}/api/accounts/user/register"
        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/create-account/password",
            "Origin": self.AUTH,
        }
        transient_gateway_statuses = {502, 503, 504, 520, 521, 522, 523, 524, 525, 526}
        max_gateway_retries = 2
        current_sentinel_token = sentinel_token

        for attempt in range(1, max_gateway_retries + 2):
            headers = dict(base_headers)
            headers.update(_make_trace_headers())
            if current_sentinel_token:
                headers["openai-sentinel-token"] = current_sentinel_token

            r = self._request_with_retry(
                "post",
                url,
                label="Register",
                json={"username": email, "password": password},
                headers=headers,
            )
            if r is None:
                if attempt <= max_gateway_retries:
                    self._log(
                        f"Register 请求失败，准备重试 ({attempt}/{max_gateway_retries})",
                        "warning",
                    )
                    _sleep_shared_delay(min(1.2 * attempt, 3.0))
                    fresh_sentinel = build_sentinel_token(
                        self.session,
                        self.device_id,
                        flow="authorize_continue",
                        user_agent=self.ua,
                        sec_ch_ua=self.sec_ch_ua,
                        impersonate=self.impersonate,
                    )
                    if fresh_sentinel:
                        current_sentinel_token = fresh_sentinel
                    continue
                return 0, {"error": "register_request_failed"}

            try:
                data = r.json()
            except Exception:
                data = {"text": r.text[:500]}
            self._log(f"Register -> {r.status_code}")

            if r.status_code not in transient_gateway_statuses:
                return r.status_code, data

            if attempt <= max_gateway_retries:
                self._log(
                    f"Register 命中网关错误 HTTP {r.status_code}，准备重试 ({attempt}/{max_gateway_retries})",
                    "warning",
                )
                _sleep_shared_delay(min(1.2 * attempt, 3.0))
                fresh_sentinel = build_sentinel_token(
                    self.session,
                    self.device_id,
                    flow="authorize_continue",
                    user_agent=self.ua,
                    sec_ch_ua=self.sec_ch_ua,
                    impersonate=self.impersonate,
                )
                if fresh_sentinel:
                    current_sentinel_token = fresh_sentinel
                continue

            return r.status_code, data

        return 0, {"error": "register_request_failed"}

    def send_otp(self):
        self._otp_sent_at = time.time()
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        otp_timeout = max(15, min(int(self.request_timeout or 30), 35))
        r = self._request_with_retry(
            "get",
            url,
            label="Send OTP",
            timeout=otp_timeout,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{self.AUTH}/create-account/password", "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
        )
        if r is None:
            return 0, {}
        self._log(f"Send OTP -> {r.status_code}")
        return r.status_code, {}

    def validate_otp(self, code: str, sentinel_token: str = None):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        otp_timeout = max(15, min(int(self.request_timeout or 30), 35))
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/email-verification", "Origin": self.AUTH}
        headers.update(_make_trace_headers())
        if sentinel_token: headers["openai-sentinel-token"] = sentinel_token
        r = self._request_with_retry(
            "post",
            url,
            label="Validate OTP",
            timeout=otp_timeout,
            json={"code": code},
            headers=headers,
        )
        if r is None:
            return 0, {"error": "validate_otp_request_failed"}
        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:500]}
        self._log(f"Validate OTP -> {r.status_code}")
        return r.status_code, data

    def create_account(
        self,
        name: str,
        birthdate: str,
        so_token: str = None,
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
    ):
        url = f"{self.AUTH}/api/accounts/create_account"
        headers = {
            "referer": f"{self.AUTH}/about-you",
            "accept": "application/json",
            "content-type": "application/json",
        }
        payload = {"name": name, "birthdate": birthdate}

        r = self._request_with_retry(
            "post",
            url,
            label="Create Account",
            timeout=timeout,
            retries=retries,
            json=payload,
            headers=headers,
            impersonate=self.impersonate,
        )
        if r is None:
            return 0, {"error": "create_account_request_failed"}

        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:500]}
        if isinstance(data, dict):
            cb = data.get("continue_url") or data.get("url") or data.get("redirect_url")
            if cb: self._callback_url = cb
        self._log(f"Create Account -> {r.status_code}")
        return r.status_code, data

    def callback(self, url: str = None):
        if not url: url = self._callback_url
        if not url:
            self._log("No callback URL")
            return None, None
        r = self._request_with_retry(
            "get",
            url,
            label="Callback",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
        )
        if r is None:
            return None, None
        self._final_callback_url = str(r.url)
        self._log(f"Callback -> {r.status_code}")
        return r.status_code, {"final_url": self._final_callback_url}

    @staticmethod
    def _find_jwt_in_data(data, depth=0):
        if depth > 5: return None
        if isinstance(data, str):
            parts = data.split(".")
            if len(parts) == 3 and len(data) > 100:
                try:
                    payload = parts[1]; padding = 4 - len(payload) % 4
                    if padding != 4: payload += "=" * padding
                    decoded = base64.urlsafe_b64decode(payload)
                    obj = json.loads(decoded)
                    if isinstance(obj, dict) and ("exp" in obj or "iat" in obj or "sub" in obj):
                        return data
                except: pass
            return None
        if isinstance(data, dict):
            for v in data.values():
                res = RegistrationEngine._find_jwt_in_data(v, depth + 1)
                if res: return res
        if isinstance(data, list):
            for item in data:
                res = RegistrationEngine._find_jwt_in_data(item, depth + 1)
                if res: return res
        return None

    def get_chatgpt_session_tokens(self):
        try:
            referer = self._final_callback_url or f"{self.BASE}/"
            r = self.session.get(f"{self.BASE}/api/auth/session", headers={
                "Accept": "application/json", "Referer": referer, "User-Agent": self.ua,
            }, timeout=30, impersonate=self.impersonate)
            if r.status_code != 200: return None
            data = r.json()
            access_token = data.get("accessToken") or data.get("access_token") or ""
            if not access_token: access_token = self._find_jwt_in_data(data)
            if not access_token: return None
            id_token = data.get("idToken") or data.get("id_token") or ""
            account_id = _extract_account_id_from_jwt(id_token) or _extract_account_id_from_jwt(access_token)
            return {
                "access_token": access_token,
                "refresh_token": data.get("refreshToken") or data.get("refresh_token") or "",
                "id_token": id_token,
                "account_id": account_id,
            }
        except: return None

    def _get_session_cookie(self) -> str:
        return (
            self.session.cookies.get("__Secure-next-auth.session-token", domain=".chatgpt.com")
            or self.session.cookies.get("__Secure-next-auth.session-token", domain="chatgpt.com")
            or ""
        )

    def _extract_oauth_state(self, url: str, text: str = "") -> Optional[str]:
        """尝试从 URL 或 HTML 文本中提取 OAuth state。"""
        try:
            state = parse_qs(urlparse(url).query).get("state", [None])[0]
            if state:
                return state
        except Exception:
            pass

        if text:
            for pattern in (
                r'name="state" value="([^"]+)"',
                r'"state"\s*:\s*"([^"]+)"',
                r"state=([^&\"'>]+)",
            ):
                match = re.search(pattern, text)
                if match:
                    return html.unescape(match.group(1))
        return None

    def _extract_callback_url_from_html(self, text: str, redirect_uri: str = "") -> Optional[str]:
        """从 HTML（含浏览器错误页脚本）提取 localhost 回调 URL。"""
        if not text:
            return None

        def _normalize(candidate: str) -> str:
            value = html.unescape(str(candidate or "")).strip()
            value = value.replace("\\u0026", "&").replace("\\/", "/").replace("&amp;", "&")
            try:
                for _ in range(2):
                    decoded = unquote(value)
                    if decoded == value:
                        break
                    value = decoded
            except Exception:
                pass
            value = value.strip(" \"'")
            return value

        def _redirect_match(candidate: str) -> bool:
            if not redirect_uri:
                return True
            if candidate.startswith(redirect_uri):
                return True
            try:
                c = urlparse(candidate)
                r = urlparse(redirect_uri)
                return (
                    (c.scheme or "").lower() == (r.scheme or "").lower()
                    and (c.netloc or "").lower() == (r.netloc or "").lower()
                    and (c.path or "") == (r.path or "")
                )
            except Exception:
                return False

        patterns = (
            r'data-url=["\']([^"\']*auth/callback[^"\']*)["\']',
            r'"reloadUrl"\s*:\s*"([^"]*auth/callback[^"]*)"',
            r"https?://localhost(?::\d+)?/auth/callback[^\s\"'<>]+",
            r"/auth/callback\?[^\"'<>\\s]+",
            r"https?%3A%2F%2Flocalhost(?:%3A\d+)?%2Fauth%2Fcallback[^\\s\"'<>]+",
        )

        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                candidate = _normalize(match)
                if not candidate:
                    continue
                if candidate.startswith("/auth/callback"):
                    try:
                        base = urlparse(redirect_uri) if redirect_uri else None
                        if base and base.scheme and base.netloc:
                            candidate = f"{base.scheme}://{base.netloc}{candidate}"
                        else:
                            candidate = f"http://localhost:1455{candidate}"
                    except Exception:
                        candidate = f"http://localhost:1455{candidate}"
                if not candidate.lower().startswith("http"):
                    continue
                if not _extract_code_from_url(candidate):
                    continue
                if _redirect_match(candidate):
                    return candidate
        return None

    def _extract_redirect_from_html(self, text: str, redirect_uri: str) -> Optional[str]:
        """从 HTML 中抽取回调地址（meta refresh / window.location / 链接）。"""
        if not text:
            return None

        callback_from_error_page = self._extract_callback_url_from_html(text, redirect_uri)
        if callback_from_error_page:
            return callback_from_error_page

        patterns = (
            r'http-equiv=["\']refresh["\']\s+content=["\']\d+;\s*url=([^"\']+)["\']',
            r'window\.location(?:\.href)?\s*=\s*"([^"]+)"',
            r'location\.href\s*=\s*"([^"]+)"',
            r'location\s*=\s*"([^"]+)"',
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                candidate = (
                    html.unescape(match.group(1) or "")
                    .replace("\\u0026", "&")
                    .replace("&amp;", "&")
                    .replace("\\/", "/")
                )
                if candidate.startswith(redirect_uri):
                    return candidate

        for match in re.findall(r"https?://[^\s\"'>]+", text):
            candidate = (
                html.unescape(match or "")
                .replace("\\u0026", "&")
                .replace("&amp;", "&")
                .replace("\\/", "/")
            )
            if candidate.startswith(redirect_uri):
                return candidate

        return None

    def _extract_oauth_code_from_callback_cookie(self, raw_value: str, redirect_uri: str = "") -> Optional[str]:
        """从 callback 类 Cookie 值中提取 OAuth code。"""
        if not raw_value:
            return None

        candidates: list[str] = []

        def _push(value: Any) -> None:
            text = str(value or "").strip()
            if not text:
                return
            if text in candidates:
                return
            candidates.append(text)

        _push(raw_value)
        try:
            decoded = unquote(str(raw_value))
            if decoded:
                _push(decoded)
        except Exception:
            pass

        for candidate in list(candidates):
            value = str(candidate or "").strip().strip("\"'")
            if not value:
                continue
            _push(value)

            # 尝试多轮解码（兼容 URL 编码层层嵌套）
            try:
                collapsed = value
                for _ in range(2):
                    decoded = unquote(collapsed)
                    if decoded == collapsed:
                        break
                    collapsed = decoded
                    _push(collapsed)
            except Exception:
                pass

            # 兼容只存了相对回调路径 /auth/callback?... 的场景
            if value.startswith("/auth/callback"):
                try:
                    base = urlparse(redirect_uri) if redirect_uri else None
                    if base and base.scheme and base.netloc:
                        _push(f"{base.scheme}://{base.netloc}{value}")
                    else:
                        _push(f"http://localhost:1455{value}")
                except Exception:
                    _push(f"http://localhost:1455{value}")

            code = _extract_code_from_url(value)
            if code:
                return code

            # 兼容 JSON 字符串（如 {"url":"http://localhost..."}）
            if value.startswith("{") or value.startswith("["):
                try:
                    payload = json.loads(value)
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    for key in ("url", "callback_url", "callbackUrl", "redirect_url", "redirectUrl", "href"):
                        nested = str(payload.get(key) or "").strip()
                        if not nested:
                            continue
                        nested_code = _extract_code_from_url(nested)
                        if nested_code:
                            return nested_code

        return None

    def _extract_oauth_code_from_session_cookies(
        self,
        session: cffi_requests.Session,
        redirect_uri: str = "",
    ) -> Optional[str]:
        """从会话 Cookie 中提取 OAuth code（优先 callback-url）。"""
        preferred_cookie_names = (
            "__Secure-next-auth.callback-url",
            "__secure-next-auth.callback-url",
            "next-auth.callback-url",
            "__Host-next-auth.callback-url",
        )

        for cookie_name in preferred_cookie_names:
            for raw_cookie in self._extract_cookie_values(session, cookie_name):
                code = self._extract_oauth_code_from_callback_cookie(raw_cookie, redirect_uri)
                if code:
                    self._log(f"从 Cookie {cookie_name} 提取到 OAuth code", "info")
                    return code

        # 兜底：遍历全部 Cookie，筛选 callback/redirect 相关名称
        try:
            jar = getattr(session.cookies, "jar", None)
            if jar is None:
                return None
            for item in list(jar):
                name = str(getattr(item, "name", "") or "").strip().lower()
                if not name:
                    continue
                if "callback" not in name and "redirect" not in name:
                    continue
                raw_value = str(getattr(item, "value", "") or "").strip()
                if not raw_value:
                    continue
                code = self._extract_oauth_code_from_callback_cookie(raw_value, redirect_uri)
                if code:
                    self._log(f"从 Cookie {name} 提取到 OAuth code", "info")
                    return code
        except Exception:
            return None

        return None

    def _extract_hidden_inputs(self, text: str) -> Dict[str, str]:
        """从 HTML 表单中提取隐藏字段（type=hidden）。"""
        if not text:
            return {}
        inputs: Dict[str, str] = {}
        for tag in re.findall(r"<input[^>]+>", text, flags=re.IGNORECASE):
            if not re.search(r'type=["\']hidden["\']', tag, flags=re.IGNORECASE):
                continue
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag, flags=re.IGNORECASE)
            if not name_match:
                continue
            value_match = re.search(r'value=["\']([^"\']*)["\']', tag, flags=re.IGNORECASE)
            name = html.unescape(name_match.group(1))
            value = html.unescape(value_match.group(1)) if value_match else ""
            inputs[name] = value
        return inputs

    def _extract_form_action(self, text: str, keyword: str) -> Optional[str]:
        """从 HTML 中抽取指定表单 action。"""
        if not text:
            return None
        for tag in re.findall(r"<form[^>]+>", text, flags=re.IGNORECASE):
            action_match = re.search(r'action=["\']([^"\']+)["\']', tag, flags=re.IGNORECASE)
            if not action_match:
                continue
            action = html.unescape(action_match.group(1))
            if keyword not in action:
                continue
            if action.startswith("/"):
                return urljoin(self.AUTH, action)
            return action
        return None

    def _extract_first_form_action(self, text: str) -> Optional[str]:
        """提取页面中第一个表单 action。"""
        if not text:
            return None
        for tag in re.findall(r"<form[^>]+>", text, flags=re.IGNORECASE):
            action_match = re.search(r'action=["\\\']([^"\\\']+)["\\\']', tag, flags=re.IGNORECASE)
            if not action_match:
                continue
            action = html.unescape(action_match.group(1))
            if action.startswith("/"):
                return urljoin(self.AUTH, action)
            return action
        return None

    def _extract_submit_field(self, text: str) -> Dict[str, str]:
        """提取“继续/同意”按钮字段，用于模拟点击提交。"""
        if not text:
            return {}

        consent_keywords = ("continue", "继续", "allow", "同意", "accept", "authorize", "授权")

        # 优先匹配 button（type=submit 或省略 type）
        for tag in re.findall(r"<button[^>]*>.*?</button>", text, flags=re.IGNORECASE | re.DOTALL):
            open_tag_match = re.search(r"<button[^>]*>", tag, flags=re.IGNORECASE)
            if not open_tag_match:
                continue
            open_tag = open_tag_match.group(0)

            type_match = re.search(r'type=["\\\']([^"\\\']+)["\\\']', open_tag, flags=re.IGNORECASE)
            if type_match and (type_match.group(1) or "").strip().lower() not in ("submit", ""):
                continue

            inner_text = re.sub(r"<[^>]+>", "", tag)
            inner_text = html.unescape(inner_text).strip().lower()
            attrs_text = html.unescape(open_tag).lower()
            value_match = re.search(r'value=["\\\']([^"\\\']*)["\\\']', open_tag, flags=re.IGNORECASE)
            value_text = html.unescape(value_match.group(1)).strip().lower() if value_match else ""
            if not any(key in f"{inner_text} {attrs_text} {value_text}" for key in consent_keywords):
                continue

            name_match = re.search(r'name=["\\\']([^"\\\']+)["\\\']', open_tag, flags=re.IGNORECASE)
            if name_match:
                return {
                    html.unescape(name_match.group(1)): html.unescape(value_match.group(1)) if value_match else "1"
                }
            return {}

        # 回退匹配 input[type=submit|button]
        for tag in re.findall(r"<input[^>]+>", text, flags=re.IGNORECASE):
            type_match = re.search(r'type=["\\\']([^"\\\']+)["\\\']', tag, flags=re.IGNORECASE)
            input_type = (type_match.group(1) if type_match else "").strip().lower()
            if input_type not in ("submit", "button"):
                continue

            value_match = re.search(r'value=["\\\']([^"\\\']*)["\\\']', tag, flags=re.IGNORECASE)
            value_text = html.unescape(value_match.group(1)).strip().lower() if value_match else ""
            attrs_text = html.unescape(tag).lower()
            if not any(key in f"{attrs_text} {value_text}" for key in consent_keywords):
                continue

            name_match = re.search(r'name=["\\\']([^"\\\']+)["\\\']', tag, flags=re.IGNORECASE)
            if name_match:
                return {html.unescape(name_match.group(1)): html.unescape(value_match.group(1)) if value_match else "1"}
            return {}

        return {}

    def _extract_navigation_url_from_html(self, text: str, base_url: str = "") -> Optional[str]:
        """从 HTML 中提取前端跳转 URL（允许非 redirect_uri 前缀）。"""
        if not text:
            return None
        callback_url = self._extract_callback_url_from_html(text, self.oauth_redirect_uri)
        if callback_url:
            return callback_url

        def _normalize(candidate: str) -> str:
            value = html.unescape(candidate or "").strip()
            value = value.replace("\\u0026", "&").replace("\\/", "/").replace("&amp;", "&")
            if not value:
                return ""
            if value.startswith("/") and base_url:
                return urljoin(base_url, value)
            return value

        def _is_static_asset(url: str) -> bool:
            lowered = (url or "").lower().split("?", 1)[0].split("#", 1)[0]
            static_suffixes = (
                ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
                ".css", ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".otf",
            )
            if lowered.endswith(static_suffixes):
                return True
            if "auth-cdn.oaistatic.com/assets/" in lowered:
                return True
            return False

        patterns = (
            r'http-equiv=["\']refresh["\']\s+content=["\']\d+;\s*url=([^"\']+)["\']',
            r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\s*=\s*["\']([^"\']+)["\']',
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                continue
            candidate = _normalize(match.group(1) or "")
            if not candidate or _is_static_asset(candidate):
                continue
            return candidate

        preferred_candidates: list[str] = []
        fallback_candidates: list[str] = []
        for match in re.findall(r"https?://[^\s\"'>]+", text):
            candidate = _normalize(match or "")
            if not candidate or _is_static_asset(candidate):
                continue

            lowered = candidate.lower()
            if any(
                marker in lowered
                for marker in (
                    "code=",
                    "/oauth",
                    "/authorize",
                    "/consent",
                    "/callback",
                    "redirect_uri=",
                    "/workspace",
                    "/organization",
                    "/continue",
                )
            ):
                preferred_candidates.append(candidate)
            else:
                fallback_candidates.append(candidate)

        if preferred_candidates:
            return preferred_candidates[0]
        if fallback_candidates:
            for candidate in fallback_candidates:
                try:
                    parsed = urlparse(candidate)
                    host = (parsed.netloc or "").lower()
                    if host in ("auth.openai.com", "localhost", "127.0.0.1"):
                        return candidate
                except Exception:
                    continue

        return None

    def _iter_workspace_search_texts(self, text: str) -> list[str]:
        """生成用于 workspace_id 提取的候选文本（含解码与 bootstrap 脚本）。"""
        if not text:
            return []
        candidates: list[str] = []

        def _push(value: str) -> None:
            value = str(value or "")
            if not value:
                return
            if value in candidates:
                return
            candidates.append(value)

        _push(text)
        try:
            _push(html.unescape(text))
        except Exception:
            pass

        # 提取 bootstrap 脚本内容并做多层轻量解码
        try:
            bootstrap_blocks = re.findall(
                r'<script[^>]+id=["\']bootstrap-inert-script["\'][^>]*>(.*?)</script>',
                text,
                flags=re.IGNORECASE | re.DOTALL,
            )
        except Exception:
            bootstrap_blocks = []

        for block in bootstrap_blocks:
            _push(block)
            try:
                unescaped = html.unescape(block)
                _push(unescaped)
                _push(unescaped.replace(r"\/", "/").replace(r"\\u0026", "&"))
                _push(unescaped.replace('\\"', '"'))
                collapsed = unescaped
                for _ in range(3):
                    next_collapsed = (
                        collapsed
                        .replace(r'\\\"', r'\"')
                        .replace(r"\\\\u0026", r"\u0026")
                        .replace(r"\\\\/", r"\\/")
                    )
                    if next_collapsed == collapsed:
                        break
                    collapsed = next_collapsed
                    _push(collapsed)
                try:
                    parsed = json.loads(unescaped.strip())
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    _push(json.dumps(parsed, ensure_ascii=False))
                    for value in parsed.values():
                        if isinstance(value, str):
                            _push(value)
                            _push(value.replace('\\"', '"'))
            except Exception:
                pass

        return candidates

    def _extract_workspace_id_from_html(self, text: str) -> Optional[str]:
        """从 consent 页面 HTML 中提取 workspace_id。"""
        if not text:
            return None
        patterns = (
            r'name=["\']workspace_id["\'][^>]*value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\'][^>]*name=["\']workspace_id["\']',
            r'"workspace_id"\s*:\s*"([^"]+)"',
            r'"workspaceId"\s*:\s*"([^"]+)"',
            r'"default_workspace_id"\s*:\s*"([^"]+)"',
            r'"defaultWorkspaceId"\s*:\s*"([^"]+)"',
            r'"workspaces"\s*:\s*\[\s*\{\s*"id"\s*:\s*"([^"]+)"',
            r'"workspaces"\s*:\s*\[[^\]]*?"id"\s*:\s*"([^"]+)"',
            r'"workspace"\s*:\s*\{[^\}]*?"id"\s*:\s*"([^"]+)"',
            r'"account"\s*:\s*\{[^\}]*?"id"\s*:\s*"([0-9a-fA-F-]{8,})"',
            r'"chatgpt_account_id"\s*:\s*"([0-9a-fA-F-]{8,})"',
            r'workspace_id=([0-9a-fA-F-]{8,})',
            # 兼容 bootstrap 脚本中被转义的 JSON 文本
            r'\\"workspace_id\\"\s*:\s*\\"([^\\"]+)\\"',
            r'\\"workspaceId\\"\s*:\s*\\"([^\\"]+)\\"',
            r'\\"default_workspace_id\\"\s*:\s*\\"([^\\"]+)\\"',
            r'\\"defaultWorkspaceId\\"\s*:\s*\\"([^\\"]+)\\"',
            r'\\"workspaces\\"\s*:\s*\[[^\]]*?\\"id\\"\s*:\s*\\"([^\\"]+)\\"',
            r'\\"workspace\\"\s*:\s*\{[^\}]*?\\"id\\"\s*:\s*\\"([^\\"]+)\\"',
            r'\\"account\\"\s*:\s*\{[^\}]*?\\"id\\"\s*:\s*\\"([0-9a-fA-F-]{8,})\\"',
            r'\\"chatgpt_account_id\\"\s*:\s*\\"([0-9a-fA-F-]{8,})\\"',
        )
        try:
            for candidate_text in self._iter_workspace_search_texts(text):
                for pattern in patterns:
                    match = re.search(pattern, candidate_text, flags=re.IGNORECASE)
                    if not match:
                        continue
                    workspace_id = str(html.unescape(match.group(1) or "")).strip()
                    if workspace_id:
                        return workspace_id
        except Exception:
            return None
        return None

    def _extract_workspace_id_from_payload(self, payload: Any) -> Optional[str]:
        """从 authorize/continue 等 JSON 响应里递归提取 workspace_id。"""
        uuid_pattern = r"^[0-9a-fA-F-]{8,}$"
        if isinstance(payload, dict):
            direct_keys = (
                "workspace_id",
                "workspaceId",
                "default_workspace_id",
                "defaultWorkspaceId",
                "selected_workspace_id",
                "selectedWorkspaceId",
                "active_workspace_id",
                "activeWorkspaceId",
                "chatgpt_account_id",
                "chatgptAccountId",
                "account_id",
                "accountId",
                "default_account_id",
                "defaultAccountId",
            )
            for key in direct_keys:
                direct = str(payload.get(key) or "").strip()
                if not direct:
                    continue
                if "workspace" in key.lower():
                    return direct
                if re.match(uuid_pattern, direct):
                    return direct
            account = payload.get("account")
            if isinstance(account, dict):
                account_id = str(account.get("id") or "").strip()
                if account_id and re.match(uuid_pattern, account_id):
                    return account_id
            user = payload.get("user")
            if isinstance(user, dict):
                user_id = str(user.get("id") or "").strip()
                if user_id and re.match(uuid_pattern, user_id):
                    return user_id
            workspaces = payload.get("workspaces")
            if isinstance(workspaces, list):
                for item in workspaces:
                    if isinstance(item, dict):
                        ws_id = str(
                            item.get("id")
                            or item.get("workspace_id")
                            or item.get("workspaceId")
                            or ""
                        ).strip()
                        if ws_id:
                            return ws_id
            organizations = payload.get("organizations") or payload.get("orgs")
            if isinstance(organizations, list):
                for org in organizations:
                    if isinstance(org, dict):
                        org_ws_id = str(
                            org.get("workspace_id")
                            or org.get("workspaceId")
                            or org.get("default_workspace_id")
                            or org.get("defaultWorkspaceId")
                            or ""
                        ).strip()
                        if org_ws_id:
                            return org_ws_id
            for value in payload.values():
                if isinstance(value, str):
                    v = value.strip()
                    if v and v[0] in "{[":
                        try:
                            nested = json.loads(v)
                        except Exception:
                            nested = None
                        if nested is not None:
                            ws_id = self._extract_workspace_id_from_payload(nested)
                            if ws_id:
                                return ws_id
                ws_id = self._extract_workspace_id_from_payload(value)
                if ws_id:
                    return ws_id
        elif isinstance(payload, list):
            for item in payload:
                ws_id = self._extract_workspace_id_from_payload(item)
                if ws_id:
                    return ws_id
        return None

    def _oauth_submit_authorize_continue_api(
        self,
        session: cffi_requests.Session,
        page_url: str,
        redirect_uri: str,
        workspace_id_hint: str = "",
        authorize_url: str = "",
        enable_workspace_fallback: bool = True,
    ) -> Optional[str]:
        """Consent 兜底：调用 authorize/continue API 后继续提取 code。"""
        # 默认至少尝试空载荷和 action=default，兼容不同风控分流。
        payload_candidates = ({}, {"action": "default"})
        if self.oauth_enable_legacy_consent_payloads:
            payload_candidates = ({}, {"action": "default"}, {"action": "accept"})
        sentinel_header = self._oauth_login_sentinel or ""
        for idx, payload in enumerate(payload_candidates, start=1):
            try:
                headers = {
                    "referer": page_url,
                    "accept": "application/json",
                    "content-type": "application/json",
                }
                if sentinel_header:
                    headers["openai-sentinel-token"] = sentinel_header
                resp = session.post(
                    OPENAI_API_ENDPOINTS["signup"],
                    headers=headers,
                    data=json.dumps(payload),
                    timeout=20,
                    allow_redirects=False,
                )
            except Exception as e:
                self._log(f"Consent API 兜底请求异常: {e}", "warning")
                continue

            self._log(f"Consent API 兜底状态: {resp.status_code} (payload={payload})")
            self._oauth_debug_response_probe(
                f"Consent API 兜底[{idx}]",
                resp,
                response_text=resp.text or "",
                redirect_uri=redirect_uri,
            )

            cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=redirect_uri)
            if cookie_code:
                return cookie_code

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Consent API 兜底(Location)")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if loc:
                    code = self._oauth_follow_and_extract_code(session, loc)
                    if code:
                        return code
                continue

            continue_url = ""
            page_type = ""
            response_text = resp.text or ""
            if resp.status_code == 200:
                try:
                    resp_data = resp.json() if response_text else {}
                except Exception:
                    resp_data = {}
                continue_url = str((resp_data or {}).get("continue_url") or "").strip()
                page_type = str((((resp_data or {}).get("page") or {}).get("type")) or "")
                self._log(
                    (
                        f"Consent API 兜底[{idx}] 解析: continue_url={self._short_log_text(continue_url, 140) or '-'}, "
                        f"page_type={page_type or '-'}, keys={','.join(sorted((resp_data or {}).keys())[:20]) or '-'}"
                    ),
                    "warning",
                )
                self._raise_if_phone_required(
                    url=continue_url,
                    page_type=page_type,
                    text=response_text,
                    stage="OAuth Consent API 兜底",
                )
                if not continue_url:
                    if enable_workspace_fallback:
                        payload_workspace_id = self._extract_workspace_id_from_payload(resp_data) or ""
                        if payload_workspace_id:
                            self._log(f"Consent API 兜底提取到 workspace_id: {payload_workspace_id}")
                            ws_continue_url = self._oauth_select_workspace(session, payload_workspace_id)
                            if ws_continue_url:
                                code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                                if code:
                                    return code
                        if not payload_workspace_id:
                            live_workspace_id = (
                                self._oauth_get_workspace_id(
                                    session,
                                    consent_url=page_url,
                                    authorize_url=authorize_url,
                                    probe_pages=False,
                                )
                                or workspace_id_hint
                            )
                            if live_workspace_id:
                                self._log(f"Consent API 空响应后提取到 workspace_id: {live_workspace_id}")
                                ws_continue_url = self._oauth_select_workspace(session, live_workspace_id)
                                if ws_continue_url:
                                    code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                                    if code:
                                        return code

                    # 无论是否允许 workspace，空响应都补一次同会话回跳
                    follow_candidates = [u for u in (authorize_url, page_url) if u]
                    for candidate_url in follow_candidates:
                        code = self._oauth_follow_and_extract_code(session, candidate_url)
                        if code:
                            self._log("Consent API 空响应后通过回跳链提取到授权码")
                            return code
                    if authorize_url:
                        try:
                            auto_resp = session.get(
                                authorize_url,
                                allow_redirects=True,
                                timeout=20,
                            )
                            self._oauth_debug_response_probe(
                                f"Consent API 兜底[{idx}]自动重定向",
                                auto_resp,
                                response_text=auto_resp.text or "",
                                redirect_uri=redirect_uri,
                            )
                            code = _extract_code_from_url(str(auto_resp.url))
                            if not code and getattr(auto_resp, "history", None):
                                for hist in auto_resp.history:
                                    code = _extract_code_from_url(hist.headers.get("Location", ""))
                                    if code:
                                        break
                            if code:
                                self._log("Consent API 空响应后通过自动重定向提取到授权码")
                                return code
                        except Exception:
                            pass

            if continue_url:
                next_url = continue_url if continue_url.startswith("http") else f"{self.oauth_issuer}{continue_url}"
                code = _extract_code_from_url(next_url) or self._oauth_follow_and_extract_code(session, next_url)
                if code:
                    return code
            elif enable_workspace_fallback and workspace_id_hint:
                ws_continue_url = self._oauth_select_workspace(session, workspace_id_hint)
                if ws_continue_url:
                    code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                    if code:
                        return code

            callback_url = self._extract_redirect_from_html(response_text, redirect_uri)
            if callback_url:
                code = _extract_code_from_url(callback_url)
                if code:
                    return code

            nav_url = self._extract_navigation_url_from_html(response_text, base_url=str(resp.url))
            if nav_url:
                code = _extract_code_from_url(nav_url) or self._oauth_follow_and_extract_code(session, nav_url)
                if code:
                    return code

            cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=redirect_uri)
            if cookie_code:
                return cookie_code
            self._oauth_debug_cookie_snapshot(session, f"Consent API 兜底[{idx}]结束仍无code")

        return None

    def _oauth_submit_consent_form(
        self,
        session: cffi_requests.Session,
        page_url: str,
        html_text: str,
        redirect_uri: str,
        authorize_url: str = "",
    ) -> Optional[str]:
        """提交 OAuth 同意页表单，提取授权码。"""
        try:
            action_url: Optional[str] = None
            payload: Dict[str, str] = {}
            workspace_id_hint = self._extract_workspace_id_from_html(html_text) or ""
            if not workspace_id_hint:
                try:
                    for cookie_name in (
                        "oai-client-auth-session",
                        "oai_client_auth_session",
                        "oai-client-auth-info",
                        "oai_client_auth_info",
                    ):
                        for raw_cookie in self._extract_cookie_values(session, cookie_name):
                            workspace_id_hint = self._extract_workspace_id_from_cookie(raw_cookie) or ""
                            if workspace_id_hint:
                                self._log(f"Consent 从 {cookie_name} 提取到 workspace_id: {workspace_id_hint}")
                                break
                        if workspace_id_hint:
                            break
                except Exception:
                    pass

            forms = re.findall(r"<form[^>]*>.*?</form>", html_text, flags=re.IGNORECASE | re.DOTALL)
            if forms:
                ranked_forms: list[tuple[int, str, Dict[str, str], Dict[str, str]]] = []
                for form_html in forms:
                    open_tag_match = re.search(r"<form[^>]*>", form_html, flags=re.IGNORECASE)
                    if not open_tag_match:
                        continue
                    open_tag = open_tag_match.group(0)
                    action_match = re.search(r'action=["\\\']([^"\\\']*)["\\\']', open_tag, flags=re.IGNORECASE)
                    action_raw = html.unescape((action_match.group(1) if action_match else "").strip())
                    candidate_action = urljoin(page_url, action_raw) if action_raw else page_url

                    candidate_payload = self._extract_hidden_inputs(form_html)
                    submit_payload = self._extract_submit_field(form_html)

                    candidate_text = f"{open_tag} {form_html}".lower()
                    score = 0
                    if "/sign-in-with-chatgpt/codex/consent" in (action_raw or ""):
                        score += 200
                    if "/api/accounts/authorize/continue" in (action_raw or ""):
                        score += 180
                    if any(k in candidate_text for k in ("continue", "继续", "allow", "同意", "accept", "authorize", "授权")):
                        score += 60
                    if submit_payload:
                        score += 30
                    if action_raw:
                        score += 10
                    if candidate_payload.get("workspace_id"):
                        score += 120

                    ranked_forms.append((score, candidate_action, candidate_payload, submit_payload))

                if ranked_forms:
                    ranked_forms.sort(key=lambda item: item[0], reverse=True)
                    best_score, action_url, payload, submit_payload = ranked_forms[0]
                    payload.update(submit_payload)
                    self._log(
                        f"Consent 表单已选中(score={best_score}) action={action_url[:120]}..., "
                        f"hidden={len(payload)}, submit={len(submit_payload)}"
                    )

            if not action_url:
                # 回退旧逻辑：尽力找到 action，没有则默认回发当前页面
                action_url = (
                    self._extract_form_action(html_text, "/sign-in-with-chatgpt/codex/consent")
                    or self._extract_form_action(html_text, "/api/accounts/authorize/continue")
                    or self._extract_first_form_action(html_text)
                    or page_url
                )
                payload = self._extract_hidden_inputs(html_text)
                payload.update(self._extract_submit_field(html_text))

            action_path = ""
            try:
                action_path = (urlparse(action_url).path or "").lower()
            except Exception:
                action_path = (action_url or "").lower()
            self._log(
                (
                    f"Consent 表单解析: page_url={self._short_log_text(page_url, 130)}, "
                    f"action={self._short_log_text(action_url, 130)}, action_path={action_path or '-'}, "
                    f"payload_keys={','.join(sorted(payload.keys())[:20]) or '-'}, "
                    f"workspace_hint={workspace_id_hint or '-'}"
                ),
                "warning",
            )

            # 对 codex consent 页面不强加 action 字段，尽量还原真实表单提交
            needs_default_action = "/api/accounts/authorize/continue" in action_path
            if needs_default_action and "action" not in payload:
                payload["action"] = "default"
            if "workspace_id" not in payload and workspace_id_hint:
                payload["workspace_id"] = workspace_id_hint

            if "/sign-in-with-chatgpt/codex/consent" in action_path:
                self._log("Consent 页面优先提交表单（模拟点击继续）")

            # 某些场景 callback-url cookie 已提前写入 code，优先尝试直接提取
            cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=redirect_uri)
            if cookie_code:
                return cookie_code

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.oauth_issuer,
                "Referer": page_url,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            resp = session.post(
                action_url,
                data=payload,
                headers=headers,
                timeout=30,
                allow_redirects=False,
            )

            self._log(f"Consent 表单提交状态: {resp.status_code}, URL: {str(resp.url)[:120]}...")
            self._oauth_debug_response_probe(
                "Consent 表单提交",
                resp,
                response_text=resp.text or "",
                redirect_uri=redirect_uri,
            )
            workspace_id_hint = str(payload.get("workspace_id") or workspace_id_hint or "").strip()

            self._raise_if_phone_required(
                url=str(resp.url),
                text=resp.text or "",
                stage="OAuth Consent 提交",
            )

            if resp.status_code == 405:
                if self.oauth_enable_workspace_fallback and workspace_id_hint:
                    self._log("Consent 表单返回 405，尝试 workspace/API 旁路兜底", "warning")
                    ws_continue_url = self._oauth_select_workspace(session, workspace_id_hint)
                    if ws_continue_url:
                        code = self._oauth_follow_and_extract_code(session, ws_continue_url)
                        if code:
                            return code
                    # workspace/select 未拿到 code，再尝试 Consent API 兜底
                    api_fallback_code = self._oauth_submit_authorize_continue_api(
                        session,
                        page_url=page_url,
                        redirect_uri=redirect_uri,
                        workspace_id_hint=workspace_id_hint,
                        authorize_url=authorize_url,
                        enable_workspace_fallback=True,
                    )
                    if api_fallback_code:
                        return api_fallback_code
                else:
                    self._log(
                        "Consent 表单返回 405，已禁用 workspace 旁路，尝试 continue API 与回调链路提取 code",
                        "warning",
                    )
                    # 即便禁用 workspace 旁路，也允许尝试 consent continue API（不做 workspace/select）。
                    api_fallback_code = self._oauth_submit_authorize_continue_api(
                        session,
                        page_url=page_url,
                        redirect_uri=redirect_uri,
                        workspace_id_hint="",
                        authorize_url=authorize_url,
                        enable_workspace_fallback=False,
                    )
                    if api_fallback_code:
                        return api_fallback_code
                    # 405 + continue API 空响应时，补一次单次 workspace 紧急恢复（避免流程卡死）
                    if workspace_id_hint:
                        self._log(
                            "Consent 405 恢复模式：continue API 未返回 code，尝试一次 workspace 兜底",
                            "warning",
                        )
                        emergency_code = self._oauth_submit_authorize_continue_api(
                            session,
                            page_url=page_url,
                            redirect_uri=redirect_uri,
                            workspace_id_hint=workspace_id_hint,
                            authorize_url=authorize_url,
                            enable_workspace_fallback=True,
                        )
                        if emergency_code:
                            return emergency_code
                    self._oauth_debug_cookie_snapshot(session, "Consent 405 分支结束仍无code")

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Consent 提交(Location)")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if loc:
                    return self._oauth_follow_and_extract_code(session, loc)
                return None

            callback_url = self._extract_redirect_from_html(resp.text or "", redirect_uri)
            if callback_url:
                return _extract_code_from_url(callback_url)

            nav_url = self._extract_navigation_url_from_html(resp.text or "", base_url=str(resp.url))
            if nav_url:
                self._log(f"Consent 响应提取到跳转 URL: {nav_url[:120]}...")
                code = _extract_code_from_url(nav_url)
                if code:
                    return code
                code = self._oauth_follow_and_extract_code(session, nav_url)
                if code:
                    return code

            cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=redirect_uri)
            if cookie_code:
                return cookie_code

            if self.oauth_enable_workspace_fallback:
                api_fallback_code = self._oauth_submit_authorize_continue_api(
                    session,
                    page_url=page_url,
                    redirect_uri=redirect_uri,
                    workspace_id_hint=workspace_id_hint,
                    authorize_url=authorize_url,
                    enable_workspace_fallback=True,
                )
                if api_fallback_code:
                    return api_fallback_code

            # 页面无直接 callback，尝试继续跟随当前 URL
            self._oauth_debug_cookie_snapshot(session, "Consent 表单结束前仍无code")
            return self._oauth_follow_and_extract_code(session, str(resp.url))
        except Exception as e:
            self._log(f"提交 Consent 表单失败: {e}", "warning")
            return None

    def _looks_like_login_page(self, url: str, text: str) -> bool:
        url_lower = (url or "").lower()
        if "/u/login/" in url_lower:
            return True
        if "name=\"username\"" in text or "name=\"password\"" in text:
            return True
        if "login" in url_lower and "auth.openai.com" in url_lower:
            return True
        return False

    def _is_phone_required(self, url: str = "", text: str = "", page_type: str = "") -> bool:
        url_lower = (url or "").lower()
        page_lower = (page_type or "").lower()
        text_lower = (text or "").lower()

        url_hit = any(key in url_lower for key in (
            "add-phone",
            "add_phone",
            "phone-verification",
            "phone_verification",
            "verify-phone",
            "verify_phone",
            "/phone",
            "onboarding",
        ))
        page_hit = any(key in page_lower for key in (
            "phone",
            "add-phone",
            "add_phone",
            "onboarding",
        ))
        text_hit = any(key in text_lower for key in (
            "add-phone",
            "add_phone",
            "phone verification",
            "verify your phone",
            "phone number",
            "phone required",
            "手机号",
        ))

        return url_hit or page_hit or text_hit

    def _raise_if_phone_required(
        self,
        *,
        url: str = "",
        text: str = "",
        page_type: str = "",
        stage: str = "",
    ) -> None:
        if self._is_phone_required(url=url, text=text, page_type=page_type):
            prefix = f"{stage}：" if stage else ""
            msg = f"{prefix}检测到需要手机号验证，OAuth 授权被拦截"
            self._log(msg, "warning")
            raise OAuthPhoneRequiredError(msg)

    def _handle_about_you(self, source: str) -> bool:
        """在 OAuth 登录流程中遇到 about_you 时补全资料并尽量继续授权。"""
        try:
            user_info = generate_random_user_info()
            name = user_info.get("name") or "User"
            birthdate = user_info.get("birthdate") or "1990-01-01"
            self._log(f"{source}命中 about-you，尝试补全资料并继续 OAuth 授权", "warning")
            about_you_timeout = max(8, min(int(self.request_timeout or 30), 25))
            try:
                status, data = self.create_account(
                    name,
                    birthdate,
                    timeout=about_you_timeout,
                    retries=1,
                )
            except TypeError:
                # 兼容旧签名/测试替身：create_account(name, birthdate, so_token=None)
                status, data = self.create_account(name, birthdate)
            if status in (200, 409):
                if status == 409:
                    self._log("about-you 返回 409（资料已存在），视为可继续授权", "warning")
                # callback 失败不阻断，后续继续走 consent/workspace 提取 code
                try:
                    self.callback()
                except Exception as cb_err:
                    self._log(f"about-you 回调阶段异常（忽略继续）: {cb_err}", "warning")
                return True
            if status == 0:
                reason = ""
                if isinstance(data, dict):
                    reason = str(data.get("error") or "")
                self._log(
                    f"about-you 提交超时或请求失败({reason or 'request_failed'})，按可继续授权处理",
                    "warning",
                )
                try:
                    self.callback()
                except Exception as cb_err:
                    self._log(f"about-you 超时后的回调阶段异常（忽略继续）: {cb_err}", "warning")
                return True
            if status in (400, 403, 422):
                details = ""
                if isinstance(data, dict):
                    try:
                        details = json.dumps(data, ensure_ascii=False)
                    except Exception:
                        details = str(data)
                else:
                    details = str(data or "")
                normalized = details.lower()
                non_blocking_markers = (
                    "registration_disallowed",
                    "already_exists",
                    "already exists",
                    "already_completed",
                    "already complete",
                    "profile_completed",
                    "profile complete",
                )
                if any(marker in normalized for marker in non_blocking_markers):
                    self._log(
                        f"about-you 返回 {status} 且命中非阻断标记，继续 OAuth 授权链路",
                        "warning",
                    )
                    try:
                        self.callback()
                    except Exception as cb_err:
                        self._log(f"about-you 非阻断分支回调异常（忽略继续）: {cb_err}", "warning")
                    return True
            self._log(f"about-you 提交失败: HTTP {status}", "warning")
            return False
        except Exception as e:
            self._log(f"about-you 处理异常: {e}", "warning")
            return False

    def _auth0_submit_identifier(
        self,
        state: str,
        email: str,
        extra_fields: Optional[Dict[str, str]] = None,
        action_url: Optional[str] = None,
    ) -> Response:
        if extra_fields and extra_fields.get("state"):
            state = extra_fields.get("state") or state
        url = action_url or f"{self.AUTH}/u/login/identifier?state={state}"
        payload = {}
        if extra_fields:
            payload.update(extra_fields)
        payload.update({
            "state": state,
            "username": email,
            "js-available": "true",
            "webauthn-available": "true",
            "is-brave": "false",
            "webauthn-platform-available": "true",
            "action": "default",
        })
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.AUTH,
            "Referer": url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        return self.session.post(
            url,
            data=payload,
            headers=headers,
            allow_redirects=True,
            impersonate=self.impersonate,
        )

    def _auth0_submit_password(
        self,
        state: str,
        email: str,
        password: str,
        extra_fields: Optional[Dict[str, str]] = None,
        action_url: Optional[str] = None,
    ) -> Response:
        if extra_fields and extra_fields.get("state"):
            state = extra_fields.get("state") or state
        url = action_url or f"{self.AUTH}/u/login/password?state={state}"
        payload = {}
        if extra_fields:
            payload.update(extra_fields)
        payload.update({
            "state": state,
            "username": email,
            "password": password,
            "action": "default",
        })
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.AUTH,
            "Referer": url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        return self.session.post(
            url,
            data=payload,
            headers=headers,
            allow_redirects=True,
            impersonate=self.impersonate,
        )

    def _complete_oauth_login(
        self,
        current_url: str,
        html_text: str,
        email: str,
        password: str,
        redirect_uri: str,
    ) -> Optional[str]:
        state = self._extract_oauth_state(current_url, html_text)
        if not state:
            return None

        # 识别并提交 identifier
        if "/u/login/identifier" in (current_url or "").lower() or "name=\"username\"" in html_text:
            hidden = self._extract_hidden_inputs(html_text)
            if hidden.get("state"):
                state = hidden.get("state") or state
            action_url = self._extract_form_action(html_text, "/u/login/identifier")
            resp = self._auth0_submit_identifier(state, email, extra_fields=hidden, action_url=action_url)
            current_url = str(resp.url)
            html_text = resp.text or ""
            self._raise_if_phone_required(url=current_url, text=html_text, stage="OAuth 登录(Identifier)")
            if current_url.startswith(redirect_uri):
                return current_url

        # 识别并提交 password
        if "/u/login/password" in (current_url or "").lower() or "name=\"password\"" in html_text:
            hidden = self._extract_hidden_inputs(html_text)
            if hidden.get("state"):
                state = hidden.get("state") or state
            action_url = self._extract_form_action(html_text, "/u/login/password")
            resp = self._auth0_submit_password(state, email, password, extra_fields=hidden, action_url=action_url)
            current_url = str(resp.url)
            html_text = resp.text or ""
            self._raise_if_phone_required(url=current_url, text=html_text, stage="OAuth 登录(Password)")
            if current_url.startswith(redirect_uri):
                return current_url

            loc = resp.headers.get("Location") or resp.headers.get("location")
            if loc:
                if loc.startswith("/"):
                    loc = urljoin(current_url, loc)
                self._raise_if_phone_required(url=loc, stage="OAuth 登录(Password 重定向)")
                if loc.startswith(redirect_uri):
                    return loc
                current_url = loc

        callback_url = self._extract_redirect_from_html(html_text, redirect_uri)
        if callback_url:
            return callback_url

        # 再尝试一次纯重定向链路（禁用登录逻辑）
        return self._follow_oauth_redirect(
            current_url,
            redirect_uri,
            allow_login=False,
        )

    def _follow_oauth_redirect(
        self,
        auth_url: str,
        redirect_uri: str,
        email: Optional[str] = None,
        password: Optional[str] = None,
        allow_login: bool = True,
    ) -> Optional[str]:
        """跟随 OAuth 重定向，获取回调 URL（避免访问本地回调地址）。"""
        current = auth_url
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.BASE}/",
            "Upgrade-Insecure-Requests": "1",
        }

        for _ in range(12):
            r = self.session.get(
                current,
                headers=headers,
                allow_redirects=False,
                impersonate=self.impersonate,
            )
            self._raise_if_phone_required(url=str(r.url), text=r.text or "", stage="OAuth 重定向")
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location") or r.headers.get("location")
                if not loc:
                    return None
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
                self._raise_if_phone_required(url=loc, stage="OAuth 重定向(Location)")
                if loc.startswith(redirect_uri):
                    return loc
                current = loc
                continue

            text = r.text or ""
            if redirect_uri and redirect_uri in text:
                callback_url = self._extract_redirect_from_html(text, redirect_uri)
                if callback_url:
                    return callback_url

            if allow_login and email and password and self._looks_like_login_page(str(r.url), text):
                return self._complete_oauth_login(str(r.url), text, email, password, redirect_uri)

            return None

        return None

    def _oauth_get_device_id(self, session: cffi_requests.Session, auth_url: str) -> Optional[str]:
        """获取 OAuth 登录流程的 Device ID。"""
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                response = session.get(auth_url, timeout=20)
                did = session.cookies.get("oai-did")
                if did:
                    self._log(f"OAuth Device ID: {did}")
                    return did
                self._log(
                    f"获取 Device ID 失败: 未返回 oai-did Cookie (HTTP {response.status_code}, 第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            except Exception as e:
                self._log(
                    f"获取 Device ID 失败: {e} (第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            if attempt < max_attempts:
                _sleep_shared_delay(attempt)
        return None

    def _oauth_submit_auth_start(
        self,
        session: cffi_requests.Session,
        did: str,
        sen_token: Optional[str],
        *,
        screen_hint: str,
        referer: str,
        log_label: str,
        record_existing_account: bool = True,
    ) -> SignupFormResult:
        """提交 OAuth 授权入口表单，返回页面类型。"""
        try:
            request_body = json.dumps({
                "username": {
                    "value": self.email,
                    "kind": "email",
                },
                "screen_hint": screen_hint,
            })

            headers = {
                "referer": referer,
                "accept": "application/json",
                "content-type": "application/json",
            }

            if sen_token:
                sentinel = json.dumps({
                    "p": "",
                    "t": "",
                    "c": sen_token,
                    "id": did,
                    "flow": "authorize_continue",
                })
                headers["openai-sentinel-token"] = sentinel

            response = session.post(
                OPENAI_API_ENDPOINTS["signup"],
                headers=headers,
                data=request_body,
            )

            self._log(f"{log_label}状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            try:
                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"响应页面类型: {page_type}")

                continue_url = str(response_data.get("continue_url") or "")
                if self._is_phone_required(
                    url=continue_url,
                    page_type=page_type,
                    text=json.dumps(response_data, ensure_ascii=False),
                ):
                    self._log("OAuth 授权入口被手机号校验拦截", "warning")
                    return SignupFormResult(
                        success=False,
                        page_type=page_type,
                        response_data=response_data,
                        error_message="PHONE_REQUIRED",
                    )

                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
                if is_existing:
                    self._otp_sent_at = time.time()
                    if record_existing_account:
                        self._log("检测到已注册账号，进入验证码流程")

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data
                )
            except Exception as parse_error:
                self._log(f"解析响应失败: {parse_error}", "warning")
                return SignupFormResult(success=True)

        except Exception as e:
            self._log(f"{log_label}失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _oauth_submit_login_start(
        self,
        session: cffi_requests.Session,
        did: str,
        sen_token: Optional[str],
    ) -> SignupFormResult:
        return self._oauth_submit_auth_start(
            session,
            did,
            sen_token,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            log_label="提交登录入口",
            record_existing_account=False,
        )

    def _oauth_submit_login_password(self, session: cffi_requests.Session) -> SignupFormResult:
        """提交登录密码，推进到邮箱验证码页面。"""
        try:
            response = session.post(
                OPENAI_API_ENDPOINTS["password_verify"],
                headers={
                    "referer": "https://auth.openai.com/log-in/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=json.dumps({"password": self.password}),
            )

            self._log(f"提交登录密码状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            response_data = response.json()
            page_type = response_data.get("page", {}).get("type", "")
            self._log(f"登录密码响应页面类型: {page_type}")

            continue_url = str(response_data.get("continue_url") or "")
            if self._is_phone_required(
                url=continue_url,
                page_type=page_type,
                text=json.dumps(response_data, ensure_ascii=False),
            ):
                self._log("登录密码阶段被手机号校验拦截", "warning")
                return SignupFormResult(
                    success=False,
                    page_type=page_type,
                    response_data=response_data,
                    error_message="PHONE_REQUIRED",
                )

            is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
            if is_existing:
                self._otp_sent_at = time.time()
                self._log("登录密码校验通过，等待系统发送验证码")

            return SignupFormResult(
                success=True,
                page_type=page_type,
                is_existing_account=is_existing,
                response_data=response_data,
            )

        except Exception as e:
            self._log(f"提交登录密码失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _oauth_validate_verification_code(self, session: cffi_requests.Session, code: str) -> bool:
        """验证验证码（OAuth 登录流程）。"""
        try:
            response = session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=json.dumps({"code": code}),
            )
            self._log(f"验证码校验状态: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _oauth_recover_after_about_you_without_otp(
        self,
        session: cffi_requests.Session,
        oauth_start: OAuthStart,
        did: str,
        sen_token: Optional[str],
    ) -> Optional[str]:
        """about-you 分支未走邮箱验证码时的恢复流程：补做登录/验证码后再提取 code。"""
        try:
            self._log("about-you 恢复流程：尝试补做登录态校准", "warning")
            login_start = self._oauth_submit_login_start(session, did, sen_token)
            if not login_start.success:
                self._log(
                    f"about-you 恢复流程登录入口失败: {login_start.error_message or 'unknown'}",
                    "warning",
                )
                return None

            page_type = str(login_start.page_type or "")
            self._log(f"about-you 恢复流程入口页面类型: {page_type or 'unknown'}", "warning")
            need_email_otp = False

            if page_type == OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
                password_result = self._oauth_submit_login_password(session)
                if not password_result.success:
                    self._log(
                        f"about-you 恢复流程密码提交失败: {password_result.error_message or 'unknown'}",
                        "warning",
                    )
                    return None
                page_type = str(password_result.page_type or "")
                self._log(f"about-you 恢复流程密码后页面类型: {page_type or 'unknown'}", "warning")
                if page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                    need_email_otp = True
                elif page_type == "about_you":
                    handled = self._handle_about_you("about-you 恢复流程")
                    if not handled:
                        self._log("about-you 恢复流程再次命中 about-you 且补全失败", "warning")
                        return None
                elif self._is_phone_required(page_type=page_type):
                    raise OAuthPhoneRequiredError("about-you 恢复流程需要手机号验证")
            elif page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                need_email_otp = True
            elif page_type == "about_you":
                handled = self._handle_about_you("about-you 恢复流程")
                if not handled:
                    self._log("about-you 恢复流程入口 about-you 补全失败", "warning")
                    return None
            elif self._is_phone_required(page_type=page_type):
                raise OAuthPhoneRequiredError("about-you 恢复流程需要手机号验证")

            if need_email_otp:
                self._log("about-you 恢复流程：获取邮箱验证码", "warning")
                code = self.wait_for_verification_email(timeout=120)
                if not code:
                    self._log("about-you 恢复流程获取邮箱验证码失败", "warning")
                    return None
                self._log("about-you 恢复流程：校验邮箱验证码", "warning")
                if not self._oauth_validate_verification_code(session, code):
                    self._log("about-you 恢复流程验证码首次校验失败，尝试重取验证码", "warning")
                    retry_code = self.wait_for_verification_email(timeout=45)
                    if not retry_code or retry_code == code:
                        self._log("about-you 恢复流程未拿到可重试的新验证码", "warning")
                        return None
                    if not self._oauth_validate_verification_code(session, retry_code):
                        self._log("about-you 恢复流程重试验证码校验失败", "warning")
                        return None
                    self._log("about-you 恢复流程重试验证码校验成功", "warning")

            self._log("about-you 恢复流程：再次尝试提取授权码", "warning")
            code = self._oauth_exchange_auth_code(session, oauth_start)
            if code:
                self._log("about-you 恢复流程成功提取授权码", "warning")
            else:
                self._log("about-you 恢复流程仍未提取到授权码", "warning")
            return code
        except OAuthPhoneRequiredError:
            raise
        except Exception as e:
            self._log(f"about-you 恢复流程异常: {e}", "warning")
            return None

    def _extract_cookie_values(self, session: cffi_requests.Session, name: str) -> list[str]:
        """从 cookie jar 中尽可能取出指定名称的 cookie 值。"""
        values: list[str] = []
        try:
            direct = session.cookies.get(name)
            if direct:
                values.append(str(direct))
        except Exception:
            pass

        # 尝试指定域名
        for domain in ("auth.openai.com", ".openai.com", "openai.com"):
            try:
                direct = session.cookies.get(name, domain=domain)
                if direct:
                    values.append(str(direct))
            except Exception:
                pass

        # 遍历 cookie jar
        try:
            jar = getattr(session.cookies, "jar", None)
            if jar is not None:
                for item in list(jar):
                    if str(getattr(item, "name", "")) == name:
                        value = str(getattr(item, "value", "") or "").strip()
                        if value:
                            values.append(value)
        except Exception:
            pass

        # 去重保持顺序
        seen = set()
        uniq: list[str] = []
        for v in values:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        return uniq

    def _decode_oauth_session_cookie(self, raw_value: str) -> Optional[Dict[str, Any]]:
        """解析 oai-client-auth-session cookie（兼容 URL 编码/引号/JWT 片段）。"""
        if not raw_value:
            return None
        candidates = [raw_value]
        try:
            decoded = unquote(raw_value)
            if decoded != raw_value:
                candidates.append(decoded)
        except Exception:
            pass

        for candidate in candidates:
            try:
                value = candidate.strip()
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                part = value.split(".")[0] if "." in value else value
                pad = "=" * ((4 - (len(part) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((part + pad).encode("ascii"))
                data = json.loads(decoded.decode("utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
        return None

    def _extract_workspace_id_from_cookie(self, raw_value: str) -> Optional[str]:
        """从授权相关 Cookie 值中提取 workspace_id。"""
        if not raw_value:
            return None

        candidates = [raw_value]
        if "." in raw_value:
            candidates.extend(str(raw_value).split("."))

        # 先走 URL 解码候选
        raw_decoded_candidates: list[str] = []
        for item in candidates:
            try:
                raw_decoded_candidates.append(unquote(str(item)))
            except Exception:
                raw_decoded_candidates.append(str(item))

        # 再追加 base64 解码候选（兼容非 JWT 的 base64-json cookie）
        for item in list(raw_decoded_candidates):
            value = str(item or "").strip().strip("\"'")
            if not value:
                continue
            for candidate in (value, value.replace("-", "+").replace("_", "/")):
                if not re.match(r"^[A-Za-z0-9+/=]+$", candidate):
                    continue
                try:
                    pad = "=" * ((4 - (len(candidate) % 4)) % 4)
                    decoded = base64.b64decode((candidate + pad).encode("ascii"), validate=False)
                    decoded_text = decoded.decode("utf-8", errors="ignore").strip()
                    if decoded_text and decoded_text not in raw_decoded_candidates:
                        raw_decoded_candidates.append(decoded_text)
                except Exception:
                    continue

        regex_patterns = (
            r'"workspace_id"\s*:\s*"([^"]+)"',
            r'"workspaceId"\s*:\s*"([^"]+)"',
            r'"default_workspace_id"\s*:\s*"([^"]+)"',
            r'"defaultWorkspaceId"\s*:\s*"([^"]+)"',
            r'"selected_workspace_id"\s*:\s*"([^"]+)"',
            r'"selectedWorkspaceId"\s*:\s*"([^"]+)"',
            r'"active_workspace_id"\s*:\s*"([^"]+)"',
            r'"activeWorkspaceId"\s*:\s*"([^"]+)"',
            r'"workspaces"\s*:\s*\[[^\]]*?"id"\s*:\s*"([^"]+)"',
            r'"workspace"\s*:\s*\{[^\}]*?"id"\s*:\s*"([^"]+)"',
            r'"account"\s*:\s*\{[^\}]*?"id"\s*:\s*"([0-9a-fA-F-]{8,})"',
            r'"chatgpt_account_id"\s*:\s*"([0-9a-fA-F-]{8,})"',
            r'"account_id"\s*:\s*"([0-9a-fA-F-]{8,})"',
            r'"default_account_id"\s*:\s*"([0-9a-fA-F-]{8,})"',
            r'workspace_id=([0-9a-fA-F-]{8,})',
            r'account_id=([0-9a-fA-F-]{8,})',
        )
        for candidate in raw_decoded_candidates:
            for pattern in regex_patterns:
                match = re.search(pattern, candidate, flags=re.IGNORECASE)
                if match:
                    workspace_id = str(match.group(1) or "").strip()
                    if workspace_id:
                        return workspace_id

        # 再尝试直接解析 JSON（兼容 URL 编码后 JSON 字符串）
        for candidate in raw_decoded_candidates:
            value = str(candidate or "").strip()
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]
            if not value:
                continue
            try:
                payload = json.loads(value)
            except Exception:
                payload = None
            if isinstance(payload, (dict, list)):
                ws_from_payload = self._extract_workspace_id_from_payload(payload)
                if ws_from_payload:
                    return ws_from_payload

        for candidate in candidates:
            payload = self._decode_oauth_session_cookie(candidate)
            if not isinstance(payload, dict):
                continue

            workspaces = payload.get("workspaces") or []
            if isinstance(workspaces, list):
                for workspace in workspaces:
                    workspace_id = str((workspace or {}).get("id") or "").strip()
                    if workspace_id:
                        return workspace_id

            for key in ("workspace_id", "workspaceId"):
                workspace_id = str(payload.get(key) or "").strip()
                if workspace_id:
                    return workspace_id
            account = payload.get("account")
            if isinstance(account, dict):
                account_id = str(account.get("id") or "").strip()
                if account_id and re.match(r"^[0-9a-fA-F-]{8,}$", account_id):
                    return account_id

            ws_from_payload = self._extract_workspace_id_from_payload(payload)
            if ws_from_payload:
                return ws_from_payload

        return None

    def _extract_workspace_id_from_response_headers(self, headers: Any) -> Optional[str]:
        """从响应头(Set-Cookie 等)提取 workspace_id。"""
        if not headers:
            return None
        try:
            header_items = []
            for k, v in getattr(headers, "items", lambda: [])():
                header_items.append(f"{k}: {v}")
            header_blob = "\n".join(header_items)

            # 先尝试从头里直接抓 workspace_id 字段
            direct_patterns = (
                r'"workspace_id"\s*:\s*"([^"]+)"',
                r'"workspaceId"\s*:\s*"([^"]+)"',
                r'"default_workspace_id"\s*:\s*"([^"]+)"',
                r'"defaultWorkspaceId"\s*:\s*"([^"]+)"',
                r'workspace_id=([0-9a-fA-F-]{8,})',
            )
            for pattern in direct_patterns:
                match = re.search(pattern, header_blob, flags=re.IGNORECASE)
                if match:
                    workspace_id = str(match.group(1) or "").strip()
                    if workspace_id:
                        return workspace_id

            # 再尝试提取 auth session cookie 再解码
            cookie_patterns = (
                r'oai-client-auth-session=([^;\n]+)',
                r'oai_client_auth_session=([^;\n]+)',
                r'oai-client-auth-info=([^;\n]+)',
                r'oai_client_auth_info=([^;\n]+)',
            )
            for pattern in cookie_patterns:
                for match in re.findall(pattern, header_blob, flags=re.IGNORECASE):
                    ws_id = self._extract_workspace_id_from_cookie(str(match))
                    if ws_id:
                        return ws_id

            # 最后兜底：从全部 Set-Cookie 里抽值尝试解析
            for _, value in re.findall(r"(?im)^set-cookie\s*:\s*([^=:\s]+)=([^;\n]+)", header_blob):
                ws_id = self._extract_workspace_id_from_cookie(str(value))
                if ws_id:
                    return ws_id
        except Exception:
            return None
        return None

    def _oauth_get_workspace_id(
        self,
        session: cffi_requests.Session,
        consent_url: str = "",
        authorize_url: str = "",
        probe_pages: bool = True,
    ) -> Optional[str]:
        """获取 Workspace ID（OAuth 登录流程）。"""
        try:
            cookie_names = (
                "oai-client-auth-session",
                "oai_client_auth_session",
                "oai-client-auth-info",
                "oai_client_auth_info",
            )
            for cookie_name in cookie_names:
                cookie_values = self._extract_cookie_values(session, cookie_name)
                for raw_cookie in cookie_values:
                    workspace_id = self._extract_workspace_id_from_cookie(raw_cookie)
                    if workspace_id:
                        self._log(f"Workspace ID: {workspace_id} (from {cookie_name})")
                        return workspace_id
            # 兼容新版 cookie 键名变更（如 unified_session_manifest/auth-session-minimized）
            try:
                seen_pairs = set()
                cookies_obj = getattr(session, "cookies", None)
                if cookies_obj is not None:
                    if hasattr(cookies_obj, "items"):
                        for name, raw_cookie in list(cookies_obj.items()):
                            name_str = str(name or "").strip()
                            value_str = str(raw_cookie or "").strip()
                            if not value_str:
                                continue
                            pair = (name_str, value_str)
                            if pair in seen_pairs:
                                continue
                            seen_pairs.add(pair)
                            workspace_id = self._extract_workspace_id_from_cookie(value_str)
                            if workspace_id:
                                self._log(f"Workspace ID: {workspace_id} (from cookie:{name_str or 'unknown'})")
                                return workspace_id
                    jar = getattr(cookies_obj, "jar", None)
                    if jar is not None:
                        for item in list(jar):
                            name_str = str(getattr(item, "name", "") or "").strip()
                            value_str = str(getattr(item, "value", "") or "").strip()
                            if not value_str:
                                continue
                            pair = (name_str, value_str)
                            if pair in seen_pairs:
                                continue
                            seen_pairs.add(pair)
                            workspace_id = self._extract_workspace_id_from_cookie(value_str)
                            if workspace_id:
                                self._log(f"Workspace ID: {workspace_id} (from cookie:{name_str or 'unknown'})")
                                return workspace_id
            except Exception:
                pass

            # 从 chatgpt 会话接口回捞 workspace（通常等于 account.id）
            try:
                resp_session = session.get(
                    f"{self.BASE}/api/auth/session",
                    headers={
                        "accept": "application/json",
                        "referer": f"{self.BASE}/",
                    },
                    timeout=15,
                )
                ws_from_headers = self._extract_workspace_id_from_response_headers(resp_session.headers)
                if ws_from_headers:
                    self._log(f"Workspace ID: {ws_from_headers} (from chatgpt session headers)")
                    return ws_from_headers
                if resp_session.status_code == 200 and (resp_session.text or "").strip():
                    try:
                        session_payload = resp_session.json()
                    except Exception:
                        session_payload = {}
                    ws_from_payload = self._extract_workspace_id_from_payload(session_payload)
                    if ws_from_payload:
                        self._log(f"Workspace ID: {ws_from_payload} (from chatgpt session payload)")
                        return ws_from_payload
                    access_token = str(
                        (session_payload or {}).get("accessToken")
                        or (session_payload or {}).get("access_token")
                        or ""
                    ).strip()
                    if access_token:
                        ws_from_jwt = _extract_account_id_from_jwt(access_token)
                        if ws_from_jwt:
                            self._log(f"Workspace ID: {ws_from_jwt} (from chatgpt session jwt)")
                            return ws_from_jwt
            except Exception:
                pass

            # 从 auth 域会话接口回捞 workspace（部分场景仅 auth 域有有效登录态）
            try:
                resp_auth_session = session.get(
                    f"{self.AUTH}/api/auth/session",
                    headers={
                        "accept": "application/json",
                        "referer": f"{self.AUTH}/log-in",
                    },
                    timeout=15,
                )
                ws_from_headers = self._extract_workspace_id_from_response_headers(resp_auth_session.headers)
                if ws_from_headers:
                    self._log(f"Workspace ID: {ws_from_headers} (from auth session headers)")
                    return ws_from_headers
                if resp_auth_session.status_code == 200 and (resp_auth_session.text or "").strip():
                    try:
                        auth_session_payload = resp_auth_session.json()
                    except Exception:
                        auth_session_payload = {}
                    ws_from_payload = self._extract_workspace_id_from_payload(auth_session_payload)
                    if ws_from_payload:
                        self._log(f"Workspace ID: {ws_from_payload} (from auth session payload)")
                        return ws_from_payload
                    access_token = str(
                        (auth_session_payload or {}).get("accessToken")
                        or (auth_session_payload or {}).get("access_token")
                        or ""
                    ).strip()
                    if access_token:
                        ws_from_jwt = _extract_account_id_from_jwt(access_token)
                        if ws_from_jwt:
                            self._log(f"Workspace ID: {ws_from_jwt} (from auth session jwt)")
                            return ws_from_jwt
            except Exception:
                pass

            if not probe_pages:
                return None

            page_candidates = []
            if authorize_url:
                page_candidates.append(authorize_url)
            if consent_url:
                page_candidates.append(consent_url)
            page_candidates.append(f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent")
            pattern = re.compile(r'"workspace_id"\s*:\s*"([^"]+)"')
            page_debug: list[str] = []
            for page_url in page_candidates:
                try:
                    response = session.get(page_url, timeout=15)
                    ws_from_headers = self._extract_workspace_id_from_response_headers(response.headers)
                    if ws_from_headers:
                        self._log(f"Workspace ID: {ws_from_headers} (from headers)")
                        return ws_from_headers

                    try:
                        ws_from_url = parse_qs(urlparse(str(response.url)).query).get("workspace_id", [None])[0]
                    except Exception:
                        ws_from_url = None
                    if ws_from_url:
                        ws_from_url = str(ws_from_url).strip()
                        if ws_from_url:
                            self._log(f"Workspace ID: {ws_from_url} (from url)")
                            return ws_from_url

                    workspace_id_from_html = self._extract_workspace_id_from_html(response.text or "")
                    if workspace_id_from_html:
                        self._log(f"Workspace ID: {workspace_id_from_html} (from html)")
                        return workspace_id_from_html
                    match = pattern.search(response.text or "")
                    if match:
                        workspace_id = str(match.group(1) or "").strip()
                        if workspace_id:
                            self._log(f"Workspace ID: {workspace_id} (from page)")
                            return workspace_id
                    bootstrap_len = 0
                    try:
                        bootstrap_match = re.search(
                            r'<script[^>]+id=["\']bootstrap-inert-script["\'][^>]*>(.*?)</script>',
                            response.text or "",
                            flags=re.IGNORECASE | re.DOTALL,
                        )
                        if bootstrap_match:
                            bootstrap_len = len(bootstrap_match.group(1) or "")
                    except Exception:
                        bootstrap_len = 0
                    page_debug.append(
                        f"url={str(response.url)[:110]} status={response.status_code} text_len={len(response.text or '')} bootstrap_len={bootstrap_len}"
                    )
                except Exception:
                    page_debug.append(f"url={page_url[:110]} status=ERR")
                    continue

            # 失败时输出诊断信息，便于定位不同账号/风控场景的结构差异
            try:
                cookie_names: list[str] = []
                jar = getattr(session.cookies, "jar", None)
                if jar is not None:
                    for item in list(jar):
                        name = str(getattr(item, "name", "") or "").strip()
                        if name:
                            cookie_names.append(name)
                cookie_names = sorted(set(cookie_names))
                if cookie_names:
                    self._log(f"Workspace 提取失败，当前 Cookie 名称: {', '.join(cookie_names[:20])}", "warning")
            except Exception:
                pass
            if page_debug:
                self._log(f"Workspace 提取失败，页面探测: {' | '.join(page_debug)}", "warning")
            self._log("未能从 Cookie/页面提取 workspace_id", "error")
            return None

        except Exception as e:
            self._log(f"获取 Workspace ID 失败: {e}", "error")
            return None

    def _oauth_select_workspace(self, session: cffi_requests.Session, workspace_id: str) -> Optional[str]:
        """选择 Workspace（OAuth 登录流程）。"""
        try:
            response = session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                },
                data=json.dumps({"workspace_id": workspace_id}),
            )

            if response.status_code in (301, 302, 303, 307, 308):
                loc = str(response.headers.get("Location") or "").strip()
                if loc:
                    self._log(f"workspace/select 重定向到: {loc[:100]}...")
                    return loc

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            data = response.json() if response.text else {}
            continue_url = str(
                (data or {}).get("continue_url")
                or (data or {}).get("url")
                or (data or {}).get("redirect_url")
                or (data or {}).get("next_url")
                or ""
            ).strip()
            if not continue_url:
                fallback_callback = self._extract_redirect_from_html(response.text or "", self.oauth_redirect_uri)
                if fallback_callback:
                    return fallback_callback
                fallback_nav = self._extract_navigation_url_from_html(response.text or "", base_url=str(response.url))
                if fallback_nav:
                    return fallback_nav
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None

            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _oauth_follow_redirects(self, session: cffi_requests.Session, start_url: str) -> Optional[str]:
        """跟随重定向链，寻找回调 URL（OAuth 登录流程）。"""
        try:
            current_url = start_url
            max_redirects = 6

            for i in range(max_redirects):
                self._log(f"重定向 {i+1}/{max_redirects}: {current_url[:100]}...")
                response = session.get(current_url, allow_redirects=False, timeout=15)
                self._raise_if_phone_required(
                    url=str(response.url),
                    text=response.text or "",
                    stage="OAuth 重定向链",
                )

                location = response.headers.get("Location") or ""
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    callback_url = self._extract_redirect_from_html(
                        response.text or "",
                        self.oauth_redirect_uri,
                    )
                    if callback_url and _extract_code_from_url(callback_url):
                        self._log(f"在页面源码中提取到回调 URL: {callback_url[:100]}...")
                        return callback_url

                    nav_url = self._extract_navigation_url_from_html(
                        response.text or "",
                        base_url=str(response.url),
                    )
                    if nav_url:
                        code = _extract_code_from_url(nav_url)
                        if code:
                            self._log(f"在页面导航脚本中提取到回调 URL: {nav_url[:100]}...")
                            return nav_url
                        if nav_url != current_url:
                            current_url = nav_url
                            continue
                    break
                if not location:
                    self._log("重定向响应缺少 Location 头")
                    callback_url = self._extract_redirect_from_html(
                        response.text or "",
                        self.oauth_redirect_uri,
                    )
                    if callback_url and _extract_code_from_url(callback_url):
                        self._log(f"在缺少 Location 的响应中提取到回调 URL: {callback_url[:100]}...")
                        return callback_url
                    break

                next_url = urljoin(current_url, location)
                self._raise_if_phone_required(url=next_url, stage="OAuth 重定向链(Location)")
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url
                current_url = next_url

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None

    def _oauth_follow_and_extract_code(self, session: cffi_requests.Session, url: str, max_depth: int = 10) -> Optional[str]:
        """跟随跳转链并提取 code（OAuth 授权流程兜底）。"""
        if not url:
            return None
        cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=self.oauth_redirect_uri)
        if cookie_code:
            return cookie_code
        current_url = url
        for step in range(1, max_depth + 1):
            if current_url.startswith("/"):
                current_url = f"{self.oauth_issuer}{current_url}"
            try:
                self._log(
                    f"OAuth 跟随跳转[{step}/{max_depth}] 请求: {self._short_log_text(current_url, 160)}",
                    "warning",
                )
                resp = session.get(current_url, allow_redirects=False, timeout=15)
            except Exception as e:
                # 有时重定向到 localhost 会触发连接异常，尝试从错误信息里抓 code
                m = re.search(r"(https?://localhost[^\s'\"]+)", str(e))
                if m:
                    self._log(
                        f"OAuth 跟随跳转[{step}/{max_depth}] 异常中提取到 localhost 回调",
                        "warning",
                    )
                    return _extract_code_from_url(m.group(1))
                self._log(
                    f"OAuth 跟随跳转[{step}/{max_depth}] 请求异常: {self._short_log_text(e, 220)}",
                    "warning",
                )
                cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=self.oauth_redirect_uri)
                if cookie_code:
                    return cookie_code
                return None

            self._raise_if_phone_required(
                url=str(resp.url),
                text=resp.text or "",
                stage="OAuth 跟随跳转",
            )
            self._log(
                (
                    f"OAuth 跟随跳转[{step}/{max_depth}] 响应: "
                    f"status={resp.status_code}, url={self._short_log_text(str(resp.url), 150)}, "
                    f"location={self._short_log_text(resp.headers.get('Location', ''), 150) or '-'}"
                ),
                "warning",
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth 跟随跳转(Location)")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if not loc:
                    cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=self.oauth_redirect_uri)
                    if cookie_code:
                        return cookie_code
                    self._oauth_debug_cookie_snapshot(session, f"OAuth 跟随跳转[{step}]缺少Location")
                    return None
                current_url = urljoin(current_url, loc)
                continue

            if resp.status_code == 200:
                code = _extract_code_from_url(str(resp.url))
                if code:
                    return code

                callback_url = self._extract_redirect_from_html(
                    resp.text or "",
                    self.oauth_redirect_uri,
                )
                code = _extract_code_from_url(callback_url or "")
                if code:
                    return code

                nav_url = self._extract_navigation_url_from_html(
                    resp.text or "",
                    base_url=str(resp.url),
                )
                self._log(
                    (
                        f"OAuth 跟随跳转[{step}/{max_depth}] 解析: "
                        f"callback={self._short_log_text(callback_url, 150) or '-'}, "
                        f"nav={self._short_log_text(nav_url, 150) or '-'}"
                    ),
                    "warning",
                )
                code = _extract_code_from_url(nav_url or "")
                if code:
                    return code
                if nav_url and nav_url != current_url:
                    current_url = nav_url
                    continue
                cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=self.oauth_redirect_uri)
                if cookie_code:
                    return cookie_code
                self._oauth_debug_cookie_snapshot(session, f"OAuth 跟随跳转[{step}]200无code")
                return None

            cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=self.oauth_redirect_uri)
            if cookie_code:
                return cookie_code
            self._oauth_debug_cookie_snapshot(session, f"OAuth 跟随跳转[{step}]非200/3xx无code")
            return None
        cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=self.oauth_redirect_uri)
        if cookie_code:
            return cookie_code
        self._oauth_debug_cookie_snapshot(session, "OAuth 跟随跳转达到最大深度仍无code")
        return None

    def _oauth_extract_code_from_exception(
        self,
        session: cffi_requests.Session,
        err: Exception,
        redirect_uri: str,
    ) -> Optional[str]:
        """从异常信息与 Cookie 中提取 OAuth 授权码。"""
        try:
            m = re.search(r"(https?://localhost[^\s'\"]+)", str(err))
            if m:
                code = _extract_code_from_url(m.group(1))
                if code:
                    self._log("OAuth 异常中捕获到 localhost 回调 code", "warning")
                    return code
        except Exception:
            pass
        self._log(f"OAuth 异常提码失败，回退 Cookie: {self._short_log_text(err, 220)}", "warning")
        self._oauth_debug_cookie_snapshot(session, "OAuth 异常分支")
        return self._extract_oauth_code_from_session_cookies(session, redirect_uri=redirect_uri)

    def _oauth_follow_candidate_urls_for_code(
        self,
        session: cffi_requests.Session,
        candidate_urls: list[str],
        redirect_uri: str,
    ) -> Optional[str]:
        """按顺序跟随候选 URL，尝试提取 OAuth code。"""
        visited: set[str] = set()
        for idx, candidate in enumerate(candidate_urls, start=1):
            url = str(candidate or "").strip()
            if not url or url in visited:
                continue
            visited.add(url)
            self._log(
                f"OAuth 候选回跳[{idx}] -> {self._short_log_text(url, 170)}",
                "warning",
            )
            direct_code = _extract_code_from_url(url)
            if direct_code:
                self._log(f"OAuth 候选回跳[{idx}] 直接命中 code", "warning")
                return direct_code
            code = self._oauth_follow_and_extract_code(session, url)
            if code:
                self._log(f"OAuth 候选回跳[{idx}] 跟随链路命中 code", "warning")
                return code
            cookie_code = self._extract_oauth_code_from_session_cookies(session, redirect_uri=redirect_uri)
            if cookie_code:
                self._log(f"OAuth 候选回跳[{idx}] 从 Cookie 命中 code", "warning")
                return cookie_code
        if candidate_urls:
            self._oauth_debug_cookie_snapshot(session, "OAuth 候选回跳结束仍无code")
        return None

    def _oauth_visit_authorize_entry(
        self,
        session: cffi_requests.Session,
        oauth_start: OAuthStart,
    ) -> Tuple[Optional[str], str]:
        """访问 OAuth authorize 入口，返回 (code, consent_url)。"""
        consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
        try:
            resp_entry = session.get(
                oauth_start.auth_url,
                headers={"referer": f"{self.oauth_issuer}/log-in"},
                allow_redirects=False,
                timeout=30,
            )
            self._raise_if_phone_required(
                url=str(resp_entry.url),
                text=resp_entry.text or "",
                stage="OAuth Authorize 入口",
            )
            self._log(f"OAuth Authorize 入口状态: {resp_entry.status_code}")

            if resp_entry.status_code in (301, 302, 303, 307, 308):
                loc = resp_entry.headers.get("Location", "")
                self._log(
                    f"OAuth Authorize 入口Location: {self._short_log_text(loc, 180) or '-'}",
                    "warning",
                )
                self._raise_if_phone_required(url=loc, stage="OAuth Authorize 入口(Location)")
                entry_next = urljoin(oauth_start.auth_url, loc) if loc else ""
                if entry_next and "/sign-in-with-chatgpt/codex/consent" in entry_next:
                    consent_url = entry_next
                    self._log(f"OAuth Authorize 入口跳转到 Consent: {consent_url[:120]}...")
                    return None, consent_url
                code = self._oauth_follow_candidate_urls_for_code(
                    session,
                    [entry_next] if entry_next else [],
                    redirect_uri=oauth_start.redirect_uri,
                )
                return code, consent_url

            if resp_entry.status_code == 200:
                code = _extract_code_from_url(str(resp_entry.url))
                if code:
                    return code, consent_url

                entry_callback = self._extract_redirect_from_html(resp_entry.text or "", oauth_start.redirect_uri)
                code = _extract_code_from_url(entry_callback or "")
                if code:
                    return code, consent_url

                nav_url = self._extract_navigation_url_from_html(resp_entry.text or "", base_url=str(resp_entry.url))
                self._oauth_debug_response_probe(
                    "OAuth Authorize 入口(200)",
                    resp_entry,
                    response_text=resp_entry.text or "",
                    redirect_uri=oauth_start.redirect_uri,
                )
                if nav_url and "/sign-in-with-chatgpt/codex/consent" in nav_url:
                    consent_url = nav_url
                    return None, consent_url
                code = self._oauth_follow_candidate_urls_for_code(
                    session,
                    [nav_url] if nav_url else [],
                    redirect_uri=oauth_start.redirect_uri,
                )
                if code:
                    return code, consent_url

                if "/sign-in-with-chatgpt/codex/consent" in str(resp_entry.url):
                    consent_url = str(resp_entry.url)
                    return None, consent_url
        except Exception as e:
            self._log(f"OAuth Authorize 入口异常: {self._short_log_text(e, 220)}", "warning")
            code = self._oauth_extract_code_from_exception(
                session,
                e,
                redirect_uri=oauth_start.redirect_uri,
            )
            if code:
                return code, consent_url

        return None, consent_url

    def _oauth_try_consent_flow(
        self,
        session: cffi_requests.Session,
        consent_url: str,
        oauth_start: OAuthStart,
    ) -> Optional[str]:
        """优先走真实 Consent 页面继续授权链路。"""
        try:
            resp_consent = session.get(
                consent_url,
                headers={"referer": f"{self.oauth_issuer}/log-in"},
                allow_redirects=False,
                timeout=30,
            )
            self._log(
                (
                    f"OAuth Consent 入口响应: status={resp_consent.status_code}, "
                    f"url={self._short_log_text(str(resp_consent.url), 150)}, "
                    f"location={self._short_log_text(resp_consent.headers.get('Location', ''), 150) or '-'}"
                ),
                "warning",
            )
            self._raise_if_phone_required(
                url=str(resp_consent.url),
                text=resp_consent.text or "",
                stage="OAuth Consent",
            )

            if resp_consent.status_code in (301, 302, 303, 307, 308):
                loc = resp_consent.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Consent(Location)")
                return self._oauth_follow_candidate_urls_for_code(
                    session,
                    [loc],
                    redirect_uri=oauth_start.redirect_uri,
                )

            if resp_consent.status_code != 200:
                self._oauth_debug_response_probe(
                    "OAuth Consent 非200",
                    resp_consent,
                    response_text=resp_consent.text or "",
                    redirect_uri=oauth_start.redirect_uri,
                )
                self._oauth_debug_cookie_snapshot(session, "OAuth Consent 非200后")
                return self._extract_oauth_code_from_session_cookies(
                    session,
                    redirect_uri=oauth_start.redirect_uri,
                )

            code = self._oauth_submit_consent_form(
                session,
                page_url=str(resp_consent.url),
                html_text=resp_consent.text or "",
                redirect_uri=oauth_start.redirect_uri,
                authorize_url=oauth_start.auth_url,
            )
            if code:
                return code

            cookie_code = self._extract_oauth_code_from_session_cookies(
                session,
                redirect_uri=oauth_start.redirect_uri,
            )
            if cookie_code:
                return cookie_code

            # 表单提交后仍无 code，继续跟随真实链路进行回跳提取。
            self._log("OAuth Consent 表单后仍无 code，进入候选回跳链路", "warning")
            return self._oauth_follow_candidate_urls_for_code(
                session,
                [
                    oauth_start.auth_url,
                    str(resp_consent.url),
                    consent_url,
                ],
                redirect_uri=oauth_start.redirect_uri,
            )
        except Exception as e:
            self._log(f"OAuth Consent 阶段异常: {self._short_log_text(e, 220)}", "warning")
            return self._oauth_extract_code_from_exception(
                session,
                e,
                redirect_uri=oauth_start.redirect_uri,
            )

    def _oauth_try_workspace_flow(
        self,
        session: cffi_requests.Session,
        consent_url: str,
        oauth_start: OAuthStart,
    ) -> Optional[str]:
        """workspace/organization 旁路兜底（可配置开关）。"""
        if not self.oauth_enable_workspace_fallback:
            return None

        workspace_id = self._oauth_get_workspace_id(
            session,
            consent_url=consent_url,
            authorize_url=oauth_start.auth_url,
        )
        if not workspace_id:
            return None

        headers = {
            "referer": consent_url,
            "content-type": "application/json",
        }
        try:
            resp_ws = session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers=headers,
                data=json.dumps({"workspace_id": workspace_id}),
                timeout=30,
                allow_redirects=False,
            )
            if resp_ws.status_code in (301, 302, 303, 307, 308):
                loc = resp_ws.headers.get("Location", "")
                self._raise_if_phone_required(url=loc, stage="OAuth Workspace(Location)")
                return self._oauth_follow_candidate_urls_for_code(
                    session,
                    [loc],
                    redirect_uri=oauth_start.redirect_uri,
                )

            if resp_ws.status_code != 200:
                return None

            ws_data = resp_ws.json() if resp_ws.text else {}
            ws_next = str(ws_data.get("continue_url") or "")
            ws_page = str(((ws_data.get("page") or {}).get("type")) or "")
            self._raise_if_phone_required(
                url=ws_next,
                page_type=ws_page,
                text=json.dumps(ws_data, ensure_ascii=False),
                stage="OAuth Workspace",
            )

            if "organization" in ws_next or "organization" in ws_page:
                org_url = ws_next if ws_next.startswith("http") else f"{self.oauth_issuer}{ws_next}"
                org_id = None
                project_id = None
                ws_orgs = (ws_data.get("data") or {}).get("orgs", []) if isinstance(ws_data, dict) else []
                if ws_orgs:
                    org_id = (ws_orgs[0] or {}).get("id")
                    projects = (ws_orgs[0] or {}).get("projects", [])
                    if projects:
                        project_id = (projects[0] or {}).get("id")

                if not org_id:
                    self._raise_if_phone_required(url=org_url, stage="OAuth Organization")
                    return self._oauth_follow_and_extract_code(session, org_url)

                body = {"org_id": org_id}
                if project_id:
                    body["project_id"] = project_id
                resp_org = session.post(
                    f"{self.oauth_issuer}/api/accounts/organization/select",
                    json=body,
                    headers={
                        "referer": org_url,
                        "content-type": "application/json",
                    },
                    timeout=30,
                    allow_redirects=False,
                )
                if resp_org.status_code in (301, 302, 303, 307, 308):
                    loc = resp_org.headers.get("Location", "")
                    self._raise_if_phone_required(url=loc, stage="OAuth Organization(Location)")
                    return self._oauth_follow_candidate_urls_for_code(
                        session,
                        [loc],
                        redirect_uri=oauth_start.redirect_uri,
                    )
                if resp_org.status_code == 200:
                    org_next = str((resp_org.json() or {}).get("continue_url") or "")
                    if org_next:
                        full_next = org_next if org_next.startswith("http") else f"{self.oauth_issuer}{org_next}"
                        self._raise_if_phone_required(url=full_next, stage="OAuth Organization")
                        return self._oauth_follow_and_extract_code(session, full_next)
                return None

            if ws_next:
                full_next = ws_next if ws_next.startswith("http") else f"{self.oauth_issuer}{ws_next}"
                self._raise_if_phone_required(url=full_next, stage="OAuth Workspace")
                return self._oauth_follow_and_extract_code(session, full_next)
            return None
        except Exception as e:
            self._log(f"OAuth workspace/organization 处理异常: {e}", "warning")
            return self._oauth_extract_code_from_exception(
                session,
                e,
                redirect_uri=oauth_start.redirect_uri,
            )

    def _oauth_try_final_redirect_fallback(
        self,
        session: cffi_requests.Session,
        consent_url: str,
        oauth_start: OAuthStart,
    ) -> Optional[str]:
        """最后兜底：允许自动重定向后再提取 code。"""
        try:
            resp_fallback = session.get(
                consent_url,
                headers={"referer": f"{self.oauth_issuer}/log-in"},
                allow_redirects=True,
                timeout=30,
            )
            self._oauth_debug_response_probe(
                "OAuth 最终重定向兜底",
                resp_fallback,
                response_text=resp_fallback.text or "",
                redirect_uri=oauth_start.redirect_uri,
            )
            self._raise_if_phone_required(
                url=str(resp_fallback.url),
                text=resp_fallback.text or "",
                stage="OAuth Consent(兜底)",
            )
            code = _extract_code_from_url(str(resp_fallback.url))
            if code:
                return code
            if getattr(resp_fallback, "history", None):
                for hist in resp_fallback.history:
                    loc = hist.headers.get("Location", "")
                    self._raise_if_phone_required(url=loc, stage="OAuth Consent(兜底 Location)")
                    code = _extract_code_from_url(loc)
                    if code:
                        return code
            self._oauth_debug_cookie_snapshot(session, "OAuth 最终兜底后仍无code")
            return self._extract_oauth_code_from_session_cookies(
                session,
                redirect_uri=oauth_start.redirect_uri,
            )
        except Exception as e:
            return self._oauth_extract_code_from_exception(
                session,
                e,
                redirect_uri=oauth_start.redirect_uri,
            )

    def _oauth_exchange_auth_code(self, session: cffi_requests.Session, oauth_start: OAuthStart) -> Optional[str]:
        """从 OAuth 授权链路中提取 code（复刻稳定脚本：Workspace -> Redirect）。"""
        self._log("获取 Workspace ID...")
        workspace_id = self._oauth_get_workspace_id(
            session,
            consent_url=f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
            authorize_url=oauth_start.auth_url,
            probe_pages=False,
        )
        if not workspace_id:
            # 保留一次页面探测兜底，避免 cookie 场景缺失导致硬失败
            workspace_id = self._oauth_get_workspace_id(
                session,
                consent_url=f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
                authorize_url=oauth_start.auth_url,
                probe_pages=True,
            )
        if not workspace_id:
            self._log("获取 Workspace ID 失败", "error")
            return None

        self._log("选择 Workspace...")
        continue_url = self._oauth_select_workspace(session, workspace_id)
        if not continue_url:
            self._log("选择 Workspace 失败", "error")
            return None

        self._log("跟随重定向链...")
        callback_url = self._oauth_follow_redirects(session, continue_url)
        if not callback_url:
            self._log("跟随重定向链失败", "error")
            return None

        auth_code = _extract_code_from_url(callback_url)
        if auth_code:
            return auth_code

        # 少数场景 code 可能仅存在于 cookie
        cookie_code = self._extract_oauth_code_from_session_cookies(
            session,
            redirect_uri=oauth_start.redirect_uri,
        )
        if cookie_code:
            return cookie_code

        self._log("重定向完成但未提取到授权码", "error")
        return None

    def _oauth_handle_callback(
        self,
        oauth_manager: OAuthManager,
        oauth_start: OAuthStart,
        callback_url: str,
    ) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调（OAuth 登录流程）。"""
        try:
            self._log("处理 OAuth 回调...")
            token_info = oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=oauth_start.state,
                code_verifier=oauth_start.code_verifier
            )
            self._log("OAuth 授权成功")
            return token_info
        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def _get_oauth_tokens_via_existing_session(self) -> Optional[Dict[str, Any]]:
        """复用当前会话尝试直接完成 OAuth 授权（避免二次登录）。"""
        try:
            if self.session is None:
                return None

            self._log("尝试复用现有会话获取 OAuth Token")
            oauth_manager = OAuthManager(
                client_id=self.oauth_client_id,
                auth_url=f"{self.oauth_issuer}/oauth/authorize",
                token_url=f"{self.oauth_issuer}/oauth/token",
                redirect_uri=self.oauth_redirect_uri,
                scope="openid email profile offline_access",
                proxy_url=self.proxy_url,
            )
            max_attempts = self.oauth_session_reuse_max_attempts
            for attempt in range(1, max_attempts + 1):
                try:
                    self._oauth_wait_global_cooldown_if_needed()
                    oauth_start = oauth_manager.start_oauth()
                    self._log(f"OAuth URL 已生成(复用会话): {oauth_start.auth_url[:80]}...")

                    # 去掉 prompt=login，避免强制重新登录
                    try:
                        parsed = urlparse(oauth_start.auth_url)
                        query = parse_qs(parsed.query, keep_blank_values=True)
                        params = {k: (v[-1] if isinstance(v, list) and v else v) for k, v in query.items()}
                        params.pop("prompt", None)
                        authorize_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    except Exception:
                        authorize_url = oauth_start.auth_url

                    callback_url = self._follow_oauth_redirect(
                        authorize_url,
                        oauth_start.redirect_uri,
                        allow_login=False,
                    )
                    if not callback_url:
                        self._log("复用会话未拿到 OAuth 回调", "warning")
                        continue

                    token_info = self._oauth_handle_callback(oauth_manager, oauth_start, callback_url)
                    if not token_info:
                        self._log("复用会话处理 OAuth 回调失败，准备重试", "warning")
                        continue

                    self._oauth_session_token = self._get_session_cookie()
                    return token_info
                except OAuthPhoneRequiredError:
                    self._log(
                        f"复用会话遇到手机号校验拦截，重新获取 OAuth URL 重试 ({attempt}/{max_attempts})",
                        "warning",
                    )
                    if attempt >= max_attempts:
                        return None
                except Exception as e:
                    error_text = str(e)
                    if self._oauth_is_rate_limited(error_text):
                        self._oauth_handle_rate_limit(attempt, stage="OAuth 复用会话")
                        return None
                    self._log(f"复用会话 OAuth 异常: {error_text}", "warning")
                    continue

        except Exception as e:
            self._log(f"复用会话 OAuth 失败: {e}", "warning")
            return None

    def _get_oauth_tokens_via_login_flow(self) -> Optional[Dict[str, Any]]:
        """使用旧版 OAuth 登录流程获取 Token（含 refresh_token）。"""
        try:
            oauth_manager = OAuthManager(
                client_id=self.oauth_client_id,
                auth_url=f"{self.oauth_issuer}/oauth/authorize",
                token_url=f"{self.oauth_issuer}/oauth/token",
                redirect_uri=self.oauth_redirect_uri,
                scope="openid email profile offline_access",
                proxy_url=self.proxy_url,
            )
            max_attempts = self.oauth_login_max_attempts
            last_error = ""
            for attempt in range(1, max_attempts + 1):
                try:
                    self._oauth_wait_global_cooldown_if_needed()
                    self._log(f"尝试 OAuth 登录流程获取 Token（第 {attempt}/{max_attempts} 次）")
                    oauth_start = oauth_manager.start_oauth()
                    self._log(f"OAuth URL 已生成: {oauth_start.auth_url[:80]}...")

                    http_client = OpenAIHTTPClient(proxy_url=self.proxy_url)
                    session = http_client.session

                    did = self._oauth_get_device_id(session, oauth_start.auth_url)
                    if not did:
                        last_error = "获取 Device ID 失败"
                        self._log(last_error, "warning")
                        continue

                    sen_token = http_client.check_sentinel(did)
                    if not sen_token:
                        self._log("Sentinel 校验失败，尝试继续 OAuth 登录流程", "warning")
                    self._oauth_login_did = did or ""
                    self._oauth_login_sentinel = sen_token or ""

                    login_start = self._oauth_submit_login_start(session, did, sen_token)
                    if not login_start.success:
                        if login_start.error_message == "PHONE_REQUIRED":
                            raise OAuthPhoneRequiredError("登录入口需要手机号验证")
                        last_error = f"登录入口失败: {login_start.error_message or 'unknown'}"
                        self._log(last_error, "warning")
                        if self._oauth_is_rate_limited(last_error):
                            self._oauth_handle_rate_limit(attempt, stage="OAuth 登录")
                            return None
                        continue

                    if login_start.page_type == OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
                        password_result = self._oauth_submit_login_password(session)
                        if not password_result.success:
                            if password_result.error_message == "PHONE_REQUIRED":
                                raise OAuthPhoneRequiredError("登录密码阶段需要手机号验证")
                            last_error = f"登录密码阶段失败: {password_result.error_message or 'unknown'}"
                            self._log(last_error, "warning")
                            continue
                        if not password_result.is_existing_account:
                            if password_result.error_message == "PHONE_REQUIRED":
                                raise OAuthPhoneRequiredError("登录密码阶段需要手机号验证")
                            last_error = f"登录密码阶段未进入验证码页面: {password_result.page_type or 'unknown'}"
                            self._log(last_error, "warning")
                            continue
                    elif login_start.page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                        self._log("已进入验证码页面，跳过密码步骤")
                    else:
                        if self._is_phone_required(page_type=login_start.page_type):
                            raise OAuthPhoneRequiredError("登录入口需要手机号验证")
                        last_error = f"登录入口未进入预期页面: {login_start.page_type}"
                        self._log(last_error, "warning")
                        continue

                    self._log("获取邮箱验证码")
                    code = self.wait_for_verification_email(timeout=120)
                    if not code:
                        last_error = "获取邮箱验证码失败"
                        self._log(last_error, "warning")
                        continue

                    self._log("校验邮箱验证码")
                    if not self._oauth_validate_verification_code(session, code):
                        self._log("验证码校验失败，尝试重新获取最新验证码后重试一次", "warning")
                        retry_code = self.wait_for_verification_email(timeout=45)
                        if retry_code and retry_code != code:
                            self._log("使用重试验证码再次校验")
                            if self._oauth_validate_verification_code(session, retry_code):
                                self._log("重试验证码校验成功")
                            else:
                                last_error = "验证码校验失败"
                                self._log(last_error, "warning")
                                continue
                        else:
                            last_error = "验证码校验失败"
                            self._log(last_error, "warning")
                            continue

                    auth_code = self._oauth_exchange_auth_code(session, oauth_start)
                    if not auth_code:
                        if self.oauth_enable_redirect_chain_fallback:
                            self._log("未能从 Workspace/重定向链提取 code，尝试授权入口重定向兜底", "warning")
                            fallback_callback = self._oauth_follow_redirects(session, oauth_start.auth_url)
                            if fallback_callback:
                                token_info = self._oauth_handle_callback(
                                    oauth_manager,
                                    oauth_start,
                                    fallback_callback,
                                )
                                if token_info:
                                    self._oauth_session_token = session.cookies.get("__Secure-next-auth.session-token") or ""
                                    return token_info
                            self._log("授权入口重定向兜底未提取到回调", "error")
                        else:
                            self._log("未能从 Workspace/重定向链提取 code", "warning")
                        last_error = "未能从 Workspace/重定向链提取 code"
                        continue

                    callback_url = f"{oauth_start.redirect_uri}?code={auth_code}&state={oauth_start.state}"
                    token_info = self._oauth_handle_callback(oauth_manager, oauth_start, callback_url)
                    if not token_info:
                        last_error = "OAuth 回调处理失败"
                        self._log(last_error, "warning")
                        continue

                    self._oauth_session_token = session.cookies.get("__Secure-next-auth.session-token") or ""
                    return token_info
                except OAuthPhoneRequiredError:
                    self._log(
                        f"OAuth 登录流程被手机号校验拦截，重新获取 OAuth URL 重试 ({attempt}/{max_attempts})",
                        "warning",
                    )
                    if attempt >= max_attempts:
                        return None
                except Exception as e:
                    last_error = str(e)
                    if self._oauth_is_rate_limited(last_error):
                        self._oauth_handle_rate_limit(attempt, stage="OAuth 登录")
                        return None
                    self._log(f"OAuth 登录流程异常: {e}，准备重试", "warning")
                    continue

            if last_error:
                self._log(f"OAuth 登录流程最终失败: {last_error}", "warning")
            return None

        except Exception as e:
            self._log(f"OAuth 登录流程失败: {e}", "warning")
            return None

    def get_oauth_tokens(self) -> Optional[Dict[str, Any]]:
        """通过 OAuth 授权获取 access_token/refresh_token。"""
        try:
            if self.oauth_enable_session_reuse:
                self._log("OAuth 授权流程：优先复用现有会话获取 Token")
                tokens = self._get_oauth_tokens_via_existing_session()
                if tokens and tokens.get("access_token"):
                    return tokens
                self._log("复用会话失败，回退 OAuth 登录流程", "warning")
            else:
                self._log("OAuth 授权流程：已禁用复用会话，直接走 OAuth 登录流程")
            return self._get_oauth_tokens_via_login_flow()
        except Exception as e:
            self._log(f"OAuth 授权失败: {e}", "warning")
            return None

    # ====== Main Run ======

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        token_source = "unknown"
        issued_client_id = ""
        token_audience = []
        token_scope = ""
        auth_profile = "unknown"
        registration_completed = False

        try:
            self._log("=" * 60)
            self._log("开始注册流程 (模拟浏览器方式)")
            self._log("=" * 60)

            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result
            result.email = self.email
            self.password = self._generate_password()
            result.password = self.password
            
            user_info = generate_random_user_info()
            name = user_info['name']
            birthdate = user_info['birthdate']

            self._log("访问 ChatGPT 首页...")
            self.visit_homepage()
            _random_delay(0.3, 0.8)

            self._log("获取 CSRF, 执行 Signin...")
            csrf = self.get_csrf()
            _random_delay(0.2, 0.5)
            auth_url = self.signin(self.email, csrf)
            _random_delay(0.3, 0.8)

            self._log("Authorize跳转...")
            final_url = self.authorize(auth_url)
            final_path = urlparse(final_url).path
            self._log(f"授权路径 -> {final_path}")
            
            _random_delay(0.3, 0.8)

            self._log("获取 Sentinel Token...")
            sentinel_token, _ = self._fetch_sentinel_tokens()

            need_otp = False
            account_created = False
            
            if "create-account/password" in final_path:
                self._log("全新注册流程: 提交密码")
                _random_delay(0.5, 1.0)
                status, data = self.register(self.email, self.password, sentinel_token)
                if status != 200: raise Exception(f"Register 失败 ({status}): {data}")
                _random_delay(0.3, 0.8)
                self.send_otp()
                need_otp = True
            elif "email-verification" in final_path or "email-otp" in final_path:
                self._log("遇到已注册/二次验证 OTP，等待验证码")
                need_otp = True
            elif "about-you" in final_path:
                self._log("跳到 about-you")
                _random_delay(0.5, 1.0)
                about_status, about_data = self.create_account(name, birthdate, retries=2)
                if about_status != 200:
                    raise Exception(f"Create Account 失败 ({about_status}): {self._short_log_text(about_data, 220)}")
                account_created = True
            elif "callback" in final_path or "chatgpt.com" in final_url:
                self._log("跳过注册，直接回调")
            else:
                self._log(f"未知跳转路径: {final_url}，默认走新注册")
                self.register(self.email, self.password, sentinel_token)
                self.send_otp()
                need_otp = True

            if need_otp:
                otp_code = self.wait_for_verification_email(timeout=120)
                if not otp_code: raise Exception("获取验证码超时或失败")
                self._log(f"拿到验证码: {otp_code}")
                _random_delay(0.3, 0.8)
                status, data = self.validate_otp(otp_code, sentinel_token)
                if status != 200:
                    if status == 0:
                        self._log("验证码校验请求失败，疑似网络波动；先使用同一验证码重试一次", "warning")
                        _random_delay(1.0, 2.0)
                        status, data = self.validate_otp(otp_code, sentinel_token)

                    if status != 200:
                        self._log("验证码通过失败，重试发送...")
                        resend_status, _ = self.send_otp()
                        if resend_status == 200:
                            _random_delay(1.0, 2.0)
                            otp_code = self.wait_for_verification_email(timeout=60)
                            if not otp_code: raise Exception("重试验证码失败")
                            status, data = self.validate_otp(otp_code, sentinel_token)
                        elif status == 0:
                            # 重发本身也失败时，保留最后一次用原验证码校验机会，减少网络波动导致的假失败
                            self._log("重发验证码请求失败，回退再次校验上一次验证码", "warning")
                            _random_delay(1.0, 2.0)
                            status, data = self.validate_otp(otp_code, sentinel_token)
                        if status != 200: raise Exception("OTP验证反复失败")

            # 继续流程：创建账号（对齐 any-auto-register 逻辑）
            if not account_created:
                self._log("创建用户账户...")
                _random_delay(0.4, 0.9)
                status, data = self.create_account(
                    name,
                    birthdate,
                    retries=2,
                )
                if status != 200:
                    raise Exception(f"Create Account 失败 ({status}): {self._short_log_text(data, 220)}")
            registration_completed = True

            # 抓取 Token
            if self.token_mode == "oauth":
                self._log("注册完成，开始重新登录以获取 Token...")
                self._log("尝试通过 OAuth 授权获取 Token（含 refresh_token）")
                tokens = self.get_oauth_tokens()
                if tokens and tokens.get("access_token"):
                    self._log("OAuth Token 获取成功")
                    result.access_token = tokens.get("access_token") or ""
                    result.refresh_token = tokens.get("refresh_token") or ""
                    result.id_token = tokens.get("id_token") or ""
                    result.account_id = tokens.get("account_id") or result.account_id
                    issued_client_id = str(tokens.get("issued_client_id") or "").strip()
                    token_audience = tokens.get("token_audience") or []
                    if not isinstance(token_audience, list):
                        token_audience = [str(token_audience)]
                    token_scope = str(tokens.get("token_scope") or "").strip()
                    if not result.email and tokens.get("email"):
                        result.email = tokens.get("email")
                    result.success = True
                    token_source = "oauth"
                    auth_profile = "codex_oauth"
                    result.session_token = self._oauth_session_token or self._get_session_cookie()
                else:
                    result.session_token = result.session_token or self._get_session_cookie() or ""
                    self._log("OAuth Token 获取失败（OAuth 模式不回退 Session）", "warning")
                    recent_logs = " ".join(self.logs[-8:]).lower()
                    if self._oauth_is_rate_limited(recent_logs):
                        result.error_message = "OAuth Token 获取失败: rate_limited"
                    else:
                        result.error_message = "OAuth Token 获取失败"
            else:
                self._log("尝试从 ChatGPT Session 提取 Token")
                tokens = self.get_chatgpt_session_tokens()
                if tokens and tokens.get("access_token"):
                    self._log("Token 提取成功")
                    result.access_token = tokens["access_token"]
                    result.refresh_token = tokens["refresh_token"]
                    result.id_token = tokens["id_token"]
                    result.account_id = tokens.get("account_id") or result.account_id
                    result.success = True
                    token_source = "session"
                    auth_profile = "session"
                    result.session_token = self._get_session_cookie()
                else:
                    # 尝试用 OAuth 后备，其实不需要，只需要报没抓到就可以
                    self._log("Session Token 提取失败，如果需要 Codex OAuth，请切换为 OAuth 模式。", "warning")
                    # 因为用户要求改成这个流程，这里为了稳妥如果是用 123.py 正常是可以拿到的。
                    result.error_message = "无法在会话中提取到 Token"

            if result.success:
                self._log("=" * 60)
                self._log("注册成功!")
                self._log(f"邮箱: {result.email}")
                self._log(f"密码: {result.password}")
                self._log("=" * 60)

            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "email_service_id": self.email_info.get("service_id") if self.email_info else None,
                "proxy_used": self.proxy_url,
                "token_mode": self.token_mode,
                "token_source": token_source,
                "auth_profile": auth_profile,
                "issued_client_id": issued_client_id,
                "token_audience": token_audience,
                "token_scope": token_scope,
                "registration_completed": registration_completed,
                "registered_at": datetime.now().isoformat(),
                "user_agent": self.ua,
            }
            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success:
            return False
        try:
            settings = get_settings()
            metadata = result.metadata or {}
            token_source = str(metadata.get("token_source") or "").strip().lower()
            issued_client_id = str(metadata.get("issued_client_id") or "").strip()
            client_id_for_db = issued_client_id or (
                settings.openai_client_id
                if token_source in {"oauth", "browser_oauth"} and result.refresh_token
                else None
            )
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=client_id_for_db,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )
                self._log(f"账户已保存到数据库，ID: {account.id}")
                return True
        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
