"""
注册流程引擎
从 main.py 中提取并重构的注册流程
加入了 123.py 的模拟浏览器并发注册流程
"""

import re
import json
import time
import logging
import secrets
import string
import random
import uuid
import hashlib
import base64
import html
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

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


def _random_delay(low=0.3, high=1.0):
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
    if not url or "code=" not in url:
        return None
    try:
        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
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
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        self.token_mode = (token_mode or "session").strip().lower()
        if self.token_mode not in ("session", "oauth"):
            self.token_mode = "session"

        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.session = cffi_requests.Session(impersonate=self.impersonate)
        if proxy_url:
            self.session.proxies = {"http": proxy_url, "https": proxy_url}
        
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": self.sec_ch_ua, "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"', "sec-ch-ua-arch": '"x86"', "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
        })
        
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
        self._callback_url = None
        self._final_callback_url = None

        self.BASE = "https://chatgpt.com"
        self.AUTH = "https://auth.openai.com"

        settings = get_settings()
        self.oauth_client_id = settings.openai_client_id
        self.oauth_redirect_uri = settings.openai_redirect_uri
        self.oauth_issuer = settings.openai_auth_url.split('/oauth/')[0] if settings.openai_auth_url else "https://auth.openai.com"
        self._oauth_session_token = ""

    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")
        if level == "error": logger.error(message)
        elif level == "warning": logger.warning(message)
        else: logger.info(message)

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
        code = self.email_service.get_verification_code(
            email=self.email,
            email_id=email_id,
            timeout=timeout,
            pattern=OTP_CODE_PATTERN,
            otp_sent_at=self._otp_sent_at,
        )
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
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.BASE}/", "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
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
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/create-account/password", "Origin": self.AUTH}
        headers.update(_make_trace_headers())
        if sentinel_token: headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"username": email, "password": password}, headers=headers)
        try: data = r.json()
        except: data = {"text": r.text[:500]}
        self._log(f"Register -> {r.status_code}")
        return r.status_code, data

    def send_otp(self):
        self._otp_sent_at = time.time()
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.AUTH}/create-account/password", "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._log(f"Send OTP -> {r.status_code}")
        return r.status_code, {}

    def validate_otp(self, code: str, sentinel_token: str = None):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/email-verification", "Origin": self.AUTH}
        headers.update(_make_trace_headers())
        if sentinel_token: headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"code": code}, headers=headers)
        try: data = r.json()
        except: data = {"text": r.text[:500]}
        self._log(f"Validate OTP -> {r.status_code}")
        return r.status_code, data

    def create_account(self, name: str, birthdate: str, so_token: str = None):
        url = f"{self.AUTH}/api/accounts/create_account"
        headers = {
            "Content-Type": "application/json", "Accept": "application/json",
            "Referer": f"{self.AUTH}/about-you", "Origin": self.AUTH,
            "User-Agent": self.ua, "oai-device-id": self.device_id,
            "sec-ch-ua": self.sec_ch_ua, "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"', "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin",
        }
        headers.update(_make_trace_headers())
        payload = {"name": name, "birthdate": birthdate}
        if so_token: headers["openai-sentinel-token"] = so_token

        r = self.session.post(url, json=payload, headers=headers, impersonate=self.impersonate)
        if r.status_code == 400 and "registration_disallowed" in (r.text or ""):
            self._log("registration_disallowed, 重新获取 sentinel 重试...")
            fresh_token = build_sentinel_token(
                self.session, self.device_id, flow="oauth_create_account",
                user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
            )
            if fresh_token:
                headers["openai-sentinel-token"] = fresh_token
                r = self.session.post(url, json=payload, headers=headers, impersonate=self.impersonate)

        try: data = r.json()
        except: data = {"text": r.text[:500]}
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
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
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

    def _extract_redirect_from_html(self, text: str, redirect_uri: str) -> Optional[str]:
        """从 HTML 中抽取回调地址（meta refresh / window.location / 链接）。"""
        if not text:
            return None

        patterns = (
            r'http-equiv=["\']refresh["\']\s+content=["\']\d+;\s*url=([^"\']+)["\']',
            r'window\.location(?:\.href)?\s*=\s*"([^"]+)"',
            r'location\.href\s*=\s*"([^"]+)"',
            r'location\s*=\s*"([^"]+)"',
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                candidate = html.unescape(match.group(1))
                if candidate.startswith(redirect_uri):
                    return candidate

        for match in re.findall(r"https?://[^\s\"'>]+", text):
            if match.startswith(redirect_uri):
                return match

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

    def _looks_like_login_page(self, url: str, text: str) -> bool:
        url_lower = (url or "").lower()
        if "/u/login/" in url_lower:
            return True
        if "name=\"username\"" in text or "name=\"password\"" in text:
            return True
        if "login" in url_lower and "auth.openai.com" in url_lower:
            return True
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
            if current_url.startswith(redirect_uri):
                return current_url

            loc = resp.headers.get("Location") or resp.headers.get("location")
            if loc:
                if loc.startswith("/"):
                    loc = urljoin(current_url, loc)
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
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location") or r.headers.get("location")
                if not loc:
                    return None
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
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
                time.sleep(attempt)
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

    def _oauth_get_workspace_id(self, session: cffi_requests.Session) -> Optional[str]:
        """获取 Workspace ID（OAuth 登录流程）。"""
        try:
            auth_cookie = session.cookies.get("oai-client-auth-session")
            if not auth_cookie:
                self._log("未能获取到授权 Cookie", "error")
                return None

            try:
                segments = auth_cookie.split(".")
                if not segments:
                    self._log("授权 Cookie 格式错误", "error")
                    return None

                payload = segments[0]
                pad = "=" * ((4 - (len(payload) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((payload + pad).encode("ascii"))
                auth_json = json.loads(decoded.decode("utf-8"))

                workspaces = auth_json.get("workspaces") or []
                if not workspaces:
                    self._log("授权 Cookie 里没有 workspace 信息", "error")
                    return None

                workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
                if not workspace_id:
                    self._log("无法解析 workspace_id", "error")
                    return None

                self._log(f"Workspace ID: {workspace_id}")
                return workspace_id

            except Exception as e:
                self._log(f"解析授权 Cookie 失败: {e}", "error")
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

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
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

                location = response.headers.get("Location") or ""
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    break
                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                next_url = urljoin(current_url, location)
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url
                current_url = next_url

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
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

    def _get_oauth_tokens_via_login_flow(self) -> Optional[Dict[str, Any]]:
        """使用旧版 OAuth 登录流程获取 Token（含 refresh_token）。"""
        try:
            self._log("尝试 OAuth 登录流程获取 Token")
            oauth_manager = OAuthManager(
                client_id=self.oauth_client_id,
                auth_url=f"{self.oauth_issuer}/oauth/authorize",
                token_url=f"{self.oauth_issuer}/oauth/token",
                redirect_uri=self.oauth_redirect_uri,
                scope="openid email profile offline_access",
                proxy_url=self.proxy_url,
            )
            oauth_start = oauth_manager.start_oauth()
            self._log(f"OAuth URL 已生成: {oauth_start.auth_url[:80]}...")

            http_client = OpenAIHTTPClient(proxy_url=self.proxy_url)
            session = http_client.session

            did = self._oauth_get_device_id(session, oauth_start.auth_url)
            if not did:
                return None

            sen_token = http_client.check_sentinel(did)
            if not sen_token:
                self._log("Sentinel 校验失败，尝试继续 OAuth 登录流程", "warning")

            login_start = self._oauth_submit_login_start(session, did, sen_token)
            if not login_start.success:
                return None

            if login_start.page_type == OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
                password_result = self._oauth_submit_login_password(session)
                if not password_result.success or not password_result.is_existing_account:
                    return None
            elif login_start.page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]:
                self._log("已进入验证码页面，跳过密码步骤")
            else:
                self._log(f"登录入口未进入预期页面: {login_start.page_type}", "warning")
                return None

            self._log("获取邮箱验证码")
            code = self.wait_for_verification_email(timeout=120)
            if not code:
                return None

            self._log("校验邮箱验证码")
            if not self._oauth_validate_verification_code(session, code):
                return None

            workspace_id = self._oauth_get_workspace_id(session)
            if not workspace_id:
                return None

            continue_url = self._oauth_select_workspace(session, workspace_id)
            if not continue_url:
                return None

            callback_url = self._oauth_follow_redirects(session, continue_url)
            if not callback_url:
                return None

            token_info = self._oauth_handle_callback(oauth_manager, oauth_start, callback_url)
            if not token_info:
                return None

            self._oauth_session_token = session.cookies.get("__Secure-next-auth.session-token") or ""
            return token_info

        except Exception as e:
            self._log(f"OAuth 登录流程失败: {e}", "warning")
            return None

    def get_oauth_tokens(self) -> Optional[Dict[str, Any]]:
        """通过 OAuth 授权获取 access_token/refresh_token。"""
        try:
            self._log("OAuth 授权流程：使用旧版 OAuth 登录流程获取 Token")
            return self._get_oauth_tokens_via_login_flow()
        except Exception as e:
            self._log(f"OAuth 授权失败: {e}", "warning")
            return None

    # ====== Main Run ======

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        token_source = "unknown"

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
            sentinel_token, so_token = self._fetch_sentinel_tokens()

            need_otp = False
            
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
                self.create_account(name, birthdate, so_token)
                self.callback()
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
                    self._log("验证码通过失败，重试发送...")
                    self.send_otp()
                    _random_delay(1.0, 2.0)
                    otp_code = self.wait_for_verification_email(timeout=60)
                    if not otp_code: raise Exception("重试验证码失败")
                    status, data = self.validate_otp(otp_code, sentinel_token)
                    if status != 200: raise Exception("OTP验证反复失败")

            # 继续流程
            continue_url = ""
            if 'data' in locals() and isinstance(data, dict):
                continue_url = data.get("continue_url", "")
            if not continue_url: continue_url = f"{self.AUTH}/about-you"
            if continue_url.startswith("/"): continue_url = f"{self.AUTH}{continue_url}"

            _random_delay(0.5, 1.0)
            try:
                self.session.get(continue_url, headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.AUTH}/email-verification", "Upgrade-Insecure-Requests": "1",
                }, allow_redirects=True, impersonate=self.impersonate)
            except Exception as e:
                self._log(f"访问 about-you 可能由于回调重定向断开: {e}")

            _random_delay(0.5, 1.5)
            status, data = self.create_account(name, birthdate, so_token)
            
            _random_delay(0.2, 0.5)
            self.callback()

            # 抓取 Token
            if self.token_mode == "oauth":
                self._log("尝试通过 OAuth 授权获取 Token（含 refresh_token）")
                tokens = self.get_oauth_tokens()
                if tokens and tokens.get("access_token"):
                    self._log("OAuth Token 获取成功")
                    result.access_token = tokens.get("access_token") or ""
                    result.refresh_token = tokens.get("refresh_token") or ""
                    result.id_token = tokens.get("id_token") or ""
                    result.account_id = tokens.get("account_id") or result.account_id
                    if not result.email and tokens.get("email"):
                        result.email = tokens.get("email")
                    result.success = True
                    token_source = "oauth"
                    result.session_token = self._oauth_session_token or self._get_session_cookie()
                else:
                    self._log("OAuth Token 获取失败，尝试回退 Session 提取", "warning")
                    tokens = self.get_chatgpt_session_tokens()
                    if tokens and tokens.get("access_token"):
                        self._log("Session Token 提取成功（OAuth 回退）")
                        result.access_token = tokens["access_token"]
                        result.refresh_token = tokens["refresh_token"]
                        result.id_token = tokens["id_token"]
                        result.account_id = tokens.get("account_id") or result.account_id
                        result.success = True
                        token_source = "session_fallback"
                        result.session_token = self._get_session_cookie()
                    else:
                        result.error_message = "OAuth 与 Session Token 均提取失败"
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
                "proxy_used": self.proxy_url,
                "token_mode": self.token_mode,
                "token_source": token_source,
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
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
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
