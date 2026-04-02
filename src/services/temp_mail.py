"""
Temp-Mail 邮箱服务实现
基于自部署 Cloudflare Worker 临时邮箱服务
接口文档参见 plan/temp-mail.md
"""

import re
import time
import json
import logging
from email import message_from_string
from email.header import decode_header, make_header
from email.message import Message
from email.policy import default as email_policy
from html import unescape
from typing import Optional, Dict, Any, List

from .base import (
    BaseEmailService,
    EmailServiceError,
    EmailServiceType,
    parse_domain_list,
    pick_domain,
)
from ..core.http_client import HTTPClient, RequestConfig
from ..config.constants import OTP_CODE_PATTERN


logger = logging.getLogger(__name__)
EMAIL_ADDRESS_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"


class TempMailService(BaseEmailService):
    """
    Temp-Mail 邮箱服务
    基于自部署 Cloudflare Worker 的临时邮箱，admin 模式管理邮箱
    不走代理，不使用 requests 库
    """

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        """
        初始化 TempMail 服务

        Args:
            config: 配置字典，支持以下键:
                - base_url: Worker 域名地址，如 https://mail.example.com (必需)
                - admin_password: Admin 密码，对应 x-admin-auth header (必需)
                - domain: 邮箱域名，如 example.com (必需)
                - enable_prefix: 是否启用前缀，默认 True
                - timeout: 请求超时时间，默认 30
                - max_retries: 最大重试次数，默认 3
                - site_password/custom_auth: 若开启私有站点密码，填写 x-custom-auth
            name: 服务名称
        """
        super().__init__(EmailServiceType.TEMP_MAIL, name)

        raw_config = config or {}
        missing_keys = []
        if not raw_config.get("base_url"):
            missing_keys.append("base_url")
        if not raw_config.get("admin_password"):
            missing_keys.append("admin_password")
        if not parse_domain_list(raw_config.get("domain") or raw_config.get("default_domain")):
            missing_keys.append("domain")
        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        default_config = {
            "enable_prefix": True,
            "domain_strategy": "round_robin",
            "timeout": 30,
            "max_retries": 3,
        }
        self.config = {**default_config, **raw_config}
        self._domains = self._resolve_domains(self.config)
        self.config["domain"] = ",".join(self._domains)

        # 不走代理，proxy_url=None
        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(proxy_url=None, config=http_config)

        # 邮箱缓存：email -> {jwt, address}
        self._email_cache: Dict[str, Dict[str, Any]] = {}
        # 验证码缓存：按收件邮箱记录最近一次命中的验证码/邮件，避免跨调用重复消费旧邮件
        self._last_code_cache: Dict[str, str] = {}
        self._last_message_id_cache: Dict[str, str] = {}

    def _resolve_domains(self, config: Dict[str, Any]) -> List[str]:
        domains = parse_domain_list(config.get("domain"))
        if domains:
            return domains
        return parse_domain_list(config.get("default_domain"))

    def _build_domain_rr_key(self, domains: List[str]) -> str:
        base_url = str(self.config.get("base_url") or "").strip().lower()
        return f"temp_mail|{self.name}|{base_url}|{','.join(domains)}"

    def _decode_mime_header(self, value: str) -> str:
        """解码 MIME 头，兼容 RFC 2047 编码主题。"""
        if not value:
            return ""
        try:
            return str(make_header(decode_header(value)))
        except Exception:
            return value

    def _extract_body_from_message(self, message: Message) -> str:
        """从 MIME 邮件对象中提取可读正文。"""
        parts: List[str] = []

        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue

                content_type = (part.get_content_type() or "").lower()
                if content_type not in ("text/plain", "text/html"):
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace") if payload else ""
                except Exception:
                    try:
                        text = part.get_content()
                    except Exception:
                        text = ""

                if content_type == "text/html":
                    text = re.sub(r"<[^>]+>", " ", text)
                parts.append(text)
        else:
            try:
                payload = message.get_payload(decode=True)
                charset = message.get_content_charset() or "utf-8"
                body = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                try:
                    body = message.get_content()
                except Exception:
                    body = str(message.get_payload() or "")

            if "html" in (message.get_content_type() or "").lower():
                body = re.sub(r"<[^>]+>", " ", body)
            parts.append(body)

        return unescape("\n".join(part for part in parts if part).strip())

    def _extract_mail_fields(self, mail: Dict[str, Any]) -> Dict[str, str]:
        """统一提取邮件字段，兼容 raw MIME 和不同 Worker 返回格式。"""
        sender = str(
            mail.get("source")
            or mail.get("from")
            or mail.get("from_address")
            or mail.get("fromAddress")
            or ""
        ).strip()
        subject = str(mail.get("subject") or mail.get("title") or "").strip()
        body_text = str(
            mail.get("text")
            or mail.get("body")
            or mail.get("content")
            or mail.get("html")
            or ""
        ).strip()
        raw = str(mail.get("raw") or "").strip()
        source_text = str(mail.get("source") or "").strip()
        if not raw and source_text:
            looks_like_raw = any(
                key in source_text.lower()
                for key in ("subject:", "content-type:", "mime-version:", "return-path:", "from:", "to:")
            )
            if looks_like_raw:
                raw = source_text
                sender = str(
                    mail.get("from")
                    or mail.get("from_address")
                    or mail.get("fromAddress")
                    or ""
                ).strip()

        if raw:
            try:
                message = message_from_string(raw, policy=email_policy)
                sender = sender or self._decode_mime_header(message.get("From", ""))
                subject = subject or self._decode_mime_header(message.get("Subject", ""))
                parsed_body = self._extract_body_from_message(message)
                if parsed_body:
                    body_text = f"{body_text}\n{parsed_body}".strip() if body_text else parsed_body
            except Exception as e:
                logger.debug(f"解析 TempMail raw 邮件失败: {e}")
                body_text = f"{body_text}\n{raw}".strip() if body_text else raw

        body_text = unescape(re.sub(r"<[^>]+>", " ", body_text))
        return {
            "sender": sender,
            "subject": subject,
            "body": body_text,
            "raw": raw,
        }

    def _extract_mail_id(self, mail: Dict[str, Any]) -> str:
        """提取邮件唯一标识，兼容不同 Worker 字段并提供兜底。"""
        id_candidates = ("id", "mailId", "messageId", "msgId", "uuid")
        for key in id_candidates:
            value = mail.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()

        created = (
            mail.get("createdAt")
            or mail.get("created_at")
            or mail.get("createTime")
            or mail.get("create_time")
            or mail.get("date")
            or mail.get("time")
            or ""
        )
        subject = str(mail.get("subject") or mail.get("title") or "").strip()
        sender = str(mail.get("from") or mail.get("fromAddress") or mail.get("source") or "").strip()

        fallback_id = f"{created}|{sender}|{subject}".strip("|")
        return fallback_id

    def _admin_headers(self) -> Dict[str, str]:
        """构造 admin 请求头"""
        headers = {
            "x-admin-auth": self.config["admin_password"],
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        custom_auth = (self.config.get("site_password") or self.config.get("custom_auth") or "").strip()
        if custom_auth:
            headers["x-custom-auth"] = custom_auth
        return headers

    def _user_headers(self, jwt: str) -> Dict[str, str]:
        """构造地址 JWT 请求头（/api/*）"""
        headers = {
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        custom_auth = (self.config.get("site_password") or self.config.get("custom_auth") or "").strip()
        if custom_auth:
            headers["x-custom-auth"] = custom_auth
        return headers

    def _make_request(self, method: str, path: str, **kwargs) -> Any:
        """
        发送请求并返回 JSON 数据

        Args:
            method: HTTP 方法
            path: 请求路径（以 / 开头）
            **kwargs: 传递给 http_client.request 的额外参数

        Returns:
            响应 JSON 数据

        Raises:
            EmailServiceError: 请求失败
        """
        base_url = self.config["base_url"].rstrip("/")
        url = f"{base_url}{path}"

        # 合并默认 admin headers
        kwargs.setdefault("headers", {})
        for k, v in self._admin_headers().items():
            kwargs["headers"].setdefault(k, v)

        try:
            response = self.http_client.request(method, url, **kwargs)

            if response.status_code >= 400:
                error_msg = f"请求失败: {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg = f"{error_msg} - {error_data}"
                except Exception:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                self.update_status(False, EmailServiceError(error_msg))
                raise EmailServiceError(error_msg)

            try:
                return response.json()
            except json.JSONDecodeError:
                return {"raw_response": response.text}

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"请求失败: {method} {path} - {e}")

    def _strip_email_addresses(self, text: str) -> str:
        """移除正文中的邮箱地址，避免将邮箱数字误判为验证码。"""
        if not text:
            return ""
        return re.sub(EMAIL_ADDRESS_PATTERN, " ", text)

    def _is_openai_verification_mail(self, sender: str, content: str) -> bool:
        """
        判断是否属于 OpenAI/ChatGPT 验证邮件。

        说明：
        - 部分邮箱平台会把发件人翻译成“无回复”，或不暴露 openai 域名；
        - 因此除了 openai，也要匹配 chatgpt/验证码语义关键词。
        """
        sender_text = str(sender or "").lower()
        content_text = str(content or "").lower()
        markers = (
            "openai",
            "chatgpt",
            "verification code",
            "your chatgpt code",
            "code is",
            "验证码",
            "验证代码",
            "临时验证码",
            "chatgpt 代码",
            "chatgpt code",
        )
        return any(marker in sender_text or marker in content_text for marker in markers)

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        通过 admin API 创建临时邮箱

        Returns:
            包含邮箱信息的字典:
            - email: 邮箱地址
            - jwt: 用户级 JWT token
            - service_id: 同 email（用作标识）
        """
        import random
        import string

        # 生成随机邮箱名
        letters = ''.join(random.choices(string.ascii_lowercase, k=5))
        digits = ''.join(random.choices(string.digits, k=random.randint(1, 3)))
        suffix = ''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
        name = letters + digits + suffix

        request_config = {**self.config, **(config or {})}
        domains = self._resolve_domains(request_config) or self._domains
        domain = pick_domain(
            domains,
            strategy=request_config.get("domain_strategy"),
            rr_key=self._build_domain_rr_key(domains),
        )
        enable_prefix = bool(request_config.get("enable_prefix", True))

        body = {
            "enablePrefix": enable_prefix,
            "name": name,
            "domain": domain,
        }

        try:
            response = self._make_request("POST", "/admin/new_address", json=body)

            address = response.get("address", "").strip()
            jwt = response.get("jwt", "").strip()

            if not address:
                raise EmailServiceError(f"API 返回数据不完整: {response}")

            email_info = {
                "email": address,
                "jwt": jwt,
                "service_id": address,
                "id": address,
                "created_at": time.time(),
            }

            # 缓存 jwt，供获取验证码时使用
            self._email_cache[address] = email_info

            logger.info(f"成功创建 TempMail 邮箱: {address}")
            self.update_status(True)
            return email_info

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"创建邮箱失败: {e}")

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
        exclude_codes: Optional[List[str]] = None,
    ) -> Optional[str]:
        """
        从 TempMail 邮箱获取验证码

        Args:
            email: 邮箱地址
            email_id: 未使用，保留接口兼容
            timeout: 超时时间（秒）
            pattern: 验证码正则
            otp_sent_at: OTP 发送时间戳（暂未使用）
            exclude_codes: 需要跳过的历史验证码（可选）

        Returns:
            验证码字符串，超时返回 None
        """
        logger.info(f"正在从 TempMail 邮箱 {email} 获取验证码...")

        start_time = time.time()
        seen_mail_ids: set = set()
        excluded = {
            str(code).strip()
            for code in (exclude_codes or [])
            if str(code or "").strip()
        }
        last_code = self._last_code_cache.get(email, "")
        if last_code:
            excluded.add(last_code)
        last_message_id = self._last_message_id_cache.get(email, "")

        # 优先使用地址级 JWT（/api/mails），回退到 admin API
        cached = self._email_cache.get(email, {})
        jwt = cached.get("jwt")

        while time.time() - start_time < timeout:
            try:
                if jwt:
                    response = self._make_request(
                        "GET",
                        "/api/mails",
                        params={"limit": 20, "offset": 0},
                        headers=self._user_headers(jwt),
                    )
                else:
                    response = self._make_request(
                        "GET",
                        "/admin/mails",
                        params={"limit": 20, "offset": 0, "address": email},
                    )

                # /user_api/mails 和 /admin/mails 返回格式相同: {"results": [...], "total": N}
                mails = response.get("results", [])
                if not isinstance(mails, list):
                    time.sleep(3)
                    continue

                for mail in mails:
                    mail_id = self._extract_mail_id(mail)
                    if mail_id and mail_id in seen_mail_ids:
                        continue
                    if mail_id:
                        seen_mail_ids.add(mail_id)
                    if mail_id and last_message_id and mail_id == last_message_id:
                        continue

                    parsed = self._extract_mail_fields(mail)
                    sender = parsed["sender"].lower()
                    subject = parsed["subject"]
                    body_text = parsed["body"]
                    raw_text = parsed["raw"]
                    content = f"{sender}\n{subject}\n{body_text}\n{raw_text}".strip()
                    safe_content = self._strip_email_addresses(content)

                    # 仅处理 OpenAI/ChatGPT 验证相关邮件
                    if not self._is_openai_verification_mail(sender, content):
                        continue

                    match = re.search(pattern, safe_content)
                    if match:
                        code = match.group(1)
                        if code in excluded:
                            continue
                        self._last_code_cache[email] = code
                        if mail_id:
                            self._last_message_id_cache[email] = mail_id
                        logger.info(f"从 TempMail 邮箱 {email} 找到验证码: {code}")
                        self.update_status(True)
                        return code

            except Exception as e:
                logger.debug(f"检查 TempMail 邮件时出错: {e}")
                if jwt:
                    # 地址 JWT 可能失效，回退到 admin API
                    jwt = None

            time.sleep(3)

        logger.warning(f"等待 TempMail 验证码超时: {email}")
        return None

    def list_emails(self, limit: int = 100, offset: int = 0, **kwargs) -> List[Dict[str, Any]]:
        """
        列出邮箱

        Args:
            limit: 返回数量上限
            offset: 分页偏移
            **kwargs: 额外查询参数，透传给 admin API

        Returns:
            邮箱列表
        """
        params = {
            "limit": limit,
            "offset": offset,
        }
        params.update({k: v for k, v in kwargs.items() if v is not None})

        try:
            response = self._make_request("GET", "/admin/mails", params=params)
            mails = response.get("results", [])
            if not isinstance(mails, list):
                raise EmailServiceError(f"API 返回数据格式错误: {response}")

            emails: List[Dict[str, Any]] = []
            for mail in mails:
                address = (mail.get("address") or "").strip()
                mail_id = mail.get("id") or address
                email_info = {
                    "id": mail_id,
                    "service_id": mail_id,
                    "email": address,
                    "subject": mail.get("subject"),
                    "from": mail.get("source"),
                    "created_at": mail.get("createdAt") or mail.get("created_at"),
                    "raw_data": mail,
                }
                emails.append(email_info)

                if address:
                    cached = self._email_cache.get(address, {})
                    self._email_cache[address] = {**cached, **email_info}

            self.update_status(True)
            return emails
        except Exception as e:
            logger.warning(f"列出 TempMail 邮箱失败: {e}")
            self.update_status(False, e)
            return list(self._email_cache.values())

    def delete_email(self, email_id: str) -> bool:
        """
        删除邮箱

        Note:
            当前 TempMail admin API 文档未见删除地址接口，这里先从本地缓存移除，
            以满足统一接口并避免服务实例化失败。
        """
        removed = False
        emails_to_delete = []

        for address, info in self._email_cache.items():
            candidate_ids = {
                address,
                info.get("id"),
                info.get("service_id"),
            }
            if email_id in candidate_ids:
                emails_to_delete.append(address)

        for address in emails_to_delete:
            self._email_cache.pop(address, None)
            self._last_code_cache.pop(address, None)
            self._last_message_id_cache.pop(address, None)
            removed = True

        if removed:
            logger.info(f"已从 TempMail 缓存移除邮箱: {email_id}")
            self.update_status(True)
        else:
            logger.info(f"TempMail 缓存中未找到邮箱: {email_id}")

        return removed

    def check_health(self) -> bool:
        """检查服务健康状态"""
        try:
            self._make_request(
                "GET",
                "/admin/mails",
                params={"limit": 1, "offset": 0},
            )
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"TempMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False
