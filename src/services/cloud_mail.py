"""
CloudMail 邮箱服务实现
"""

import logging
import os
import re
import secrets
import time
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..core.http_client import HTTPClient, RequestConfig
from ..config.constants import OTP_CODE_PATTERN


logger = logging.getLogger(__name__)


class CloudMailService(BaseEmailService):
    """
    CloudMail 邮箱服务
    基于 CloudMail 的公开 API 轮询验证码
    """

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.CLOUD_MAIL, name)

        default_config = {
            "base_url": "",
            "api_token": "",
            "default_domain": "",
            "timeout": 30,
            "max_retries": 3,
            "poll_interval": 3,
            "time_tolerance": 43200,
            "otp_sent_time_skew_seconds": 12,
            "prefix": "oc",
            "token_bytes": 3,
            "page_size": 20,
            "auth_header": "Authorization",
            "auth_prefix": "",
            "proxy_url": None,
        }

        self.config = {**default_config, **(config or {})}
        self.config["base_url"] = str(self.config.get("base_url") or "").rstrip("/")

        missing_keys = []
        if not self.config.get("base_url"):
            missing_keys.append("base_url")
        if not (self.config.get("api_token") or self.config.get("token")):
            missing_keys.append("api_token")

        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        if not self._resolve_domain(self.config):
            raise ValueError("缺少邮箱域名")

        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(
            proxy_url=self.config.get("proxy_url"),
            config=http_config,
        )

        self._email_cache: Dict[str, Dict[str, Any]] = {}
        self._last_code_cache: Dict[str, str] = {}
        self._last_message_id_cache: Dict[str, str] = {}
        self._verbose_content_logging = (
            self._is_truthy(self.config.get("verbose_content"))
            or self._is_truthy(os.environ.get("CLOUD_MAIL_VERBOSE_CONTENT"))
        )
        quiet_raw = self.config.get("quiet_warnings")
        if quiet_raw is None:
            quiet_raw = os.environ.get("CLOUD_MAIL_QUIET", "1")
        self._quiet_warnings = self._is_truthy(quiet_raw)
        if self._verbose_content_logging:
            self._quiet_warnings = False

    @staticmethod
    def _is_truthy(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _short_text(value: Any, limit: int = 220) -> str:
        text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
        if len(text) <= limit:
            return text
        return text[: max(20, limit)] + "..."

    def _resolve_domain(self, config: Dict[str, Any]) -> str:
        domain = (
            config.get("default_domain")
            or config.get("domain")
            or ""
        )
        return str(domain).strip().lstrip("@")

    def _sanitize_local_part(self, local_part: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "", local_part or "")
        return safe.lower().strip(".")

    def _generate_local_part(self, config: Dict[str, Any]) -> str:
        prefix = self._sanitize_local_part(str(config.get("prefix") or "oc"))
        token_bytes = int(config.get("token_bytes") or 3)
        token_bytes = max(1, min(token_bytes, 16))
        stamp = int(time.time())
        rand = secrets.token_hex(token_bytes)
        return f"{prefix}{stamp}{rand}" if prefix else f"cm{stamp}{rand}"

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        token = self.config.get("api_token") or self.config.get("token")
        if token:
            header_name = str(self.config.get("auth_header") or "Authorization")
            prefix = str(self.config.get("auth_prefix") or "")
            headers[header_name] = f"{prefix}{token}" if prefix else str(token)
        return headers

    def _extract_message_timestamp(self, message: Dict[str, Any]) -> Optional[float]:
        candidates = [
            "createTime", "create_time",
            "createdAt", "created_at",
            "time", "timestamp",
        ]
        for key in candidates:
            if key not in message:
                continue
            value = message.get(key)
            ts = self._parse_timestamp(value)
            if ts:
                return ts
        nested = message.get("data")
        if isinstance(nested, dict):
            for key in candidates:
                if key not in nested:
                    continue
                ts = self._parse_timestamp(nested.get(key))
                if ts:
                    return ts
        return None

    def _parse_timestamp(self, value: Any) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            ts = float(value)
        else:
            text = str(value).strip()
            if not text:
                return None
            if text.isdigit():
                ts = float(text)
            else:
                try:
                    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        # CloudMail 的 createTime 常见为无时区字符串，按 UTC 解释避免错判旧邮件
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.timestamp()
                except Exception:
                    return None
        if ts > 10_000_000_000:
            ts = ts / 1000.0
        return ts

    def _extract_messages(self, payload: Any) -> List[Dict[str, Any]]:
        """从 API 响应中提取邮件列表，兼容多种字段结构。"""
        if payload is None:
            return []

        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if not isinstance(payload, dict):
            return []

        # 常见结构：{ "data": [...] } 或 { "data": { "list": [...] } }
        data = payload.get("data", payload)

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]

        if isinstance(data, dict):
            for key in ("list", "records", "rows", "items", "emails", "messages", "result", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            # 可能直接返回单条邮件对象
            if any(k in data for k in ("subject", "text", "content", "html", "body")):
                return [data]

        return []

    def _extract_message_text(self, message: Dict[str, Any]) -> str:
        """提取邮件正文文本，兼容不同字段名。"""
        parts: List[str] = []

        def _strip_html(text: str) -> str:
            return re.sub(r"<[^>]+>", " ", text)

        def _append(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, list):
                merged = " ".join(str(item) for item in value if item)
                if merged:
                    parts.append(_strip_html(merged) if ("<" in merged and ">" in merged) else merged)
            else:
                text = str(value).strip()
                if text:
                    parts.append(_strip_html(text) if ("<" in text and ">" in text) else text)

        direct_text_keys = (
            "subject", "title", "mailSubject", "mailTitle",
            "text", "content", "html", "body",
            "textContent", "contentText", "mailText", "mailContent",
            "bodyText", "text_body", "mail_body", "mailBody",
            "preview", "snippet", "summary", "intro", "mailPreview",
            "contentHtml", "htmlContent", "source", "raw",
        )
        for key in direct_text_keys:
            value = message.get(key)
            if isinstance(value, dict):
                for nested_key in direct_text_keys:
                    _append(value.get(nested_key))
            else:
                _append(value)

        # 兼容嵌套结构
        for nested_key in ("data", "mail", "email", "detail", "message", "payload", "item", "record"):
            nested = message.get(nested_key)
            if isinstance(nested, dict):
                for key in direct_text_keys:
                    _append(nested.get(key))

        return " ".join(parts).strip()

    def _extract_message_id(self, message: Dict[str, Any]) -> str:
        """提取邮件唯一标识，避免重复消费旧邮件。"""
        id_candidates = ("emailId", "id", "mailId", "messageId", "msgId")
        for key in id_candidates:
            value = message.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
        nested = message.get("data")
        if isinstance(nested, dict):
            for key in id_candidates:
                value = nested.get(key)
                if value is not None and str(value).strip():
                    return str(value).strip()
        return ""

    def _extract_code_from_text(self, text: str, pattern: str) -> Optional[str]:
        """从文本中提取验证码，优先语义匹配。"""
        if not text:
            return None
        lowered = text.lower()
        semantic_patterns = (
            r"(?is)(?:verification\s+code|temporary verification code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code|验证码|校验码|动态码|認證碼|驗證碼|代码|code)[^0-9]{0,30}(\d{6})",
            r"(?is)\bcode\b[^0-9]{0,12}(\d{6})",
        )
        for regex in semantic_patterns:
            match = re.search(regex, text, re.I)
            if match:
                return match.group(1) if match.groups() else match.group(0)

        # 对大段 JSON 文本做兜底时，避免误命中随机 6 位数字
        context_hint = (
            "openai" in lowered
            or "chatgpt" in lowered
            or "verification" in lowered
            or "验证码" in text
            or "校验码" in text
            or "代码" in text
        )
        match = re.search(pattern, text)
        if not match:
            return None
        code = match.group(1) if match.groups() else match.group(0)
        if len(text) <= 1200 or context_hint:
            return code
        return None

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """生成 CloudMail 邮箱地址（无需远端创建）。"""
        try:
            request_config = {**self.config, **(config or {})}
            domain = self._resolve_domain(request_config)
            if not domain:
                raise EmailServiceError("CloudMail 缺少邮箱域名")

            local_part = (
                request_config.get("local_part")
                or request_config.get("name")
                or self._generate_local_part(request_config)
            )
            local_part = self._sanitize_local_part(str(local_part))
            if not local_part:
                local_part = self._generate_local_part(request_config)

            email = f"{local_part}@{domain}"
            email_info = {
                "email": email,
                "service_id": email,
                "created_at": time.time(),
                "domain": domain,
            }
            self._email_cache[email] = email_info

            logger.info(f"成功生成 CloudMail 邮箱: {email}")
            self.update_status(True)
            return email_info

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"生成 CloudMail 邮箱失败: {e}")

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
        exclude_codes: Optional[List[str]] = None,
    ) -> Optional[str]:
        """轮询 CloudMail API 获取验证码。"""
        if not email:
            return None

        url = f"{self.config['base_url']}/api/public/emailList"
        headers = self._build_headers()
        payload = {
            "toEmail": email,
            "timeSort": "desc",
            "num": 1,
            "size": int(self.config.get("page_size") or 5),
        }

        start_time = time.time()
        poll_interval = max(1, int(self.config.get("poll_interval") or 3))
        excluded = {
            str(code).strip()
            for code in (exclude_codes or [])
            if str(code or "").strip()
        }
        strict_time_filter = bool(excluded)
        time_filter_relaxed = False
        # 每次取码调用都重置一次调试开关，避免多任务时后续调用失去诊断日志
        self._debug_dumped = False
        self._debug_no_code_dumped = False
        self._debug_time_filter_dumped = False
        saw_messages = False
        last_payload_snippet = ""
        non_200_count = 0
        last_non_200_status = 0

        while time.time() - start_time < timeout:
            try:
                response = self.http_client.post(url, headers=headers, json=payload)
                if response.status_code != 200:
                    non_200_count += 1
                    last_non_200_status = int(response.status_code)
                    if non_200_count == 1 or non_200_count % 10 == 0:
                        logger.warning(
                            "CloudMail emailList 响应非 200: status=%s, body=%s",
                            response.status_code,
                            self._short_text(response.text, 220),
                        )
                    time.sleep(poll_interval)
                    continue

                data = response.json()
                if self._verbose_content_logging:
                    try:
                        last_payload_snippet = json.dumps(data, ensure_ascii=False)[:500]
                    except Exception:
                        last_payload_snippet = str(data)[:500]
                messages = self._extract_messages(data)
                if not messages:
                    if not getattr(self, "_debug_dumped", False):
                        if self._quiet_warnings:
                            logger.debug("CloudMail 未解析到邮件列表（quiet 模式已静默）")
                        elif self._verbose_content_logging:
                            try:
                                snippet = json.dumps(data, ensure_ascii=False)[:500]
                            except Exception:
                                snippet = str(data)[:500]
                            logger.warning(f"CloudMail 未解析到邮件列表，响应片段: {snippet}")
                        else:
                            logger.warning("CloudMail 未解析到邮件列表（已隐藏响应片段）")
                        self._debug_dumped = True
                    time.sleep(poll_interval)
                    continue

                saw_messages = True
                found_code = None
                last_message_id = self._last_message_id_cache.get(email, "")
                last_code = self._last_code_cache.get(email, "")
                skew_seconds = int(self.config.get("otp_sent_time_skew_seconds") or 12)
                skew_seconds = max(0, min(skew_seconds, 60))
                cutoff_ts = (otp_sent_at - skew_seconds) if otp_sent_at else None
                if cutoff_ts is not None and not time_filter_relaxed:
                    # 在云端环境中，CloudMail 服务器时间与运行节点可能存在时钟偏差；
                    # 若较长时间未命中验证码，则放宽时间窗，避免误判超时。
                    relax_after = max(20.0, min(float(timeout) * 0.4, 45.0))
                    if (time.time() - start_time) >= relax_after:
                        time_filter_relaxed = True
                        logger.warning("CloudMail 长时间未命中验证码，已放宽时间窗口过滤")

                effective_cutoff_ts = None if time_filter_relaxed else cutoff_ts
                candidates: List[Dict[str, Any]] = []
                skipped_by_time = 0
                for message in messages:
                    if not isinstance(message, dict):
                        continue
                    msg_id = self._extract_message_id(message)
                    msg_time = self._extract_message_timestamp(message)
                    # 仅在“二次验证码排重阶段”启用严格时间窗，首轮验证码不做硬过滤，
                    # 避免云端与邮箱服务时钟偏差导致把第一封验证码误判为旧邮件。
                    if (
                        strict_time_filter
                        and effective_cutoff_ts is not None
                        and msg_time is not None
                        and msg_time < effective_cutoff_ts
                    ):
                        skipped_by_time += 1
                        continue

                    content = self._extract_message_text(message)
                    code = self._extract_code_from_text(content, pattern)
                    if not code:
                        # 兜底：无论正文是否为空，都在原始消息 JSON 中做一次提码，兼容异构字段名
                        raw_blob = json.dumps(message, ensure_ascii=False)
                        code = self._extract_code_from_text(raw_blob, pattern)

                    if code:
                        if code in excluded:
                            continue
                        candidates.append(
                            {
                                "code": code,
                                "msg_id": msg_id,
                                "msg_time": float(msg_time) if msg_time is not None else float("-inf"),
                            }
                        )

                if candidates:
                    candidates.sort(key=lambda item: item["msg_time"], reverse=True)
                    for candidate in candidates:
                        code = str(candidate.get("code") or "")
                        msg_id = str(candidate.get("msg_id") or "")
                        if msg_id and last_message_id and msg_id == last_message_id:
                            # 兼容部分平台复用同一个 message_id 但更新验证码内容
                            if last_code and code == last_code:
                                continue
                        if not msg_id and last_code and code == last_code:
                            continue
                        self._last_code_cache[email] = code
                        if msg_id:
                            self._last_message_id_cache[email] = msg_id
                        logger.info(f"CloudMail 获取验证码成功: {code}")
                        self.update_status(True)
                        found_code = code
                        break

                if found_code:
                    return found_code

                if skipped_by_time > 0 and strict_time_filter and not getattr(self, "_debug_time_filter_dumped", False):
                    logger.warning(
                        "CloudMail 时间窗过滤跳过 %s 封邮件（strict=%s, relaxed=%s）",
                        skipped_by_time,
                        strict_time_filter,
                        time_filter_relaxed,
                    )
                    self._debug_time_filter_dumped = True

                if messages and not getattr(self, "_debug_no_code_dumped", False):
                    if self._quiet_warnings:
                        logger.debug("CloudMail 已获取邮件但未匹配验证码（quiet 模式已静默）")
                    elif self._verbose_content_logging:
                        sample = messages[0] if isinstance(messages[0], dict) else {}
                        try:
                            snippet = json.dumps(sample, ensure_ascii=False)[:400]
                        except Exception:
                            snippet = str(sample)[:400]
                        key_hint = ", ".join(sorted(sample.keys())[:20]) if isinstance(sample, dict) else "-"
                        logger.warning(
                            f"CloudMail 已获取邮件但未匹配验证码，示例字段: {key_hint}，示例片段: {snippet}"
                        )
                    else:
                        logger.warning("CloudMail 已获取邮件但未匹配验证码（已隐藏示例片段）")
                    self._debug_no_code_dumped = True

            except Exception as e:
                logger.debug(f"CloudMail 轮询失败: {e}")

            time.sleep(poll_interval)

        if self._quiet_warnings:
            logger.warning(f"CloudMail 等待验证码超时: {email}")
        else:
            logger.warning(
                "CloudMail 等待验证码超时: %s (saw_messages=%s, excluded_count=%s, time_filter_relaxed=%s, non_200_count=%s, last_non_200=%s, payload=%s)",
                email,
                saw_messages,
                len(excluded),
                time_filter_relaxed,
                non_200_count,
                last_non_200_status or "-",
                (last_payload_snippet or "-"),
            )
        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        """返回缓存邮箱列表。"""
        return list(self._email_cache.values())

    def delete_email(self, email_id: str) -> bool:
        """CloudMail 不支持删除邮箱，这里仅清理缓存。"""
        if not email_id:
            return False
        keys_to_remove = [
            email for email, info in self._email_cache.items()
            if info.get("service_id") == email_id or email == email_id
        ]
        for key in keys_to_remove:
            self._email_cache.pop(key, None)
        return bool(keys_to_remove)

    def check_health(self) -> bool:
        """检查 CloudMail 服务可用性。"""
        try:
            domain = self._resolve_domain(self.config)
            test_email = f"healthcheck@{domain}" if domain else "healthcheck@example.com"
            url = f"{self.config['base_url']}/api/public/emailList"
            payload = {
                "toEmail": test_email,
                "timeSort": "desc",
                "num": 1,
                "size": 1,
            }
            response = self.http_client.post(url, headers=self._build_headers(), json=payload)
            if response.status_code >= 500:
                self.update_status(False, EmailServiceError(f"状态码: {response.status_code}"))
                return False
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"CloudMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False
