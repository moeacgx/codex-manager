"""待 OAuth 授权队列处理。"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import or_

from ..config.constants import EmailServiceType
from ..config.settings import get_settings
from ..database import crud
from ..database.models import Account, OAuthPendingAccount
from ..database.session import get_db
from ..services import EmailServiceFactory
from .register import RegistrationEngine, RegistrationResult
from .upload.cpa_upload import (
    generate_token_json,
    upload_to_cpa,
    validate_codex_account_for_upload,
)

logger = logging.getLogger(__name__)


OAUTH_PENDING_STATUS_PENDING = "pending"
OAUTH_PENDING_STATUS_RUNNING = "running"
OAUTH_PENDING_STATUS_SUCCESS = "success"
OAUTH_PENDING_STATUS_FAILED = "failed"
OAUTH_PENDING_STATUS_RATE_LIMITED = "rate_limited"
OAUTH_PENDING_STATUSES = {
    OAUTH_PENDING_STATUS_PENDING,
    OAUTH_PENDING_STATUS_RUNNING,
    OAUTH_PENDING_STATUS_SUCCESS,
    OAUTH_PENDING_STATUS_FAILED,
    OAUTH_PENDING_STATUS_RATE_LIMITED,
}


def _recover_stale_running_records(
    *,
    max_attempts: int,
    logs: Optional[List[str]] = None,
) -> int:
    """回收卡在 running 状态过久的记录，避免队列永久阻塞。"""
    settings = get_settings()
    try:
        stale_seconds = max(120, int(settings.oauth_pending_poll_interval_seconds or 60) * 3)
    except Exception:
        stale_seconds = 180

    now = datetime.utcnow()
    stale_before = now - timedelta(seconds=stale_seconds)
    recovered = 0

    with get_db() as db:
        stale_items = (
            db.query(OAuthPendingAccount)
            .filter(
                OAuthPendingAccount.status == OAUTH_PENDING_STATUS_RUNNING,
                or_(
                    OAuthPendingAccount.locked_at.is_(None),
                    OAuthPendingAccount.locked_at <= stale_before,
                ),
            )
            .all()
        )

        for pending in stale_items:
            account = crud.get_account_by_id(db, pending.account_id)
            attempt_count = int(pending.attempt_count or 0)
            last_error = str(pending.last_error or "").strip()

            if attempt_count >= max_attempts:
                pending.status = OAUTH_PENDING_STATUS_FAILED
                pending.locked_at = None
                pending.next_retry_at = None
                pending.last_error = last_error or "授权重试超限，running 回收失败"
                if account:
                    account.status = "failed"
                    account.extra_data = _merge_metadata_for_pending(
                        account.extra_data,
                        {},
                        pending_status=OAUTH_PENDING_STATUS_FAILED,
                        pending_error=pending.last_error,
                    )
            else:
                fallback_status = (
                    OAUTH_PENDING_STATUS_RATE_LIMITED
                    if _is_rate_limited_error(last_error)
                    else OAUTH_PENDING_STATUS_PENDING
                )
                pending.status = fallback_status
                pending.locked_at = None
                if pending.next_retry_at and pending.next_retry_at > now:
                    pass
                else:
                    pending.next_retry_at = now

                if account:
                    account.status = "pending_oauth"
                    account.extra_data = _merge_metadata_for_pending(
                        account.extra_data,
                        {},
                        pending_status=fallback_status,
                        pending_error=last_error,
                    )

            recovered += 1

        if recovered > 0:
            db.commit()

    if recovered > 0:
        _safe_log(logs, f"检测到并回收 {recovered} 条卡住的 running 队列记录", level="warning")
    return recovered


def _normalize_email_service_config(
    service_type: EmailServiceType,
    config: Optional[dict],
    proxy_url: Optional[str] = None,
) -> dict:
    """按服务类型兼容旧字段名，避免不同服务配置键互相污染。"""
    normalized = config.copy() if config else {}

    if "api_url" in normalized and "base_url" not in normalized:
        normalized["base_url"] = normalized.pop("api_url")
    if "domain_select_strategy" in normalized and "domain_strategy" not in normalized:
        normalized["domain_strategy"] = normalized.pop("domain_select_strategy")

    if service_type == EmailServiceType.CUSTOM_DOMAIN:
        if "domain" in normalized and "default_domain" not in normalized:
            normalized["default_domain"] = normalized.pop("domain")
        strategy = str(normalized.get("domain_strategy") or "").strip().lower()
        normalized["domain_strategy"] = strategy if strategy in ("round_robin", "random") else "round_robin"
    elif service_type == EmailServiceType.TEMP_MAIL:
        if "default_domain" in normalized and "domain" not in normalized:
            normalized["domain"] = normalized.pop("default_domain")
        strategy = str(normalized.get("domain_strategy") or "").strip().lower()
        normalized["domain_strategy"] = strategy if strategy in ("round_robin", "random") else "round_robin"
    elif service_type == EmailServiceType.DUCK_MAIL:
        if "domain" in normalized and "default_domain" not in normalized:
            normalized["default_domain"] = normalized.pop("domain")
        strategy = str(normalized.get("domain_strategy") or "").strip().lower()
        normalized["domain_strategy"] = strategy if strategy in ("round_robin", "random") else "round_robin"
    elif service_type == EmailServiceType.CLOUD_MAIL:
        if "domain" in normalized and "default_domain" not in normalized:
            normalized["default_domain"] = normalized.pop("domain")
        if "token" in normalized and "api_token" not in normalized:
            normalized["api_token"] = normalized.pop("token")
        strategy = str(normalized.get("domain_strategy") or "").strip().lower()
        normalized["domain_strategy"] = strategy if strategy in ("round_robin", "random") else "round_robin"

    if proxy_url and "proxy_url" not in normalized:
        normalized["proxy_url"] = proxy_url

    return normalized


def _safe_log(logs: Optional[List[str]], message: str, *, level: str = "info") -> None:
    if logs is not None:
        logs.append(f"[{level.upper()}] {message}")

    log_fn = getattr(logger, level, logger.info)
    log_fn(message)


def _is_rate_limited_error(text: str) -> bool:
    lower = str(text or "").lower()
    if not lower:
        return False
    return "429" in lower or "rate limit" in lower or "too many requests" in lower


def _compute_retry_seconds(attempt_count: int) -> int:
    settings = get_settings()
    try:
        base_seconds = max(5, int(settings.oauth_pending_retry_base_seconds or 60))
    except Exception:
        base_seconds = 60
    try:
        max_seconds = max(base_seconds, int(settings.oauth_pending_retry_max_seconds or 1800))
    except Exception:
        max_seconds = 1800
    return min(max_seconds, base_seconds * max(1, int(attempt_count or 1)))


def _merge_metadata_for_pending(
    original: Optional[Dict[str, Any]],
    updates: Optional[Dict[str, Any]],
    *,
    pending_status: str,
    pending_error: str = "",
) -> Dict[str, Any]:
    merged: Dict[str, Any] = dict(original or {})
    merged.update(dict(updates or {}))
    merged["oauth_pending"] = True
    merged["oauth_pending_status"] = pending_status
    merged["oauth_pending_updated_at"] = datetime.utcnow().isoformat()
    if pending_error:
        merged["oauth_pending_last_error"] = pending_error
    return merged


def _build_email_service_for_account(account: Account):
    settings = get_settings()
    service_raw = str(account.email_service or "").strip().lower()
    if not service_raw:
        raise ValueError("账号缺少 email_service")

    try:
        service_type = EmailServiceType(service_raw)
    except Exception as exc:
        raise ValueError(f"不支持的邮箱服务类型: {service_raw}") from exc

    proxy_url = str(account.proxy_used or "").strip() or None
    mailbox_id = str(account.email_service_id or "").strip() or None

    if service_type == EmailServiceType.TEMPMAIL:
        config = {
            "base_url": settings.tempmail_base_url,
            "timeout": settings.tempmail_timeout,
            "max_retries": settings.tempmail_max_retries,
            "proxy_url": proxy_url,
        }
        return EmailServiceFactory.create(service_type, config), mailbox_id

    if service_type == EmailServiceType.CUSTOM_DOMAIN and settings.custom_domain_base_url:
        config = {
            "base_url": settings.custom_domain_base_url,
            "api_key": settings.custom_domain_api_key.get_secret_value() if settings.custom_domain_api_key else "",
        }
        config = _normalize_email_service_config(service_type, config, proxy_url)
        return EmailServiceFactory.create(service_type, config), mailbox_id

    with get_db() as db:
        services = crud.get_email_services(
            db,
            service_type=service_type.value,
            enabled=True,
            limit=100,
        )

    if not services:
        if service_type == EmailServiceType.GENERATOR_EMAIL:
            config = _normalize_email_service_config(service_type, {}, proxy_url)
            return EmailServiceFactory.create(service_type, config), mailbox_id
        raise ValueError(f"未找到可用邮箱服务配置: {service_type.value}")

    selected = services[0]
    if service_type == EmailServiceType.OUTLOOK:
        account_email = str(account.email or "").strip().lower()
        for svc in services:
            cfg = svc.config or {}
            svc_email = str(cfg.get("email") or "").strip().lower()
            if svc_email and svc_email == account_email:
                selected = svc
                break

    config = _normalize_email_service_config(service_type, selected.config or {}, proxy_url)
    return EmailServiceFactory.create(service_type, config), mailbox_id


def upsert_pending_oauth_account_from_result(
    result: RegistrationResult,
    *,
    proxy_url: Optional[str] = None,
) -> Tuple[bool, str, Optional[int]]:
    """把 OAuth 失败但已完成注册的账号写入待授权队列。"""
    metadata = dict(result.metadata or {})
    registration_completed = bool(metadata.get("registration_completed"))
    if not registration_completed:
        return False, "注册流程未完成，跳过待授权入库", None

    email = str(result.email or "").strip()
    password = str(result.password or "").strip()
    if not email or not password:
        return False, "缺少邮箱或密码，无法进入待授权队列", None

    email_service = str(metadata.get("email_service") or "").strip().lower() or EmailServiceType.TEMPMAIL.value
    email_service_id = str(metadata.get("email_service_id") or "").strip() or None
    pending_error = str(result.error_message or "OAuth Token 获取失败").strip() or "OAuth Token 获取失败"

    settings = get_settings()
    issued_client_id = str(metadata.get("issued_client_id") or "").strip()

    with get_db() as db:
        account = crud.get_account_by_email(db, email)
        now = datetime.utcnow()

        if account is None:
            account = crud.create_account(
                db,
                email=email,
                password=password,
                client_id=issued_client_id if result.refresh_token else None,
                session_token=result.session_token,
                email_service=email_service,
                email_service_id=email_service_id,
                account_id=result.account_id,
                workspace_id=result.workspace_id,
                access_token=result.access_token or None,
                refresh_token=result.refresh_token or None,
                id_token=result.id_token or None,
                proxy_used=proxy_url,
                extra_data=_merge_metadata_for_pending(
                    {},
                    metadata,
                    pending_status=OAUTH_PENDING_STATUS_PENDING,
                    pending_error=pending_error,
                ),
                source=result.source or "register",
                status="pending_oauth",
            )
        else:
            account.password = password or account.password
            account.session_token = result.session_token or account.session_token
            account.account_id = result.account_id or account.account_id
            account.workspace_id = result.workspace_id or account.workspace_id
            account.proxy_used = proxy_url or account.proxy_used
            account.email_service = email_service or account.email_service
            account.email_service_id = email_service_id or account.email_service_id
            if result.access_token:
                account.access_token = result.access_token
            if result.refresh_token:
                account.refresh_token = result.refresh_token
            if result.id_token:
                account.id_token = result.id_token
            if result.refresh_token:
                account.client_id = issued_client_id or account.client_id or settings.openai_client_id
            account.status = "pending_oauth"
            account.source = result.source or account.source or "register"
            account.extra_data = _merge_metadata_for_pending(
                account.extra_data,
                metadata,
                pending_status=OAUTH_PENDING_STATUS_PENDING,
                pending_error=pending_error,
            )
            db.commit()
            db.refresh(account)

        pending = crud.get_oauth_pending_by_account_id(db, account.id)
        if pending is None:
            pending = crud.create_oauth_pending_account(
                db,
                account_id=account.id,
                status=OAUTH_PENDING_STATUS_PENDING,
                attempt_count=0,
                next_retry_at=now,
                last_error=pending_error,
            )
        else:
            pending.status = OAUTH_PENDING_STATUS_PENDING
            pending.attempt_count = 0
            pending.next_retry_at = now
            pending.last_error = pending_error
            pending.locked_at = None
            db.commit()
            db.refresh(pending)

        return True, "已加入待授权队列", account.id


def get_oauth_pending_overview() -> Dict[str, int]:
    """获取待 OAuth 授权队列概览。"""
    with get_db() as db:
        return {
            "total": crud.get_oauth_pending_count(db),
            "pending": crud.get_oauth_pending_count(db, status=OAUTH_PENDING_STATUS_PENDING),
            "running": crud.get_oauth_pending_count(db, status=OAUTH_PENDING_STATUS_RUNNING),
            "success": crud.get_oauth_pending_count(db, status=OAUTH_PENDING_STATUS_SUCCESS),
            "failed": crud.get_oauth_pending_count(db, status=OAUTH_PENDING_STATUS_FAILED),
            "rate_limited": crud.get_oauth_pending_count(db, status=OAUTH_PENDING_STATUS_RATE_LIMITED),
        }


def list_oauth_pending_accounts(
    *,
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    """分页查询待 OAuth 授权队列。"""
    normalized_status = str(status or "").strip().lower() or None
    if normalized_status and normalized_status not in OAUTH_PENDING_STATUSES:
        raise ValueError(f"无效的待授权状态: {normalized_status}")

    safe_page = max(1, int(page or 1))
    safe_page_size = max(1, min(200, int(page_size or 20)))
    offset = (safe_page - 1) * safe_page_size

    with get_db() as db:
        query = db.query(OAuthPendingAccount)
        if normalized_status:
            query = query.filter(OAuthPendingAccount.status == normalized_status)

        total = int(query.count() or 0)
        records = (
            query.order_by(
                OAuthPendingAccount.updated_at.desc(),
                OAuthPendingAccount.id.desc(),
            )
            .offset(offset)
            .limit(safe_page_size)
            .all()
        )

        account_ids = [int(item.account_id) for item in records if item.account_id]
        accounts_by_id: Dict[int, Account] = {}
        if account_ids:
            account_rows = db.query(Account).filter(Account.id.in_(account_ids)).all()
            accounts_by_id = {int(row.id): row for row in account_rows}

        items: List[Dict[str, Any]] = []
        for item in records:
            account = accounts_by_id.get(int(item.account_id))
            items.append(
                {
                    "id": int(item.id),
                    "account_id": int(item.account_id),
                    "pending_status": str(item.status or ""),
                    "attempt_count": int(item.attempt_count or 0),
                    "next_retry_at": item.next_retry_at.isoformat() if item.next_retry_at else None,
                    "last_error": str(item.last_error or ""),
                    "locked_at": item.locked_at.isoformat() if item.locked_at else None,
                    "created_at": item.created_at.isoformat() if item.created_at else None,
                    "updated_at": item.updated_at.isoformat() if item.updated_at else None,
                    "email": str(account.email or "") if account else "",
                    "account_status": str(account.status or "") if account else "",
                }
            )

        return {
            "page": safe_page,
            "page_size": safe_page_size,
            "total": total,
            "items": items,
        }


def _mark_pending_result(
    pending: OAuthPendingAccount,
    account: Account,
    *,
    status: str,
    error_message: str,
    retry_after_seconds: Optional[int],
) -> None:
    now = datetime.utcnow()
    pending.status = status
    pending.last_error = error_message
    pending.locked_at = None
    if retry_after_seconds is not None and retry_after_seconds > 0:
        pending.next_retry_at = now + timedelta(seconds=retry_after_seconds)
    elif status in {OAUTH_PENDING_STATUS_FAILED, OAUTH_PENDING_STATUS_SUCCESS}:
        pending.next_retry_at = None
    else:
        pending.next_retry_at = now

    if status in {OAUTH_PENDING_STATUS_PENDING, OAUTH_PENDING_STATUS_RATE_LIMITED, OAUTH_PENDING_STATUS_RUNNING}:
        account.status = "pending_oauth"
    elif status == OAUTH_PENDING_STATUS_SUCCESS:
        account.status = "active"
    elif status == OAUTH_PENDING_STATUS_FAILED:
        account.status = "failed"

    account.extra_data = _merge_metadata_for_pending(
        account.extra_data,
        {},
        pending_status=status,
        pending_error=error_message,
    )


def _auto_upload_to_cpa(account: Account, logs: Optional[List[str]]) -> Tuple[int, int]:
    settings = get_settings()
    if not settings.cpa_enabled:
        _safe_log(logs, f"账号 {account.email}：CPA 自动上传未启用，跳过")
        return 0, 0

    with get_db() as db:
        services = crud.get_cpa_services(db, enabled=True)

    if not services:
        _safe_log(logs, f"账号 {account.email}：未配置可用 CPA 服务，跳过")
        return 0, 0

    expected_client_id = str(settings.openai_client_id or "").strip()
    valid, reason = validate_codex_account_for_upload(account, expected_client_id=expected_client_id)
    if not valid:
        _safe_log(logs, f"账号 {account.email}：授权校验未通过，跳过上传 ({reason})", level="warning")
        return len(services), 0

    token_data = generate_token_json(account)
    success_count = 0

    for service in services:
        ok, message = upload_to_cpa(
            token_data,
            api_url=service.api_url,
            api_token=service.api_token,
        )
        if ok:
            success_count += 1
            _safe_log(logs, f"账号 {account.email}：上传 CPA 成功 ({service.name})")
        else:
            _safe_log(logs, f"账号 {account.email}：上传 CPA 失败 ({service.name}): {message}", level="warning")

    return len(services), success_count


def process_pending_oauth_once(
    *,
    logs: Optional[List[str]] = None,
    limit: Optional[int] = None,
) -> Dict[str, int]:
    """执行一轮待 OAuth 队列处理。"""
    settings = get_settings()
    recovered_running = 0
    if not settings.oauth_pending_enabled:
        _safe_log(logs, "待授权队列未启用，跳过本轮处理")
        return {
            "picked": 0,
            "success": 0,
            "failed": 0,
            "rate_limited": 0,
            "requeued": 0,
            "uploaded": 0,
            "recovered_running": recovered_running,
        }

    try:
        max_attempts = max(1, int(settings.oauth_pending_max_attempts or 8))
    except Exception:
        max_attempts = 8
    recovered_running = _recover_stale_running_records(
        max_attempts=max_attempts,
        logs=logs,
    )

    worker_limit = limit
    if worker_limit is None:
        worker_limit = max(1, int(settings.global_concurrency or 1))
    worker_limit = max(1, min(50, int(worker_limit)))

    with get_db() as db:
        due_items = crud.get_due_oauth_pending_accounts(
            db,
            due_before=datetime.utcnow(),
            statuses=[OAUTH_PENDING_STATUS_PENDING, OAUTH_PENDING_STATUS_RATE_LIMITED],
            limit=worker_limit,
        )
        pending_ids = [item.id for item in due_items]

    summary = {
        "picked": len(pending_ids),
        "success": 0,
        "failed": 0,
        "rate_limited": 0,
        "requeued": 0,
        "uploaded": 0,
        "recovered_running": recovered_running,
    }

    if not pending_ids:
        return summary

    for pending_id in pending_ids:
        with get_db() as db:
            pending = crud.get_oauth_pending_by_id(db, pending_id)
            if not pending:
                continue

            if pending.status not in {OAUTH_PENDING_STATUS_PENDING, OAUTH_PENDING_STATUS_RATE_LIMITED}:
                continue

            if pending.next_retry_at and pending.next_retry_at > datetime.utcnow():
                continue

            account = crud.get_account_by_id(db, pending.account_id)
            if not account:
                pending.status = OAUTH_PENDING_STATUS_FAILED
                pending.last_error = "账号不存在"
                pending.next_retry_at = None
                pending.locked_at = None
                db.commit()
                summary["failed"] += 1
                continue

            attempt_count = int(pending.attempt_count or 0) + 1
            pending.attempt_count = attempt_count
            pending.status = OAUTH_PENDING_STATUS_RUNNING
            pending.locked_at = datetime.utcnow()
            db.commit()

        with get_db() as db:
            pending = crud.get_oauth_pending_by_id(db, pending_id)
            if not pending:
                continue
            account = crud.get_account_by_id(db, pending.account_id)
            if not account:
                pending.status = OAUTH_PENDING_STATUS_FAILED
                pending.last_error = "账号不存在"
                pending.next_retry_at = None
                pending.locked_at = None
                db.commit()
                summary["failed"] += 1
                continue

            if not str(account.password or "").strip():
                _mark_pending_result(
                    pending,
                    account,
                    status=OAUTH_PENDING_STATUS_FAILED,
                    error_message="缺少账号密码，无法执行 OAuth 登录",
                    retry_after_seconds=None,
                )
                db.commit()
                summary["failed"] += 1
                continue

            try:
                email_service, mailbox_id = _build_email_service_for_account(account)
            except Exception as exc:
                if pending.attempt_count >= max_attempts:
                    _mark_pending_result(
                        pending,
                        account,
                        status=OAUTH_PENDING_STATUS_FAILED,
                        error_message=f"邮箱服务初始化失败: {exc}",
                        retry_after_seconds=None,
                    )
                    summary["failed"] += 1
                else:
                    retry_seconds = _compute_retry_seconds(pending.attempt_count)
                    _mark_pending_result(
                        pending,
                        account,
                        status=OAUTH_PENDING_STATUS_PENDING,
                        error_message=f"邮箱服务初始化失败: {exc}",
                        retry_after_seconds=retry_seconds,
                    )
                    summary["requeued"] += 1
                db.commit()
                continue

            engine = RegistrationEngine(
                email_service=email_service,
                proxy_url=account.proxy_used,
                token_mode="oauth",
            )
            legacy_removed_msg = str(getattr(engine, "LEGACY_REMOVED_MESSAGE", "") or "").strip()
            if legacy_removed_msg:
                _mark_pending_result(
                    pending,
                    account,
                    status=OAUTH_PENDING_STATUS_FAILED,
                    error_message=(
                        "旧 OAuth 待授权队列流程已移除：当前仅支持 Playwright 浏览器通道。"
                        "请重新走浏览器注册流程。"
                    ),
                    retry_after_seconds=None,
                )
                db.commit()
                summary["failed"] += 1
                _safe_log(logs, f"账号 {account.email} 跳过待授权队列：{legacy_removed_msg}", level="warning")
                continue

            engine.email = account.email
            engine.password = account.password
            if mailbox_id:
                engine.email_info = {"service_id": mailbox_id}
            if account.session_token:
                try:
                    engine.session.cookies.set(
                        "__Secure-next-auth.session-token",
                        account.session_token,
                        domain="chatgpt.com",
                    )
                    engine.session.cookies.set(
                        "__Secure-next-auth.session-token",
                        account.session_token,
                        domain=".chatgpt.com",
                    )
                except Exception:
                    pass

            tokens = engine.get_oauth_tokens()
            if tokens and tokens.get("access_token") and tokens.get("refresh_token"):
                issued_client_id = str(tokens.get("issued_client_id") or settings.openai_client_id or "").strip()
                token_audience = tokens.get("token_audience")
                if not isinstance(token_audience, list):
                    token_audience = [str(token_audience)] if token_audience else []
                token_scope = str(tokens.get("token_scope") or "").strip()

                merged_meta = _merge_metadata_for_pending(
                    account.extra_data,
                    {
                        "token_mode": "oauth",
                        "token_source": "oauth",
                        "auth_profile": "codex_oauth",
                        "issued_client_id": issued_client_id,
                        "token_audience": token_audience,
                        "token_scope": token_scope,
                        "oauth_pending": False,
                        "oauth_authorized_at": datetime.utcnow().isoformat(),
                    },
                    pending_status=OAUTH_PENDING_STATUS_SUCCESS,
                    pending_error="",
                )
                merged_meta["oauth_pending"] = False
                merged_meta.pop("oauth_pending_last_error", None)

                account.access_token = tokens.get("access_token") or account.access_token
                account.refresh_token = tokens.get("refresh_token") or account.refresh_token
                account.id_token = tokens.get("id_token") or account.id_token
                account.account_id = tokens.get("account_id") or account.account_id
                if tokens.get("workspace_id"):
                    account.workspace_id = tokens.get("workspace_id")
                account.client_id = issued_client_id or account.client_id
                account.session_token = engine._oauth_session_token or engine._get_session_cookie() or account.session_token
                account.status = "active"
                account.extra_data = merged_meta

                pending.status = OAUTH_PENDING_STATUS_SUCCESS
                pending.last_error = ""
                pending.next_retry_at = None
                pending.locked_at = None

                total_upload, success_upload = _auto_upload_to_cpa(account, logs)
                if success_upload > 0:
                    account.cpa_uploaded = True
                    account.cpa_uploaded_at = datetime.utcnow()
                if total_upload > 0:
                    summary["uploaded"] += success_upload

                db.commit()
                summary["success"] += 1
                _safe_log(logs, f"账号 {account.email} OAuth 授权成功，已移出待授权队列")
                continue

            log_text = "\n".join([str(item) for item in (engine.logs or [])[-12:]])
            error_message = "OAuth Token 获取失败"
            if log_text:
                error_message = f"OAuth Token 获取失败: {log_text[-280:]}"

            if _is_rate_limited_error(log_text):
                try:
                    cooldown = max(1, int(settings.oauth_rate_limit_cooldown_seconds or 900))
                except Exception:
                    cooldown = 900
                _mark_pending_result(
                    pending,
                    account,
                    status=OAUTH_PENDING_STATUS_RATE_LIMITED,
                    error_message=error_message,
                    retry_after_seconds=cooldown,
                )
                db.commit()
                summary["rate_limited"] += 1
                _safe_log(logs, f"账号 {account.email} 命中 429，{cooldown}s 后重试", level="warning")
                continue

            if pending.attempt_count >= max_attempts:
                _mark_pending_result(
                    pending,
                    account,
                    status=OAUTH_PENDING_STATUS_FAILED,
                    error_message=error_message,
                    retry_after_seconds=None,
                )
                db.commit()
                summary["failed"] += 1
                _safe_log(logs, f"账号 {account.email} 授权失败，已达最大重试次数", level="warning")
                continue

            retry_seconds = _compute_retry_seconds(pending.attempt_count)
            _mark_pending_result(
                pending,
                account,
                status=OAUTH_PENDING_STATUS_PENDING,
                error_message=error_message,
                retry_after_seconds=retry_seconds,
            )
            db.commit()
            summary["requeued"] += 1
            _safe_log(logs, f"账号 {account.email} 授权失败，{retry_seconds}s 后重试", level="warning")

    return summary
