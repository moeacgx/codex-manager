import asyncio
import json
import base64
import re
import time
import logging
import uuid
from typing import Any, List, Optional
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from curl_cffi import requests as cffi_requests

from ..database.session import get_db
from ..database import crud
from ..config.settings import get_settings
from ..config.constants import EmailServiceType
from .upload.cpa_upload import _normalize_cpa_auth_files_url, _build_cpa_headers
from ..web.routes.registration import run_batch_registration

logger = logging.getLogger(__name__)

# 系统日志缓冲池（最多保留500条）
global_log_counter = 0
system_logs = deque(maxlen=500)

def append_system_log(level: str, msg: str):
    global global_log_counter
    global_log_counter += 1
    system_logs.append({"id": global_log_counter, "level": level, "msg": f"[系统自动任务] {msg}"})

DEFAULT_CLIPROXY_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
KNOWN_CLIPROXY_ERROR_LABELS = {
    "usage_limit_reached": "周限额已耗尽",
    "account_deactivated": "账号已停用",
    "insufficient_quota": "额度不足",
    "invalid_api_key": "凭证无效",
    "unsupported_region": "地区不支持",
}


def _extract_cpa_error(response) -> str:
    error_msg = f"HTTP {response.status_code}"
    try:
        data = response.json()
        if isinstance(data, dict):
            error_msg = data.get("message", error_msg)
    except Exception:
        error_msg = f"{error_msg} - {response.text[:200]}"
    return error_msg


def _extract_cliproxy_account_id(item: dict) -> Optional[str]:
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return str(val)
    id_token = item.get("id_token")
    if isinstance(id_token, dict):
        val = id_token.get("chatgpt_account_id")
        if val:
            return str(val)
    if isinstance(id_token, str):
        val = _extract_account_id_from_jwt(id_token)
        if val:
            return val
    return None


def _extract_account_id_from_jwt(token: str) -> Optional[str]:
    """从 JWT 中解析 chatgpt_account_id（兼容 Session 提取的 token）。"""
    if not token or token.count(".") < 2:
        return None
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
        return str(account_id or "").strip() or None
    except Exception:
        return None


def _coerce_status_code(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def _infer_status_code_from_text(text: str) -> Optional[int]:
    if not text:
        return None
    lower = text.lower()
    if "token_revoked" in lower or "token_invalidated" in lower or "invalidated oauth token" in lower:
        return 401
    if "unauthorized" in lower:
        return 401
    if "forbidden" in lower:
        return 403
    match = re.search(r"\b(401|403)\b", lower)
    if match:
        return int(match.group(1))
    return None


def _maybe_parse_json_text(text: str) -> Optional[Any]:
    if not text:
        return None
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except Exception:
        return None


def _extract_cliproxy_status_code(item: Any) -> Optional[int]:
    if not isinstance(item, dict):
        return None

    def _check_value(value: Any) -> Optional[int]:
        code = _coerce_status_code(value)
        if code is not None:
            return code
        if isinstance(value, str):
            inferred = _infer_status_code_from_text(value)
            if inferred is not None:
                return inferred
            parsed = _maybe_parse_json_text(value)
            if isinstance(parsed, dict):
                return _extract_cliproxy_status_code(parsed)
        return None

    for key in (
        "status_code",
        "statusCode",
        "http_status",
        "httpStatus",
        "last_status_code",
        "lastStatusCode",
        "last_http_status",
        "lastHttpStatus",
        "status",
        "http_code",
        "httpCode",
        "code",
    ):
        code = _check_value(item.get(key))
        if code is not None:
            return code

    for key in (
        "status_message",
        "statusMessage",
        "last_status",
        "lastStatus",
        "error",
        "last_error",
        "lastError",
        "error_message",
        "errorMessage",
        "message",
        "reason",
    ):
        nested = item.get(key)
        if isinstance(nested, str):
            inferred = _infer_status_code_from_text(nested)
            if inferred is not None:
                return inferred
            parsed = _maybe_parse_json_text(nested)
            if isinstance(parsed, dict):
                nested = parsed
        if isinstance(nested, dict):
            for inner_key in (
                "status_code",
                "statusCode",
                "http_status",
                "httpStatus",
                "status",
                "http_code",
                "httpCode",
                "code",
                "message",
                "error",
                "reason",
            ):
                code = _check_value(nested.get(inner_key))
                if code is not None:
                    return code
    return None


def _extract_cpa_provider_value(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        for key in ("provider", "type"):
            value = str(payload.get(key) or "").strip().lower()
            if value:
                return value

        for key in ("metadata", "auth", "auth_file", "data", "payload", "content", "json"):
            nested = payload.get(key)
            provider = _extract_cpa_provider_value(_decode_possible_json_payload(nested))
            if provider:
                return provider

    if isinstance(payload, list):
        for item in payload:
            provider = _extract_cpa_provider_value(_decode_possible_json_payload(item))
            if provider:
                return provider

    if isinstance(payload, str):
        return _extract_cpa_provider_value(_decode_possible_json_payload(payload))

    return None


def _parse_auto_register_email_pool(raw: str) -> List[tuple[str, Optional[int]]]:
    """解析自动注册邮箱服务列表（支持逗号分隔）。"""
    if not raw:
        return []
    items = [item.strip() for item in str(raw).replace(";", ",").split(",") if item.strip()]
    pool: List[tuple[str, Optional[int]]] = []
    for item in items:
        if ":" in item:
            svc_type, svc_id = item.split(":", 1)
        else:
            svc_type, svc_id = item, ""
        svc_type = svc_type.strip()
        if not svc_type:
            continue
        try:
            EmailServiceType(svc_type)
        except Exception:
            continue
        svc_id = (svc_id or "").strip()
        parsed_id: Optional[int] = None
        if svc_id and svc_id not in {"default", "all"}:
            try:
                parsed_id = int(svc_id)
            except Exception:
                parsed_id = None
        pool.append((svc_type, parsed_id))
    return pool


def _is_cpa_codex_auth_file(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    return _extract_cpa_provider_value(item) == "codex"


def fetch_cliproxy_auth_files(api_url: str, api_token: str) -> tuple[List[dict], int, int]:
    url = _normalize_cpa_auth_files_url(api_url)
    resp = cffi_requests.get(url, headers=_build_cpa_headers(api_token), timeout=30, impersonate="chrome110")
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        return [], 0, 0
    files = data.get("files")
    if not isinstance(files, list):
        return [], 0, 0

    normalized_files = [item for item in files if isinstance(item, dict)]
    total_count = len(normalized_files)

    codex_files = [item for item in normalized_files if _is_cpa_codex_auth_file(item)]
    skipped_count = total_count - len(codex_files)
    return codex_files, total_count, skipped_count


def _decode_possible_json_payload(payload: Any) -> Any:
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return payload
        try:
            return json.loads(text)
        except Exception:
            return payload
    return payload


def _extract_remaining_percent(window_info: Any) -> Optional[float]:
    if not isinstance(window_info, dict):
        return None

    remaining_percent = window_info.get("remaining_percent")
    if isinstance(remaining_percent, (int, float)):
        return max(0.0, min(100.0, float(remaining_percent)))

    used_percent = window_info.get("used_percent")
    if isinstance(used_percent, (int, float)):
        return max(0.0, min(100.0, 100.0 - float(used_percent)))

    return None


def _format_percent(value: float) -> str:
    normalized = round(float(value), 2)
    if normalized.is_integer():
        return str(int(normalized))
    return f"{normalized:.2f}".rstrip("0").rstrip(".")


def _format_known_cliproxy_error(error_type: str) -> str:
    label = KNOWN_CLIPROXY_ERROR_LABELS.get(error_type)
    if label:
        return f"{label} ({error_type})"
    return f"错误类型: {error_type}"


def _extract_rate_limit_reason(
    rate_info: Any,
    key: str,
    min_remaining_weekly_percent: int = 0,
) -> Optional[str]:
    if not isinstance(rate_info, dict):
        return None
    allowed = rate_info.get("allowed")
    limit_reached = rate_info.get("limit_reached")
    if allowed is False or limit_reached is True:
        label_map = {
            "rate_limit": "周限额已耗尽",
            "code_review_rate_limit": "代码审查周限额已耗尽",
        }
        label = label_map.get(key, f"{key} 已耗尽")
        return f"{label}（allowed={allowed}, limit_reached={limit_reached}）"

    if key == "rate_limit" and min_remaining_weekly_percent > 0:
        remaining_percent = _extract_remaining_percent(rate_info.get("primary_window"))
        if remaining_percent is not None and remaining_percent < min_remaining_weekly_percent:
            return (
                f"周限额剩余 {_format_percent(remaining_percent)}%，"
                f"低于阈值 {min_remaining_weekly_percent}%"
            )
    return None


def _extract_cliproxy_failure_reason(
    payload: Any,
    min_remaining_weekly_percent: int = 0,
) -> Optional[str]:
    data = _decode_possible_json_payload(payload)

    if isinstance(data, str):
        for keyword in (
            "usage_limit_reached",
            "account_deactivated",
            "insufficient_quota",
            "invalid_api_key",
            "unsupported_region",
        ):
            if keyword in data:
                return _format_known_cliproxy_error(keyword)
        return None

    if not isinstance(data, dict):
        return None

    error = data.get("error")
    if isinstance(error, dict):
        err_type = error.get("type")
        if err_type:
            return _format_known_cliproxy_error(err_type)
        message = error.get("message")
        if message:
            return str(message)

    for key in ("rate_limit", "code_review_rate_limit"):
        min_remaining_percent = min_remaining_weekly_percent if key == "rate_limit" else 0
        reason = _extract_rate_limit_reason(
            data.get(key),
            key,
            min_remaining_percent,
        )
        if reason:
            return reason

    additional_rate_limits = data.get("additional_rate_limits")
    if isinstance(additional_rate_limits, list):
        for index, rate_info in enumerate(additional_rate_limits):
            reason = _extract_rate_limit_reason(
                rate_info,
                f"additional_rate_limits[{index}]",
                0,
            )
            if reason:
                return reason
    elif isinstance(additional_rate_limits, dict):
        for key, rate_info in additional_rate_limits.items():
            reason = _extract_rate_limit_reason(
                rate_info,
                f"additional_rate_limits.{key}",
                0,
            )
            if reason:
                return reason

    for key in ("data", "body", "response", "text", "content", "status_message"):
        reason = _extract_cliproxy_failure_reason(
            data.get(key),
            min_remaining_weekly_percent,
        )
        if reason:
            return reason

    data_str = json.dumps(data, ensure_ascii=False)
    for keyword in (
        "usage_limit_reached",
        "account_deactivated",
        "insufficient_quota",
        "invalid_api_key",
        "unsupported_region",
    ):
        if keyword in data_str:
            return _format_known_cliproxy_error(keyword)

    return None


def _extract_cliproxy_item_failure_reason(
    item: dict,
    min_remaining_weekly_percent: int = 0,
) -> Optional[str]:
    reason = _extract_cliproxy_failure_reason(
        item.get("status_message"),
        min_remaining_weekly_percent,
    )
    if item.get("unavailable") is True:
        return f"unavailable ({reason or item.get('status') or 'unknown'})"

    status = str(item.get("status") or "").strip().lower()
    if status in {"invalid", "disabled"}:
        return f"status={status}"

    return reason


def _extract_cliproxy_panel_direct_reason(item: dict) -> Optional[str]:
    """面板直接剔除使用的明确错误（401/403 或 usage_limit_reached）。"""
    status_code = _extract_cliproxy_status_code(item)
    if status_code in (401, 403):
        return f"status_code={status_code}"

    reason = _extract_cliproxy_failure_reason(item, 0)
    if reason and "usage_limit_reached" in str(reason).lower():
        return reason

    return None


def _describe_cliproxy_failure(msg: str) -> str:
    text = str(msg or "")
    if "低于阈值" in text:
        return "周限额低于阈值"
    if "周限额已耗尽" in text or "usage_limit_reached" in text:
        return "周限额已耗尽"
    if "代码审查周限额已耗尽" in text:
        return "代码审查周限额已耗尽"
    return "失效"


def test_cliproxy_auth_file(item: dict, api_url: str, api_token: str) -> tuple[bool, str]:
    auth_index = item.get("auth_index")
    if not auth_index:
        return False, "missing auth_index"

    settings = get_settings()
    min_remaining_weekly_percent = int(
        getattr(settings, "cpa_auto_check_min_remaining_weekly_percent", 0) or 0
    )
    min_remaining_weekly_percent = max(0, min(100, min_remaining_weekly_percent))

    item_failure_reason = _extract_cliproxy_item_failure_reason(
        item,
        min_remaining_weekly_percent,
    )
    if item_failure_reason:
        return False, item_failure_reason

    account_id = _extract_cliproxy_account_id(item)
    call_header: dict = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_CLIPROXY_UA,
    }
    if account_id:
        call_header["Chatgpt-Account-Id"] = account_id

    test_url = settings.cpa_auto_check_test_url or "https://chatgpt.com/backend-api/wham/usage"
    test_model = settings.cpa_auto_check_test_model or "gpt-5.2-codex"
    
    method = "POST" if (test_model and "usage" not in test_url.lower()) else "GET"

    payload = {
        "authIndex": auth_index,
        "method": method,
        "url": test_url,
        "header": call_header,
    }
    
    if test_model:
        payload["body"] = {"model": test_model}

    base_url = (api_url or "").strip().rstrip("/")
    if base_url.endswith("/v0/management"):
        url = f"{base_url}/api-call"
    elif base_url.endswith("/management"):
        url = f"{base_url}/api-call"
    elif base_url.endswith("/v0"):
        url = f"{base_url}/management/api-call"
    elif base_url.endswith("/auth-files"):
        url = base_url.replace("/auth-files", "/api-call")
    else:
        url = f"{base_url}/v0/management/api-call"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    resp = cffi_requests.post(url, headers=headers, json=payload, timeout=30, impersonate="chrome110")
    if resp.status_code != 200:
        return False, _extract_cpa_error(resp)

    data = resp.json()
    status_code = data.get("status_code")
    if not isinstance(status_code, int):
        return False, "missing status_code"

    failure_reason = _extract_cliproxy_failure_reason(
        data,
        min_remaining_weekly_percent,
    )
    if status_code >= 400 or failure_reason:
        suffix = f" - {failure_reason}" if failure_reason else ""
        return False, f"status_code={status_code}{suffix}"

    return True, f"status_code={status_code}"


def delete_cliproxy_auth_file(name: str, api_url: str, api_token: str) -> None:
    if not name:
        return
    url = _normalize_cpa_auth_files_url(api_url)
    resp = cffi_requests.delete(url, headers=_build_cpa_headers(api_token), params={"name": name}, timeout=30, impersonate="chrome110")
    resp.raise_for_status()


async def trigger_auto_registration(count: int, cpa_service_id: int):
    logger.info(f"触发自动注册凭证，数量: {count}, 目标CPA 服务 ID: {cpa_service_id}")
    task_uuids = [str(uuid.uuid4()) for _ in range(count)]
    batch_id = str(uuid.uuid4())
    _track_auto_register_batch(batch_id)

    settings = get_settings()
    
    email_service_type = "temp_mail"
    email_service_id = None
    email_service_pool: List[tuple[str, Optional[int]]] = []
    
    # 优先使用配置中保存的邮箱服务
    saved_email_svc = settings.cpa_auto_register_email_service
    if saved_email_svc:
        email_service_pool = _parse_auto_register_email_pool(saved_email_svc)
    if email_service_pool:
        email_service_type, email_service_id = email_service_pool[0]
    else:
        if saved_email_svc and ':' in saved_email_svc:
            parts = saved_email_svc.split(':', 1)
            email_service_type = parts[0]
            if len(parts) > 1 and parts[1] != 'default':
                try:
                    email_service_id = int(parts[1])
                except:
                    pass
        else:
            with get_db() as db:
                enabled_services = crud.get_email_services(db, enabled=True)
                if enabled_services:
                    best_svc = enabled_services[0]
                    email_service_type = best_svc.service_type
                    email_service_id = best_svc.id

    with get_db() as db:
        initial_service_id = email_service_id if len(email_service_pool) <= 1 else None
        for task_uuid in task_uuids:
            crud.create_registration_task(
                db,
                task_uuid=task_uuid,
                email_service_id=initial_service_id,
                proxy=None
            )

    asyncio.create_task(
        run_batch_registration(
            batch_id=batch_id,
            task_uuids=task_uuids,
            email_service_type=email_service_type,
            proxy=None,
            email_service_config=None,
            email_service_id=email_service_id,
            interval_min=settings.registration_sleep_min,
            interval_max=settings.registration_sleep_max,
            concurrency=settings.global_concurrency,
            mode="pipeline",
            token_mode="auto",
            email_service_pool=email_service_pool if len(email_service_pool) > 1 else None,
            auto_upload_cpa=True,
            cpa_service_ids=[cpa_service_id],
        )
    )


_is_checking = False
_is_checking_401 = False
_pending_check_once = False
_pending_check_lock = threading.Lock()
_check_abort_requested = False
_check_abort_lock = threading.Lock()
_last_config_trigger_ts = 0.0
_auto_register_batch_ids = set()
_auto_register_batch_lock = threading.Lock()


def _track_auto_register_batch(batch_id: str) -> None:
    if not batch_id:
        return
    with _auto_register_batch_lock:
        _auto_register_batch_ids.add(batch_id)


def cancel_auto_register_batches() -> int:
    """取消所有自动注册批量任务（不影响手动发起的批量注册）"""
    try:
        from ..web.task_manager import task_manager
    except Exception:
        return 0

    with _auto_register_batch_lock:
        batch_ids = list(_auto_register_batch_ids)
        _auto_register_batch_ids.clear()

    cancelled = 0
    for batch_id in batch_ids:
        try:
            task_manager.cancel_batch(batch_id)
            append_system_log("warning", f"已请求停止自动注册批量任务: {batch_id[:8]}")
            cancelled += 1
        except Exception:
            continue
    return cancelled

def _mark_pending_check_once() -> bool:
    """标记在当前检查任务结束后再补跑一次检查。"""
    global _pending_check_once
    with _pending_check_lock:
        if _pending_check_once:
            return False
        _pending_check_once = True
        return True


def _consume_pending_check_once() -> bool:
    """消费一次待执行的检查请求。"""
    global _pending_check_once
    with _pending_check_lock:
        if not _pending_check_once:
            return False
        _pending_check_once = False
        return True


def _request_abort_check() -> None:
    global _check_abort_requested
    with _check_abort_lock:
        _check_abort_requested = True


def _consume_abort_check() -> bool:
    global _check_abort_requested
    with _check_abort_lock:
        if not _check_abort_requested:
            return False
        _check_abort_requested = False
        return True


def _should_abort_check() -> bool:
    with _check_abort_lock:
        return _check_abort_requested


def request_cpa_check_once(main_loop, reason: str = "config") -> None:
    """请求立即执行一次 CPA 检查（若正在运行则排队一次）。"""
    global _last_config_trigger_ts
    now = time.time()
    # 防止短时间重复触发导致多次补跑
    if now - _last_config_trigger_ts < 3:
        append_system_log("warning", "检测任务保存过于频繁，已合并触发请求")
        return
    _last_config_trigger_ts = now
    check_cpa_services_job(main_loop, None, allow_queue=True, reason=reason)

def check_cpa_services_401_job(main_loop, manual_logs: list = None, force: bool = False):
    """快速检查并剔除面板明确报错的凭证（401/403/usage_limit_reached，不做测活）"""
    global _is_checking_401
    settings = get_settings()

    if not settings.cpa_auto_check_enabled and manual_logs is None:
        return
    if not settings.cpa_auto_check_remove_401:
        msg = "未启用 401/403/usage_limit_reached 快速剔除，任务跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
            append_system_log("warning", msg)
        return
    if _is_checking and not force:
        msg = "当前正在执行完整体检任务，401/403/usage_limit_reached 快速剔除本轮跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
            append_system_log("warning", msg)
        return
    if _is_checking_401:
        msg = "当前已有 401/403/usage_limit_reached 快速剔除任务在运行，本轮跳过。"
        if manual_logs is not None:
            manual_logs.append(f"[WARNING] {msg}")
            append_system_log("warning", msg)
        return

    force_full_check_running = _is_checking and force
    _is_checking_401 = True

    def _log(msg: str, level: str = 'info'):
        log_func = getattr(logger, level, logger.info)
        log_func(msg)
        append_system_log(level, msg)
        if manual_logs is not None:
            manual_logs.append(f"[{level.upper()}] {msg}")

    if force_full_check_running:
        _log("当前正在执行完整体检任务，已按手动请求强制执行 401/403/usage_limit_reached 快速剔除。", "warning")
    _log("开始快速检查 CPA 401/403/usage_limit_reached 标记凭证...")
    try:
        with get_db() as db:
            services = crud.get_cpa_services(db, enabled=True)
            if not services:
                _log("警告：当前没有任何启用的 CPA 服务！请先配置并启用 CPA 服务。", "warning")
            for svc in services:
                try:
                    _log(f"检查 CPA 服务(401/403/usage_limit_reached 快速剔除): {svc.name}")
                    files, total_count, skipped_count = fetch_cliproxy_auth_files(svc.api_url, svc.api_token)
                    if not files:
                        if total_count > 0:
                            _log(
                                f"CPA 服务 {svc.name} 获取到 {total_count} 个凭证，"
                                f"筛选后没有 Codex 凭证（已跳过 {skipped_count} 个非 Codex/未标注凭证）",
                                'warning',
                            )
                        else:
                            _log(f"CPA 服务 {svc.name} 没有凭证", 'warning')
                        continue

                    removed_401 = 0
                    for item in files:
                        remove_reason = _extract_cliproxy_panel_direct_reason(item)
                        if not remove_reason:
                            continue
                        name = str(item.get("name", "")).strip()
                        if not name:
                            _log("检测到面板标记 401/403/usage_limit_reached 的凭证但缺少名称，已跳过快速剔除", 'warning')
                            continue
                        if not _is_cpa_codex_auth_file(item):
                            _log(f"面板标记 401/403/usage_limit_reached 的凭证 {name} 非 Codex，按策略仅跳过不清理", 'warning')
                            continue
                        try:
                            delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
                            removed_401 += 1
                            _log(f"面板快速剔除: {name} ({remove_reason})", 'warning')
                        except Exception as e:
                            _log(f"面板快速剔除 {name} 失败: {e}", 'error')

                    _log(f"CPA 服务 {svc.name} 401/403/usage_limit_reached 快速剔除完成，剔除: {removed_401}")
                except Exception as e:
                    _log(f"检查 CPA 服务 {svc.id} ({svc.name}) 401/403/usage_limit_reached 快速剔除异常: {e}", 'error')
    except Exception as e:
        _log(f"401/403/usage_limit_reached 快速剔除任务异常: {e}", 'error')
    finally:
        _is_checking_401 = False

def check_cpa_services_job(
    main_loop,
    manual_logs: list = None,
    allow_queue: bool = False,
    reason: str = "scheduler",
):
    """定时检查所有启用的 CPA 服务"""
    global _is_checking
    settings = get_settings()
    if not settings.cpa_auto_check_enabled and manual_logs is None: # if manual trigger, ignore enabled flag
        return

    if _is_checking:
        if allow_queue and manual_logs is None:
            _request_abort_check()
            queued = _mark_pending_check_once()
            msg = "检测任务运行中，已请求中止并重启以应用新配置。" if queued else "检测任务运行中，已存在重启请求，已合并。"
            append_system_log("warning", msg)
        else:
            msg = "当前已有一个检查任务在运行，本次并发请求将被跳过。"
            if manual_logs is not None:
                manual_logs.append(f"[WARNING] {msg}")
                # only inject system log if triggered manually to not pollute too much
                append_system_log("warning", msg)
        return
        
    _is_checking = True

    def _log(msg: str, level: str = 'info'):
        log_func = getattr(logger, level, logger.info)
        log_func(msg)
        append_system_log(level, msg)
        if manual_logs is not None:
            manual_logs.append(f"[{level.upper()}] {msg}")

    _log("开始检查 CPA (CLIProxy) 服务...")
    try:
        with get_db() as db:
            services = crud.get_cpa_services(db, enabled=True)
            if not services:
                _log("警告：当前没有任何启用的 CPA 服务！请先配置并启用 CPA 服务。", "warning")
            for svc in services:
                aborted = False
                if _should_abort_check():
                    _consume_abort_check()
                    _log("检测任务收到中止请求，准备重启以应用新配置。", "warning")
                    aborted = True
                    break
                valid_count = 0
                fetch_success = False
                check_failed = False
                files: List[dict] = []
                try:
                    _log(f"检查 CPA 服务: {svc.name}")
                    files, total_count, skipped_count = fetch_cliproxy_auth_files(svc.api_url, svc.api_token)
                    fetch_success = True
                    if not files:
                        if total_count > 0:
                            _log(
                                f"CPA 服务 {svc.name} 获取到 {total_count} 个凭证，"
                                f"筛选后没有 Codex 凭证（已跳过 {skipped_count} 个非 Codex/未标注凭证）",
                                'warning',
                            )
                        else:
                            _log(f"CPA 服务 {svc.name} 没有凭证", 'warning')
                    else:
                        _log(
                            f"CPA 服务 {svc.name} 获取到 {total_count} 个凭证，"
                            f"筛选后保留 {len(files)} 个 Codex 凭证，跳过 {skipped_count} 个"
                        )

                        removed_401 = 0
                        if settings.cpa_auto_check_remove_401:
                            remaining_files = []
                            for item in files:
                                remove_reason = _extract_cliproxy_panel_direct_reason(item)
                                if remove_reason:
                                    name = str(item.get("name", "")).strip()
                                    if not name:
                                        _log("检测到面板标记 401/403/usage_limit_reached 的凭证但缺少名称，已跳过快速剔除", 'warning')
                                        remaining_files.append(item)
                                        continue
                                    if not _is_cpa_codex_auth_file(item):
                                        _log(f"面板标记 401/403/usage_limit_reached 的凭证 {name} 非 Codex，按策略仅跳过不清理", 'warning')
                                        remaining_files.append(item)
                                        continue
                                    try:
                                        delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
                                        removed_401 += 1
                                        _log(f"面板快速剔除: {name} ({remove_reason})", 'warning')
                                        continue
                                    except Exception as e:
                                        _log(f"面板快速剔除 {name} 失败: {e}", 'error')
                                        remaining_files.append(item)
                                        continue
                                remaining_files.append(item)

                            if removed_401 > 0:
                                _log(f"面板 401/403/usage_limit_reached 快速剔除完成，已剔除 {removed_401} 个，剩余待测 {len(remaining_files)} 个")
                            files = remaining_files
                        
                        has_triggered_early = False
                        if settings.cpa_auto_register_enabled:
                            threshold = settings.cpa_auto_register_threshold
                            if len(files) < threshold:
                                _log(f"当前凭证总数 {len(files)} 已少于阈值 {threshold}，无需等待测活完毕，立即补货！")
                                to_register = settings.cpa_auto_register_batch_count
                                if to_register > 0:
                                    try:
                                        if main_loop:
                                            asyncio.run_coroutine_threadsafe(
                                                trigger_auto_registration(to_register, svc.id),
                                                main_loop
                                            )
                                        has_triggered_early = True
                                    except Exception as e:
                                        _log(f"调度早间补偿任务失败: {e}", 'error')
                        
                        check_mode = (getattr(settings, "cpa_auto_check_mode", "probe") or "probe").lower()
                        if check_mode not in ("probe", "panel"):
                            check_mode = "probe"

                        if check_mode == "panel":
                            if not files:
                                if removed_401 > 0:
                                    _log(f"CPA 服务 {svc.name} 401/403/usage_limit_reached 快速剔除后无剩余凭证待测", 'warning')
                                else:
                                    _log(f"CPA 服务 {svc.name} 暂无可测凭证", 'warning')
                            else:
                                _log(f"启用面板报错剔除模式，不进行穿透测活，待处理 {len(files)} 个凭证")
                            invalid_count = removed_401
                            remaining_count = 0
                            min_remaining_weekly_percent = int(
                                getattr(settings, "cpa_auto_check_min_remaining_weekly_percent", 0) or 0
                            )
                            min_remaining_weekly_percent = max(0, min(100, min_remaining_weekly_percent))
                            for item in files:
                                if _should_abort_check():
                                    _consume_abort_check()
                                    _log("检测任务收到中止请求，终止面板报错剔除并准备重启。", "warning")
                                    aborted = True
                                    break
                                name = str(item.get("name", "")).strip()
                                if not name:
                                    continue
                                status_code = _extract_cliproxy_status_code(item)
                                reason = _extract_cliproxy_item_failure_reason(
                                    item,
                                    min_remaining_weekly_percent,
                                )
                                should_remove = False
                                if status_code is not None and status_code >= 400:
                                    should_remove = True
                                if reason:
                                    should_remove = True

                                if should_remove:
                                    try:
                                        delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
                                        invalid_count += 1
                                        suffix = f" ({reason})" if reason else ""
                                        code_text = f"status_code={status_code}" if status_code is not None else "status_code=unknown"
                                        _log(f"面板报错剔除: {name} ({code_text}){suffix}", 'warning')
                                    except Exception as e:
                                        _log(f"面板报错剔除 {name} 失败: {e}", 'error')
                                else:
                                    remaining_count += 1

                            valid_count = remaining_count
                            if not aborted:
                                _log(f"CPA 服务 {svc.name} 面板报错剔除完成，有效: {valid_count}，剔除: {invalid_count}")
                        else:
                            if not files:
                                if removed_401 > 0:
                                    _log(f"CPA 服务 {svc.name} 401/403/usage_limit_reached 快速剔除后无剩余凭证待测", 'warning')
                                else:
                                    _log(f"CPA 服务 {svc.name} 暂无可测凭证", 'warning')
                            else:
                                _log(f"开始并发穿透测试这 {len(files)} 个凭证的健康状态，最大并发数: {settings.global_concurrency}，请耐心等待...")
                            invalid_count = removed_401
                            valid_count_lock = threading.Lock()
                            invalid_count_lock = threading.Lock()
                            total_files = len(files)
                            
                            def _test_item(item, index, total):
                                if _should_abort_check():
                                    return True, None
                                name = str(item.get("name", "")).strip()
                                if not name:
                                    return False, None
                                
                                if settings.cpa_auto_check_sleep_seconds > 0:
                                    import time
                                    time.sleep(settings.cpa_auto_check_sleep_seconds)
                                
                                try:
                                    is_valid, msg = test_cliproxy_auth_file(item, svc.api_url, svc.api_token)
                                    if is_valid:
                                        _log(f"测活进度 [{index}/{total}]: 凭证 {name} 状态正常")
                                        return True, name
                                    else:
                                        failure_desc = _describe_cliproxy_failure(msg)
                                        _log(
                                            f"测活进度 [{index}/{total}]: 凭证 {name} {failure_desc} ({msg})，正在剔除...",
                                            'warning',
                                        )
                                        if not _is_cpa_codex_auth_file(item):
                                            _log(f"检测到非 Codex 凭证 {name}，按策略仅跳过不清理", 'warning')
                                            return False, None
                                        delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
                                        _log(f"已剔除失效凭证: {name}")
                                        return False, name
                                except Exception as e:
                                    _log(f"测活进度 [{index}/{total}]: 测试凭证 {name} 报错 ({e})", 'error')
                                    return True, None

                            if files:
                                with ThreadPoolExecutor(max_workers=settings.global_concurrency) as executor:
                                    futures = []
                                    for i, item in enumerate(files, 1):
                                        if not get_settings().cpa_auto_check_enabled and manual_logs is None:
                                            _log("任务参数已被手动修改为停止，中止并退出当前检查...", 'warning')
                                            # Cancel pending futures
                                            for f in futures: f.cancel()
                                            return
                                        if _should_abort_check():
                                            _consume_abort_check()
                                            _log("检测任务收到中止请求，终止后续测活并准备重启。", "warning")
                                            for f in futures: f.cancel()
                                            aborted = True
                                            break
                                        futures.append(executor.submit(_test_item, item, i, total_files))
                                    
                                    for future in as_completed(futures):
                                        is_valid, deleted_name = future.result()
                                        if is_valid:
                                            with valid_count_lock: valid_count += 1
                                        elif deleted_name:
                                            with invalid_count_lock: invalid_count += 1
                                            
                            if not aborted:
                                _log(f"CPA 服务 {svc.name} 检查完成，有效: {valid_count}，剔除: {invalid_count}")
                    
                except Exception as e:
                    _log(f"检查 CPA 服务 {svc.id} ({svc.name}) 异常/鉴权失败: {e}", 'error')
                    _log(f"无法正确访问接通接口，为保障供应，视为其剩余有效凭证数量为 0", "warning")
                    valid_count = 0
                    check_failed = True

                if aborted:
                    break
                # 无论检查成功还是失败，只要启用自动补充且 valid_count < threshold 就补货
                if settings.cpa_auto_register_enabled:
                    if check_failed:
                        _log(f"CPA 服务 {svc.name} 本次检查失败，已跳过自动注册判断", "warning")
                        continue
                    # 如果之前因为总数不够已经触发过了，就不要重复触发了
                    if fetch_success and len(files) < settings.cpa_auto_register_threshold:
                        pass
                    else:
                        threshold = settings.cpa_auto_register_threshold
                        if valid_count < threshold:
                            _log(f"CPA 服务 {svc.name} 当前有效凭证估算 ({valid_count}) 少于阈值 ({threshold})，准备开启自动注册")
                            to_register = settings.cpa_auto_register_batch_count
                            if to_register > 0:
                                _log(f"已自动排队，指派生成 {to_register} 个新任务入列！")
                                try:
                                    if main_loop:
                                        asyncio.run_coroutine_threadsafe(
                                            trigger_auto_registration(to_register, svc.id),
                                            main_loop
                                        )
                                    else:
                                        _log("调度错误: 没有提供有效的 main_loop 导致无法开启协程", "error")
                                except Exception as e:
                                    _log(f"调度自动注册任务失败: {e}", 'error')

        
    except Exception as e:
        _log(f"定时检查 CPA 任务异常: {e}", 'error')
    finally:
        _is_checking = False

    if manual_logs is None and _consume_pending_check_once():
        if get_settings().cpa_auto_check_enabled:
            _log("检测任务因配置更新请求将立即再次执行", "warning")
            check_cpa_services_job(main_loop, None, allow_queue=False, reason="pending")


async def _scheduler_loop():
    """调度器主循环"""
    await asyncio.sleep(5) # 启动后延迟 5 秒开始
    loop = asyncio.get_running_loop()
    while True:
        settings = get_settings()
        try:
            await loop.run_in_executor(None, check_cpa_services_job, loop, None)
        except Exception as e:
            logger.error(f"Scheduler loop exception: {e}")
        
        # 休眠指定间隔
        interval_min = settings.cpa_auto_check_interval
        if interval_min < 1:
            interval_min = 1
        await asyncio.sleep(interval_min * 60)


async def _scheduler_401_loop():
    """401 快速剔除调度器主循环"""
    await asyncio.sleep(8) # 启动后延迟 8 秒开始
    loop = asyncio.get_running_loop()
    while True:
        settings = get_settings()
        try:
            await loop.run_in_executor(None, check_cpa_services_401_job, loop, None)
        except Exception as e:
            logger.error(f"Scheduler 401 loop exception: {e}")
        interval_min = getattr(settings, "cpa_auto_check_remove_401_interval", 3) or 3
        if interval_min < 1:
            interval_min = 1
        await asyncio.sleep(interval_min * 60)


def start_scheduler():
    """启动调度器"""
    logger.info("启动后台调度器，负责定时任务...")
    loop = asyncio.get_event_loop()
    loop.create_task(_scheduler_loop())
    loop.create_task(_scheduler_401_loop())
