"""
注册任务 API 路由
"""

import asyncio
import logging
import uuid
import random
import os
import time
import threading
from datetime import datetime
from typing import List, Optional, Dict, Tuple

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field

from ...database import crud
from ...database.session import get_db
from ...database.models import RegistrationTask, Proxy
from ...core.register import RegistrationResult
from ...core.pending_oauth import upsert_pending_oauth_account_from_result
from ...services import EmailServiceFactory, EmailServiceType
from ...config.settings import get_settings
from ..task_manager import task_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# 任务存储（简单的内存存储，生产环境应使用 Redis）
running_tasks: dict = {}
# 批量任务存储
batch_tasks: Dict[str, dict] = {}

# 多邮箱轮询指针（单次任务使用）
_email_service_rr_index = 0
_email_service_rr_lock = threading.Lock()


# ============== Proxy Helper Functions ==============

def get_proxy_for_registration(db) -> Tuple[Optional[str], Optional[int]]:
    """
    获取用于注册的代理

    策略：
    1. 优先从代理列表中随机选择一个启用的代理
    2. 如果代理列表为空且启用了动态代理，调用动态代理 API 获取
    3. 否则使用系统设置中的静态默认代理

    Returns:
        Tuple[proxy_url, proxy_id]: 代理 URL 和代理 ID（如果来自代理列表）
    """
    # 先尝试从代理列表中获取
    proxy = crud.get_random_proxy(db)
    if proxy:
        return proxy.proxy_url, proxy.id

    # 代理列表为空，尝试动态代理或静态代理
    from ...core.dynamic_proxy import get_proxy_url_for_task
    proxy_url = get_proxy_url_for_task()
    if proxy_url:
        return proxy_url, None

    return None, None


def update_proxy_usage(db, proxy_id: Optional[int]):
    """更新代理的使用时间"""
    if proxy_id:
        crud.update_proxy_last_used(db, proxy_id)


EMAIL_SERVICE_LABELS = {
    "tempmail": "Tempmail.lol",
    "generator_email": "Generator.email",
    "outlook": "Outlook",
    "custom_domain": "自定义域名",
    "temp_mail": "Temp-Mail 自部署",
    "duck_mail": "DuckMail",
    "cloud_mail": "CloudMail",
}


def _parse_email_service_value(value: str) -> Tuple[str, Optional[int]]:
    """解析前端邮箱服务值 (type:id 或 type:default)。"""
    if not value:
        raise ValueError("邮箱服务不能为空")
    parts = value.split(":", 1)
    service_type = parts[0].strip()
    if service_type == "outlook_batch":
        raise ValueError("Outlook 批量注册请使用专用模式")
    # 校验服务类型
    EmailServiceType(service_type)

    service_id: Optional[int] = None
    if len(parts) > 1:
        raw_id = parts[1].strip()
        if raw_id and raw_id not in ("default", "all"):
            try:
                service_id = int(raw_id)
            except ValueError:
                raise ValueError(f"无效的邮箱服务 ID: {raw_id}")

    return service_type, service_id


def _normalize_email_service_pool(values: Optional[List[str]]) -> List[Tuple[str, Optional[int]]]:
    """规范化邮箱服务多选列表，保持原有顺序并去重。"""
    if not values:
        return []

    normalized: List[Tuple[str, Optional[int]]] = []
    seen = set()
    for raw in values:
        if not raw:
            continue
        service_type, service_id = _parse_email_service_value(raw)
        key = (service_type, service_id)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(key)

    return normalized


SUPPORTED_TOKEN_MODES = {
    "browser",
    "browser_http_first",
    "browser_http_only",
}


def _normalize_token_mode(mode: str) -> str:
    """规范化 token 获取方式。"""
    value = (mode or "browser_http_only").strip().lower()
    # 兼容旧值：http_independent -> browser_http_only
    if value == "http_independent":
        logger.warning("Token 获取方式 http_independent 已合并为 browser_http_only")
        return "browser_http_only"
    if value in SUPPORTED_TOKEN_MODES:
        return value
    logger.warning(f"Token 获取方式 {value} 不受支持，回退为 browser_http_only")
    return "browser_http_only"


def _get_shared_oauth_pre_delay_seconds() -> float:
    """
    与浏览器通道共用 OAuth 前置等待变量：
    - BROWSER_OAUTH_PRE_DELAY_SECONDS
    - BROWSER_OAUTH_PRE_DELAY_JITTER_SECONDS
    """
    try:
        base = max(0.0, float(os.environ.get("BROWSER_OAUTH_PRE_DELAY_SECONDS", "0")))
    except Exception:
        base = 0.0
    try:
        jitter = max(0.0, float(os.environ.get("BROWSER_OAUTH_PRE_DELAY_JITTER_SECONDS", "0")))
    except Exception:
        jitter = 0.0
    if jitter > 0:
        base += random.uniform(0.0, jitter)
    return max(0.0, base)


def _pick_rr_service(pool: List[Tuple[str, Optional[int]]]) -> Tuple[str, Optional[int]]:
    """轮询选择邮箱服务（用于单次注册）。"""
    global _email_service_rr_index
    if not pool:
        raise ValueError("邮箱服务列表为空")
    with _email_service_rr_lock:
        index = _email_service_rr_index % len(pool)
        _email_service_rr_index += 1
        return pool[index]


# ============== Pydantic Models ==============

class RegistrationTaskCreate(BaseModel):
    """创建注册任务请求"""
    email_service_type: str = "tempmail"
    email_service_pool: List[str] = []
    token_mode: str = "browser_http_only"
    proxy: Optional[str] = None
    email_service_config: Optional[dict] = None
    email_service_id: Optional[int] = None
    auto_upload_cpa: bool = False
    cpa_service_ids: List[int] = []  # 指定 CPA 服务 ID 列表，空则取第一个启用的
    auto_upload_sub2api: bool = False
    sub2api_service_ids: List[int] = []  # 指定 Sub2API 服务 ID 列表
    auto_upload_tm: bool = False
    tm_service_ids: List[int] = []  # 指定 TM 服务 ID 列表


class BatchRegistrationRequest(BaseModel):
    """批量注册请求"""
    count: int = 1
    email_service_type: str = "tempmail"
    email_service_pool: List[str] = []
    token_mode: str = "browser_http_only"
    proxy: Optional[str] = None
    email_service_config: Optional[dict] = None
    email_service_id: Optional[int] = None
    interval_min: int = 5
    interval_max: int = 30
    concurrency: int = 1
    mode: str = "pipeline"
    auto_upload_cpa: bool = False
    cpa_service_ids: List[int] = []
    auto_upload_sub2api: bool = False
    sub2api_service_ids: List[int] = []
    auto_upload_tm: bool = False
    tm_service_ids: List[int] = []


class RegistrationTaskResponse(BaseModel):
    """注册任务响应"""
    id: int
    task_uuid: str
    status: str
    email_service_id: Optional[int] = None
    proxy: Optional[str] = None
    logs: Optional[str] = None
    result: Optional[dict] = None
    error_message: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    class Config:
        from_attributes = True


class BatchRegistrationResponse(BaseModel):
    """批量注册响应"""
    batch_id: str
    count: int
    tasks: List[RegistrationTaskResponse]


class TaskListResponse(BaseModel):
    """任务列表响应"""
    total: int
    tasks: List[RegistrationTaskResponse]


# ============== Outlook 批量注册模型 ==============

class OutlookAccountForRegistration(BaseModel):
    """可用于注册的 Outlook 账户"""
    id: int                      # EmailService 表的 ID
    email: str
    name: str
    has_oauth: bool              # 是否有 OAuth 配置
    is_registered: bool          # 是否已注册
    registered_account_id: Optional[int] = None


class OutlookAccountsListResponse(BaseModel):
    """Outlook 账户列表响应"""
    total: int
    registered_count: int        # 已注册数量
    unregistered_count: int      # 未注册数量
    accounts: List[OutlookAccountForRegistration]


class OutlookBatchRegistrationRequest(BaseModel):
    """Outlook 批量注册请求"""
    service_ids: List[int]
    skip_registered: bool = True
    token_mode: str = "browser_http_only"
    proxy: Optional[str] = None
    interval_min: int = 5
    interval_max: int = 30
    concurrency: int = 1
    mode: str = "pipeline"
    auto_upload_cpa: bool = False
    cpa_service_ids: List[int] = []
    auto_upload_sub2api: bool = False
    sub2api_service_ids: List[int] = []
    auto_upload_tm: bool = False
    tm_service_ids: List[int] = []


class OutlookBatchRegistrationResponse(BaseModel):
    """Outlook 批量注册响应"""
    batch_id: str
    total: int                   # 总数
    skipped: int                 # 跳过数（已注册）
    to_register: int             # 待注册数
    service_ids: List[int]       # 实际要注册的服务 ID


# ============== Helper Functions ==============

def task_to_response(task: RegistrationTask) -> RegistrationTaskResponse:
    """转换任务模型为响应"""
    return RegistrationTaskResponse(
        id=task.id,
        task_uuid=task.task_uuid,
        status=task.status,
        email_service_id=task.email_service_id,
        proxy=task.proxy,
        logs=task.logs,
        result=task.result,
        error_message=task.error_message,
        created_at=task.created_at.isoformat() if task.created_at else None,
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
    )


def _normalize_email_service_config(
    service_type: EmailServiceType,
    config: Optional[dict],
    proxy_url: Optional[str] = None
) -> dict:
    """按服务类型兼容旧字段名，避免不同服务的配置键互相污染。"""
    normalized = config.copy() if config else {}

    if 'api_url' in normalized and 'base_url' not in normalized:
        normalized['base_url'] = normalized.pop('api_url')
    if 'domain_select_strategy' in normalized and 'domain_strategy' not in normalized:
        normalized['domain_strategy'] = normalized.pop('domain_select_strategy')

    if service_type == EmailServiceType.CUSTOM_DOMAIN:
        if 'domain' in normalized and 'default_domain' not in normalized:
            normalized['default_domain'] = normalized.pop('domain')
        strategy = str(normalized.get('domain_strategy') or '').strip().lower()
        normalized['domain_strategy'] = strategy if strategy in ('round_robin', 'random') else 'round_robin'
    elif service_type == EmailServiceType.TEMP_MAIL:
        if 'default_domain' in normalized and 'domain' not in normalized:
            normalized['domain'] = normalized.pop('default_domain')
        strategy = str(normalized.get('domain_strategy') or '').strip().lower()
        normalized['domain_strategy'] = strategy if strategy in ('round_robin', 'random') else 'round_robin'
    elif service_type == EmailServiceType.DUCK_MAIL:
        if 'domain' in normalized and 'default_domain' not in normalized:
            normalized['default_domain'] = normalized.pop('domain')
        strategy = str(normalized.get('domain_strategy') or '').strip().lower()
        normalized['domain_strategy'] = strategy if strategy in ('round_robin', 'random') else 'round_robin'
    elif service_type == EmailServiceType.CLOUD_MAIL:
        if 'domain' in normalized and 'default_domain' not in normalized:
            normalized['default_domain'] = normalized.pop('domain')
        if 'token' in normalized and 'api_token' not in normalized:
            normalized['api_token'] = normalized.pop('token')
        strategy = str(normalized.get('domain_strategy') or '').strip().lower()
        normalized['domain_strategy'] = strategy if strategy in ('round_robin', 'random') else 'round_robin'

    if proxy_url and 'proxy_url' not in normalized:
        normalized['proxy_url'] = proxy_url

    return normalized


def _run_sync_registration_task(
    task_uuid: str,
    email_service_type: str,
    proxy: Optional[str],
    email_service_config: Optional[dict],
    email_service_id: Optional[int] = None,
    token_mode: str = "browser_http_only",
    log_prefix: str = "",
    batch_id: str = "",
    auto_upload_cpa: bool = False,
    cpa_service_ids: List[int] = None,
    auto_upload_sub2api: bool = False,
    sub2api_service_ids: List[int] = None,
    auto_upload_tm: bool = False,
    tm_service_ids: List[int] = None
):
    """
    在线程池中执行的同步注册任务

    这个函数会被 run_in_executor 调用，运行在独立线程中
    """
    with get_db() as db:
        try:
            token_mode = _normalize_token_mode(token_mode)
            http_oauth_first = token_mode == "browser_http_first"
            http_oauth_only = token_mode == "browser_http_only"
            # 检查是否已取消
            if task_manager.is_cancelled(task_uuid):
                logger.info(f"任务 {task_uuid} 已取消，跳过执行")
                return

            # 更新任务状态为运行中
            task = crud.update_registration_task(
                db, task_uuid,
                status="running",
                started_at=datetime.utcnow()
            )

            if not task:
                logger.error(f"任务不存在: {task_uuid}")
                return

            # 更新 TaskManager 状态
            task_manager.update_status(task_uuid, "running")

            # 确定使用的代理
            # 如果前端传入了代理参数，使用传入的
            # 否则从代理列表或系统设置中获取
            actual_proxy_url = proxy
            proxy_id = None

            if not actual_proxy_url:
                actual_proxy_url, proxy_id = get_proxy_for_registration(db)
                if actual_proxy_url:
                    logger.info(f"任务 {task_uuid} 使用代理: {actual_proxy_url[:50]}...")

            # 更新任务的代理记录
            crud.update_registration_task(db, task_uuid, proxy=actual_proxy_url)

            # 创建邮箱服务
            service_type = EmailServiceType(email_service_type)
            settings = get_settings()
            service_name = None
            service_id_for_log: Optional[int] = None

            # 优先使用数据库中配置的邮箱服务
            if email_service_id:
                from ...database.models import EmailService as EmailServiceModel
                db_service = db.query(EmailServiceModel).filter(
                    EmailServiceModel.id == email_service_id,
                    EmailServiceModel.enabled == True
                ).first()

                if db_service:
                    service_type = EmailServiceType(db_service.service_type)
                    config = _normalize_email_service_config(service_type, db_service.config, actual_proxy_url)
                    # 更新任务关联的邮箱服务
                    crud.update_registration_task(db, task_uuid, email_service_id=db_service.id)
                    service_name = db_service.name or EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                    service_id_for_log = db_service.id
                    logger.info(f"使用数据库邮箱服务: {db_service.name} (ID: {db_service.id}, 类型: {service_type.value})")
                else:
                    raise ValueError(f"邮箱服务不存在或已禁用: {email_service_id}")
            else:
                # 使用默认配置或传入的配置
                if service_type == EmailServiceType.TEMPMAIL:
                    config = {
                        "base_url": settings.tempmail_base_url,
                        "timeout": settings.tempmail_timeout,
                        "max_retries": settings.tempmail_max_retries,
                        "proxy_url": actual_proxy_url,
                    }
                    service_name = EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                elif service_type == EmailServiceType.GENERATOR_EMAIL:
                    config = _normalize_email_service_config(service_type, email_service_config, actual_proxy_url)
                    service_name = EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                elif service_type == EmailServiceType.CUSTOM_DOMAIN:
                    # 检查数据库中是否有可用的自定义域名服务
                    from ...database.models import EmailService as EmailServiceModel
                    db_service = db.query(EmailServiceModel).filter(
                        EmailServiceModel.service_type == "custom_domain",
                        EmailServiceModel.enabled == True
                    ).order_by(EmailServiceModel.priority.asc()).first()

                    if db_service and db_service.config:
                        config = _normalize_email_service_config(service_type, db_service.config, actual_proxy_url)
                        crud.update_registration_task(db, task_uuid, email_service_id=db_service.id)
                        service_name = db_service.name or EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                        service_id_for_log = db_service.id
                        logger.info(f"使用数据库自定义域名服务: {db_service.name}")
                    elif settings.custom_domain_base_url and settings.custom_domain_api_key:
                        config = {
                            "base_url": settings.custom_domain_base_url,
                            "api_key": settings.custom_domain_api_key.get_secret_value() if settings.custom_domain_api_key else "",
                            "proxy_url": actual_proxy_url,
                        }
                        service_name = "默认自定义域名服务"
                    else:
                        raise ValueError("没有可用的自定义域名邮箱服务，请先在设置中配置")
                elif service_type == EmailServiceType.OUTLOOK:
                    # 检查数据库中是否有可用的 Outlook 账户
                    from ...database.models import EmailService as EmailServiceModel, Account
                    # 获取所有启用的 Outlook 服务
                    outlook_services = db.query(EmailServiceModel).filter(
                        EmailServiceModel.service_type == "outlook",
                        EmailServiceModel.enabled == True
                    ).order_by(EmailServiceModel.priority.asc()).all()

                    if not outlook_services:
                        raise ValueError("没有可用的 Outlook 账户，请先在设置中导入账户")

                    # 找到一个未注册的 Outlook 账户
                    selected_service = None
                    for svc in outlook_services:
                        email = svc.config.get("email") if svc.config else None
                        if not email:
                            continue
                        # 检查是否已在 accounts 表中注册
                        existing = db.query(Account).filter(Account.email == email).first()
                        if not existing:
                            selected_service = svc
                            logger.info(f"选择未注册的 Outlook 账户: {email}")
                            break
                        else:
                            logger.info(f"跳过已注册的 Outlook 账户: {email}")

                    if selected_service and selected_service.config:
                        config = selected_service.config.copy()
                        crud.update_registration_task(db, task_uuid, email_service_id=selected_service.id)
                        service_name = selected_service.name or EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                        service_id_for_log = selected_service.id
                        logger.info(f"使用数据库 Outlook 账户: {selected_service.name}")
                    else:
                        raise ValueError("所有 Outlook 账户都已注册过 OpenAI 账号，请添加新的 Outlook 账户")
                elif service_type == EmailServiceType.DUCK_MAIL:
                    from ...database.models import EmailService as EmailServiceModel

                    db_service = db.query(EmailServiceModel).filter(
                        EmailServiceModel.service_type == "duck_mail",
                        EmailServiceModel.enabled == True
                    ).order_by(EmailServiceModel.priority.asc()).first()

                    if db_service and db_service.config:
                        config = _normalize_email_service_config(service_type, db_service.config, actual_proxy_url)
                        crud.update_registration_task(db, task_uuid, email_service_id=db_service.id)
                        service_name = db_service.name or EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                        service_id_for_log = db_service.id
                        logger.info(f"使用数据库 DuckMail 服务: {db_service.name}")
                    else:
                        raise ValueError("没有可用的 DuckMail 邮箱服务，请先在邮箱服务页面添加服务")
                elif service_type == EmailServiceType.CLOUD_MAIL:
                    from ...database.models import EmailService as EmailServiceModel

                    db_service = db.query(EmailServiceModel).filter(
                        EmailServiceModel.service_type == "cloud_mail",
                        EmailServiceModel.enabled == True
                    ).order_by(EmailServiceModel.priority.asc()).first()

                    if db_service and db_service.config:
                        config = _normalize_email_service_config(service_type, db_service.config, actual_proxy_url)
                        crud.update_registration_task(db, task_uuid, email_service_id=db_service.id)
                        service_name = db_service.name or EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
                        service_id_for_log = db_service.id
                        logger.info(f"使用数据库 CloudMail 服务: {db_service.name}")
                    else:
                        raise ValueError("没有可用的 CloudMail 邮箱服务，请先在邮箱服务页面添加服务")
                else:
                    config = email_service_config or {}
                    service_name = EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)

            # 创建注册引擎 - 使用 TaskManager 的日志回调
            log_callback = task_manager.create_log_callback(task_uuid, prefix=log_prefix, batch_id=batch_id)

            email_service = EmailServiceFactory.create(service_type, config)

            # 记录邮箱服务来源，便于控制台追踪
            label = service_name or EMAIL_SERVICE_LABELS.get(service_type.value, service_type.value)
            if service_id_for_log:
                log_callback(f"[邮箱] 使用服务: {label} (ID: {service_id_for_log}, 类型: {service_type.value})")
            else:
                log_callback(f"[邮箱] 使用服务: {label} (类型: {service_type.value})")
            # 根据 token 模式选择引擎：
            # 1) browser: 直接 Playwright
            # 2) browser_http_first: 先全程 HTTP，失败回退 Playwright
            # 3) browser_http_only: 仅全程 HTTP，失败不回退
            active_engine = None
            result = None

            if token_mode in {"browser_http_first", "browser_http_only"}:
                if token_mode == "browser_http_first":
                    log_callback("[Token] 全程 HTTP OAuth 优先（失败回退浏览器）")
                else:
                    log_callback("[Token] 仅 HTTP OAuth（失败不回退浏览器）")

                try:
                    from ...core.http_register_engine import RegistrationEngine as HttpRegistrationEngine
                    http_engine = HttpRegistrationEngine(
                        email_service=email_service,
                        proxy_url=actual_proxy_url,
                        callback_logger=log_callback,
                        task_uuid=task_uuid,
                        token_mode="oauth",
                    )
                except ImportError as ie:
                    log_callback(f"[系统] 导入 HttpRegistrationEngine 失败: {ie}")
                    raise ValueError("未完整部署独立 HTTP 注册引擎依赖")

                active_engine = http_engine
                result = http_engine.run()

                if (not result.success) and token_mode == "browser_http_first":
                    log_callback("[Token] HTTP 全程失败，回退 Playwright 浏览器流程")
                    try:
                        from ...core.browser_register import BrowserRegistrationEngine
                        browser_engine = BrowserRegistrationEngine(
                            email_service=email_service,
                            proxy_url=actual_proxy_url,
                            callback_logger=log_callback,
                            task_uuid=task_uuid,
                            oauth_http_first=False,
                            oauth_http_only=False,
                        )
                    except ImportError as ie:
                        log_callback(f"[系统] 导入 BrowserRegistrationEngine 失败: {ie}")
                        raise ValueError("未完整部署浏览器注册引擎依赖")
                    active_engine = browser_engine
                    result = browser_engine.run()
            else:
                log_callback("[Token] Playwright 浏览器全流程（默认）")
                try:
                    from ...core.browser_register import BrowserRegistrationEngine
                    browser_engine = BrowserRegistrationEngine(
                        email_service=email_service,
                        proxy_url=actual_proxy_url,
                        callback_logger=log_callback,
                        task_uuid=task_uuid,
                        oauth_http_first=http_oauth_first,
                        oauth_http_only=http_oauth_only,
                    )
                except ImportError as ie:
                    log_callback(f"[系统] 导入 BrowserRegistrationEngine 失败: {ie}")
                    raise ValueError("未完整部署浏览器注册引擎依赖")
                active_engine = browser_engine
                result = browser_engine.run()

            if result.success:
                # 更新代理使用时间
                update_proxy_usage(db, proxy_id)

                # 保存到数据库
                if active_engine:
                    active_engine.save_to_database(result)

                # 自动上传到 CPA（可多服务）
                if auto_upload_cpa:
                    try:
                        from ...core.upload.cpa_upload import (
                            upload_to_cpa,
                            generate_token_json,
                            validate_codex_account_for_upload,
                        )
                        from ...database.models import Account as AccountModel
                        saved_account = db.query(AccountModel).filter_by(email=result.email).first()
                        if saved_account and saved_account.access_token:
                            expected_client_id = str(get_settings().openai_client_id or "").strip()
                            valid, reason = validate_codex_account_for_upload(
                                saved_account,
                                expected_client_id=expected_client_id,
                            )
                            if not valid:
                                log_callback(f"[CPA] 凭证未授权，跳过上传: {reason}")
                            else:
                                token_data = generate_token_json(saved_account)
                                _cpa_ids = cpa_service_ids or []
                                if not _cpa_ids:
                                    # 未指定则取所有启用的服务
                                    _cpa_ids = [s.id for s in crud.get_cpa_services(db, enabled=True)]
                                if not _cpa_ids:
                                    log_callback("[CPA] 无可用 CPA 服务，跳过上传")
                                for _sid in _cpa_ids:
                                    try:
                                        _svc = crud.get_cpa_service_by_id(db, _sid)
                                        if not _svc:
                                            continue
                                        log_callback(f"[CPA] 上传到服务: {_svc.name}")
                                        _ok, _msg = upload_to_cpa(token_data, api_url=_svc.api_url, api_token=_svc.api_token)
                                        if _ok:
                                            saved_account.cpa_uploaded = True
                                            saved_account.cpa_uploaded_at = datetime.utcnow()
                                            db.commit()
                                            log_callback(f"[CPA] 上传成功: {_svc.name}")
                                        else:
                                            log_callback(f"[CPA] 上传失败({_svc.name}): {_msg}")
                                    except Exception as _e:
                                        log_callback(f"[CPA] 异常({_sid}): {_e}")
                    except Exception as cpa_err:
                        log_callback(f"[CPA] 上传异常: {cpa_err}")

                # 自动上传到 Sub2API（可多服务）
                if auto_upload_sub2api:
                    try:
                        from ...core.upload.sub2api_upload import upload_to_sub2api
                        from ...database.models import Account as AccountModel
                        saved_account = db.query(AccountModel).filter_by(email=result.email).first()
                        if saved_account and saved_account.access_token:
                            _s2a_ids = sub2api_service_ids or []
                            if not _s2a_ids:
                                _s2a_ids = [s.id for s in crud.get_sub2api_services(db, enabled=True)]
                            if not _s2a_ids:
                                log_callback("[Sub2API] 无可用 Sub2API 服务，跳过上传")
                            for _sid in _s2a_ids:
                                try:
                                    _svc = crud.get_sub2api_service_by_id(db, _sid)
                                    if not _svc:
                                        continue
                                    log_callback(f"[Sub2API] 上传到服务: {_svc.name}")
                                    _ok, _msg = upload_to_sub2api([saved_account], _svc.api_url, _svc.api_key)
                                    log_callback(f"[Sub2API] {'成功' if _ok else '失败'}({_svc.name}): {_msg}")
                                except Exception as _e:
                                    log_callback(f"[Sub2API] 异常({_sid}): {_e}")
                    except Exception as s2a_err:
                        log_callback(f"[Sub2API] 上传异常: {s2a_err}")

                # 自动上传到 Team Manager（可多服务）
                if auto_upload_tm:
                    try:
                        from ...core.upload.team_manager_upload import upload_to_team_manager
                        from ...database.models import Account as AccountModel
                        saved_account = db.query(AccountModel).filter_by(email=result.email).first()
                        if saved_account and saved_account.access_token:
                            _tm_ids = tm_service_ids or []
                            if not _tm_ids:
                                _tm_ids = [s.id for s in crud.get_tm_services(db, enabled=True)]
                            if not _tm_ids:
                                log_callback("[TM] 无可用 Team Manager 服务，跳过上传")
                            for _sid in _tm_ids:
                                try:
                                    _svc = crud.get_tm_service_by_id(db, _sid)
                                    if not _svc:
                                        continue
                                    log_callback(f"[TM] 上传到服务: {_svc.name}")
                                    _ok, _msg = upload_to_team_manager(saved_account, _svc.api_url, _svc.api_key)
                                    log_callback(f"[TM] {'成功' if _ok else '失败'}({_svc.name}): {_msg}")
                                except Exception as _e:
                                    log_callback(f"[TM] 异常({_sid}): {_e}")
                    except Exception as tm_err:
                        log_callback(f"[TM] 上传异常: {tm_err}")

                # 更新任务状态
                crud.update_registration_task(
                    db, task_uuid,
                    status="completed",
                    completed_at=datetime.utcnow(),
                    result=result.to_dict()
                )

                # 更新 TaskManager 状态
                task_manager.update_status(task_uuid, "completed", email=result.email)

                logger.info(f"注册任务完成: {task_uuid}, 邮箱: {result.email}")
            else:
                metadata = result.metadata or {}
                registration_completed = bool(metadata.get("registration_completed"))
                should_queue_pending_oauth = (
                    token_mode == "oauth"
                    and registration_completed
                    and bool(str(result.email or "").strip())
                    and bool(str(result.password or "").strip())
                )
                logger.info(
                    "任务 %s OAuth 失败后入队判断: token_mode=%s, registration_completed=%s, has_email=%s, has_password=%s",
                    task_uuid,
                    token_mode,
                    registration_completed,
                    bool(str(result.email or "").strip()),
                    bool(str(result.password or "").strip()),
                )

                if should_queue_pending_oauth:
                    queued = False
                    queue_message = ""
                    queued_account_id = None
                    try:
                        queued, queue_message, queued_account_id = upsert_pending_oauth_account_from_result(
                            result,
                            proxy_url=actual_proxy_url,
                        )
                    except Exception as queue_exc:
                        queue_message = f"待授权入库异常: {queue_exc}"
                        logger.exception("任务 %s 待授权入库异常", task_uuid)

                    if queued:
                        log_callback(
                            f"[OAuth] 授权未完成，已入待授权库（账号ID: {queued_account_id}）"
                        )
                        result_metadata = dict(metadata)
                        result_metadata.update(
                            {
                                "oauth_pending": True,
                                "oauth_pending_account_id": queued_account_id,
                                "oauth_pending_message": queue_message,
                            }
                        )
                        result.metadata = result_metadata
                        if not result.error_message:
                            result.error_message = "OAuth Token 获取失败，已加入待授权队列"

                        crud.update_registration_task(
                            db,
                            task_uuid,
                            status="completed",
                            completed_at=datetime.utcnow(),
                            result=result.to_dict(),
                        )
                        task_manager.update_status(task_uuid, "completed", email=result.email)
                        logger.info(
                            f"注册任务完成(待授权): {task_uuid}, 邮箱: {result.email}, 账号ID: {queued_account_id}"
                        )
                        return

                    logger.warning(
                        f"任务 {task_uuid} 入待授权库失败: {queue_message}，保持失败状态"
                    )
                else:
                    logger.info(
                        "任务 %s 未满足待授权入队条件: token_mode=%s, registration_completed=%s",
                        task_uuid,
                        token_mode,
                        registration_completed,
                    )

                # 更新任务状态为失败
                crud.update_registration_task(
                    db, task_uuid,
                    status="failed",
                    completed_at=datetime.utcnow(),
                    error_message=result.error_message,
                    result=result.to_dict(),
                )

                # 更新 TaskManager 状态
                task_manager.update_status(task_uuid, "failed", error=result.error_message)

                logger.warning(f"注册任务失败: {task_uuid}, 原因: {result.error_message}")

        except Exception as e:
            logger.error(f"注册任务异常: {task_uuid}, 错误: {e}")

            try:
                with get_db() as db:
                    crud.update_registration_task(
                        db, task_uuid,
                        status="failed",
                        completed_at=datetime.utcnow(),
                        error_message=str(e)
                    )

                # 更新 TaskManager 状态
                task_manager.update_status(task_uuid, "failed", error=str(e))
            except:
                pass


async def run_registration_task(
    task_uuid: str,
    email_service_type: str,
    proxy: Optional[str],
    email_service_config: Optional[dict],
    email_service_id: Optional[int] = None,
    token_mode: str = "browser_http_only",
    log_prefix: str = "",
    batch_id: str = "",
    auto_upload_cpa: bool = False,
    cpa_service_ids: List[int] = None,
    auto_upload_sub2api: bool = False,
    sub2api_service_ids: List[int] = None,
    auto_upload_tm: bool = False,
    tm_service_ids: List[int] = None
):
    """
    异步执行注册任务

    使用 run_in_executor 将同步任务放入线程池执行，避免阻塞主事件循环
    """
    loop = task_manager.get_loop()
    if loop is None:
        loop = asyncio.get_event_loop()
        task_manager.set_loop(loop)
    token_mode = _normalize_token_mode(token_mode)

    # 初始化 TaskManager 状态
    task_manager.update_status(task_uuid, "pending")
    task_manager.add_log(task_uuid, f"{log_prefix} [系统] 任务 {task_uuid[:8]} 已加入队列" if log_prefix else f"[系统] 任务 {task_uuid[:8]} 已加入队列")

    try:
        # 在线程池中执行同步任务（传入 log_prefix 和 batch_id 供回调使用）
        await loop.run_in_executor(
            task_manager.executor,
            _run_sync_registration_task,
            task_uuid,
            email_service_type,
            proxy,
            email_service_config,
            email_service_id,
            token_mode,
            log_prefix,
            batch_id,
            auto_upload_cpa,
            cpa_service_ids or [],
            auto_upload_sub2api,
            sub2api_service_ids or [],
            auto_upload_tm,
            tm_service_ids or [],
        )
    except Exception as e:
        logger.error(f"线程池执行异常: {task_uuid}, 错误: {e}")
        task_manager.add_log(task_uuid, f"[错误] 线程池执行异常: {str(e)}")
        task_manager.update_status(task_uuid, "failed", error=str(e))


def _init_batch_state(batch_id: str, task_uuids: List[str]):
    """初始化批量任务内存状态"""
    task_manager.init_batch(batch_id, len(task_uuids))
    batch_tasks[batch_id] = {
        "total": len(task_uuids),
        "completed": 0,
        "success": 0,
        "failed": 0,
        "cancelled": False,
        "task_uuids": task_uuids,
        "current_index": 0,
        "logs": [],
        "finished": False
    }


def _make_batch_helpers(batch_id: str):
    """返回 add_batch_log 和 update_batch_status 辅助函数"""
    def add_batch_log(msg: str):
        batch_tasks[batch_id]["logs"].append(msg)
        task_manager.add_batch_log(batch_id, msg)

    def update_batch_status(**kwargs):
        for key, value in kwargs.items():
            if key in batch_tasks[batch_id]:
                batch_tasks[batch_id][key] = value
        task_manager.update_batch_status(batch_id, **kwargs)

    return add_batch_log, update_batch_status


async def run_batch_parallel(
    batch_id: str,
    task_uuids: List[str],
    email_service_type: str,
    proxy: Optional[str],
    email_service_config: Optional[dict],
    email_service_id: Optional[int],
    concurrency: int,
    token_mode: str = "browser_http_only",
    email_service_pool: Optional[List[Tuple[str, Optional[int]]]] = None,
    auto_upload_cpa: bool = False,
    cpa_service_ids: List[int] = None,
    auto_upload_sub2api: bool = False,
    sub2api_service_ids: List[int] = None,
    auto_upload_tm: bool = False,
    tm_service_ids: List[int] = None,
    oauth_jitter_min_seconds: int = 0,
    oauth_jitter_max_seconds: int = 0,
):
    """
    并行模式：所有任务同时提交，Semaphore 控制最大并发数
    """
    _init_batch_state(batch_id, task_uuids)
    add_batch_log, update_batch_status = _make_batch_helpers(batch_id)
    semaphore = asyncio.Semaphore(concurrency)
    counter_lock = asyncio.Lock()
    token_mode = _normalize_token_mode(token_mode)
    jitter_min = max(0.0, float(oauth_jitter_min_seconds or 0))
    jitter_max = max(jitter_min, float(oauth_jitter_max_seconds or 0))
    add_batch_log(f"[系统] 并行模式启动，并发数: {concurrency}，总任务: {len(task_uuids)}")

    async def _run_one(idx: int, uuid: str):
        prefix = f"[任务{idx + 1}]"
        if email_service_pool:
            service_type, service_id = email_service_pool[idx % len(email_service_pool)]
        else:
            service_type, service_id = email_service_type, email_service_id
        logger.info(f"批量任务 {batch_id}: 任务{idx + 1}/{len(task_uuids)} 开始 ({service_type}:{service_id or 'default'})")
        async with semaphore:
            if token_mode == "oauth" and jitter_max > 0:
                jitter_delay = random.uniform(jitter_min, jitter_max)
                if jitter_delay > 0:
                    add_batch_log(f"{prefix} [节流] OAuth 启动等待 {jitter_delay:.1f}s")
                    await asyncio.sleep(jitter_delay)
            await run_registration_task(
                uuid, service_type, proxy, email_service_config, service_id,
                token_mode, log_prefix=prefix, batch_id=batch_id,
                auto_upload_cpa=auto_upload_cpa, cpa_service_ids=cpa_service_ids or [],
                auto_upload_sub2api=auto_upload_sub2api, sub2api_service_ids=sub2api_service_ids or [],
                auto_upload_tm=auto_upload_tm, tm_service_ids=tm_service_ids or [],
            )
        with get_db() as db:
            t = crud.get_registration_task(db, uuid)
            if t:
                async with counter_lock:
                    new_completed = batch_tasks[batch_id]["completed"] + 1
                    new_success = batch_tasks[batch_id]["success"]
                    new_failed = batch_tasks[batch_id]["failed"]
                    if t.status == "completed":
                        new_success += 1
                        add_batch_log(f"{prefix} [成功] 注册成功")
                    elif t.status == "failed":
                        new_failed += 1
                        add_batch_log(f"{prefix} [失败] 注册失败: {t.error_message}")
            update_batch_status(completed=new_completed, success=new_success, failed=new_failed)
            logger.info(f"批量任务 {batch_id}: 任务{idx + 1} 完成，状态={t.status}")

    try:
        await asyncio.gather(*[_run_one(i, u) for i, u in enumerate(task_uuids)], return_exceptions=True)
        if not task_manager.is_batch_cancelled(batch_id):
            add_batch_log(f"[完成] 批量任务完成！成功: {batch_tasks[batch_id]['success']}, 失败: {batch_tasks[batch_id]['failed']}")
            update_batch_status(finished=True, status="completed")
        else:
            update_batch_status(finished=True, status="cancelled")
    except Exception as e:
        logger.error(f"批量任务 {batch_id} 异常: {e}")
        add_batch_log(f"[错误] 批量任务异常: {str(e)}")
        update_batch_status(finished=True, status="failed")
    finally:
        batch_tasks[batch_id]["finished"] = True


async def run_batch_pipeline(
    batch_id: str,
    task_uuids: List[str],
    email_service_type: str,
    proxy: Optional[str],
    email_service_config: Optional[dict],
    email_service_id: Optional[int],
    interval_min: int,
    interval_max: int,
    concurrency: int,
    token_mode: str = "browser_http_only",
    email_service_pool: Optional[List[Tuple[str, Optional[int]]]] = None,
    auto_upload_cpa: bool = False,
    cpa_service_ids: List[int] = None,
    auto_upload_sub2api: bool = False,
    sub2api_service_ids: List[int] = None,
    auto_upload_tm: bool = False,
    tm_service_ids: List[int] = None,
    oauth_jitter_min_seconds: int = 0,
    oauth_jitter_max_seconds: int = 0,
):
    """
    流水线模式：每隔 interval 秒启动一个新任务，Semaphore 限制最大并发数
    """
    _init_batch_state(batch_id, task_uuids)
    add_batch_log, update_batch_status = _make_batch_helpers(batch_id)
    semaphore = asyncio.Semaphore(concurrency)
    counter_lock = asyncio.Lock()
    running_tasks_list = []
    token_mode = _normalize_token_mode(token_mode)
    jitter_min = max(0.0, float(oauth_jitter_min_seconds or 0))
    jitter_max = max(jitter_min, float(oauth_jitter_max_seconds or 0))
    add_batch_log(f"[系统] 流水线模式启动，并发数: {concurrency}，总任务: {len(task_uuids)}")

    auto_token_mode = token_mode == "auto"
    auto_sample_size = 10
    auto_min_success = 3
    auto_use_mode = "oauth" if auto_token_mode else token_mode
    sample_total = min(auto_sample_size, len(task_uuids)) if auto_token_mode else 0
    sample_done = asyncio.Event()
    sample_lock = asyncio.Lock()
    sample_completed = 0
    sample_success = 0

    if auto_token_mode:
        if sample_total == 0:
            sample_done.set()
        else:
            add_batch_log(
                f"[系统] Token 自动模式启用：前 {sample_total} 个使用 OAuth 采样，"
                f"成功 < {auto_min_success} 将切换 Session"
            )
        if jitter_max > 0:
            add_batch_log(f"[系统] OAuth 启动抖动: {jitter_min:.1f}-{jitter_max:.1f}s")
    elif token_mode == "oauth" and jitter_max > 0:
        add_batch_log(f"[系统] OAuth 启动抖动: {jitter_min:.1f}-{jitter_max:.1f}s")

    async def _run_and_release(idx: int, uuid: str, pfx: str, mode_for_task: str, is_sample: bool):
        nonlocal auto_use_mode, sample_completed, sample_success
        try:
            if email_service_pool:
                service_type, service_id = email_service_pool[idx % len(email_service_pool)]
            else:
                service_type, service_id = email_service_type, email_service_id
            if mode_for_task == "oauth" and jitter_max > 0:
                jitter_delay = random.uniform(jitter_min, jitter_max)
                if jitter_delay > 0:
                    add_batch_log(f"{pfx} [节流] OAuth 启动等待 {jitter_delay:.1f}s")
                    await asyncio.sleep(jitter_delay)
            await run_registration_task(
                uuid, service_type, proxy, email_service_config, service_id,
                mode_for_task, log_prefix=pfx, batch_id=batch_id,
                auto_upload_cpa=auto_upload_cpa, cpa_service_ids=cpa_service_ids or [],
                auto_upload_sub2api=auto_upload_sub2api, sub2api_service_ids=sub2api_service_ids or [],
                auto_upload_tm=auto_upload_tm, tm_service_ids=tm_service_ids or [],
            )
            with get_db() as db:
                t = crud.get_registration_task(db, uuid)
                if t:
                    async with counter_lock:
                        new_completed = batch_tasks[batch_id]["completed"] + 1
                        new_success = batch_tasks[batch_id]["success"]
                        new_failed = batch_tasks[batch_id]["failed"]
                        if t.status == "completed":
                            new_success += 1
                            add_batch_log(f"{pfx} [成功] 注册成功")
                        elif t.status == "failed":
                            new_failed += 1
                            add_batch_log(f"{pfx} [失败] 注册失败: {t.error_message}")
                        update_batch_status(completed=new_completed, success=new_success, failed=new_failed)

                if auto_token_mode and is_sample and sample_total > 0:
                    async with sample_lock:
                        sample_completed += 1
                        if t and t.status == "completed":
                            token_source = None
                            if isinstance(t.result, dict):
                                meta = t.result.get("metadata") or {}
                                token_source = meta.get("token_source")
                            if token_source == "oauth":
                                sample_success += 1
                        if sample_completed >= sample_total and not sample_done.is_set():
                            if sample_success < auto_min_success:
                                auto_use_mode = "session"
                                add_batch_log(
                                    f"[系统] OAuth 成功 {sample_success}/{sample_total}，已切换为 Session 提取"
                                )
                            else:
                                auto_use_mode = "oauth"
                                add_batch_log(
                                    f"[系统] OAuth 成功 {sample_success}/{sample_total}，继续使用 OAuth"
                                )
                            sample_done.set()
        finally:
            semaphore.release()

    try:
        for i, task_uuid in enumerate(task_uuids):
            if task_manager.is_batch_cancelled(batch_id) or batch_tasks[batch_id]["cancelled"]:
                with get_db() as db:
                    for remaining_uuid in task_uuids[i:]:
                        crud.update_registration_task(db, remaining_uuid, status="cancelled")
                add_batch_log("[取消] 批量任务已取消")
                update_batch_status(finished=True, status="cancelled")
                break

            if auto_token_mode and sample_total > 0 and i == sample_total and not sample_done.is_set():
                add_batch_log("[系统] OAuth 采样完成，等待统计结果...")
                await sample_done.wait()
                if task_manager.is_batch_cancelled(batch_id) or batch_tasks[batch_id]["cancelled"]:
                    with get_db() as db:
                        for remaining_uuid in task_uuids[i:]:
                            crud.update_registration_task(db, remaining_uuid, status="cancelled")
                    add_batch_log("[取消] 批量任务已取消")
                    update_batch_status(finished=True, status="cancelled")
                    break

            update_batch_status(current_index=i)
            await semaphore.acquire()
            prefix = f"[任务{i + 1}]"
            add_batch_log(f"{prefix} 开始注册...")
            if email_service_pool:
                preview_type, preview_id = email_service_pool[i % len(email_service_pool)]
            else:
                preview_type, preview_id = email_service_type, email_service_id
            logger.info(
                f"批量任务 {batch_id}: 任务{i + 1}/{len(task_uuids)} 开始 "
                f"({preview_type}:{preview_id or 'default'})"
            )
            is_sample = auto_token_mode and i < sample_total
            if auto_token_mode:
                mode_for_task = "oauth" if is_sample else auto_use_mode
            else:
                mode_for_task = token_mode
            t = asyncio.create_task(_run_and_release(i, task_uuid, prefix, mode_for_task, is_sample))
            running_tasks_list.append(t)

            if i < len(task_uuids) - 1 and not task_manager.is_batch_cancelled(batch_id):
                wait_time = random.randint(interval_min, interval_max)
                logger.info(f"批量任务 {batch_id}: 等待 {wait_time} 秒后启动下一个任务")
                await asyncio.sleep(wait_time)

        if running_tasks_list:
            await asyncio.gather(*running_tasks_list, return_exceptions=True)

        if not task_manager.is_batch_cancelled(batch_id):
            add_batch_log(f"[完成] 批量任务完成！成功: {batch_tasks[batch_id]['success']}, 失败: {batch_tasks[batch_id]['failed']}")
            update_batch_status(finished=True, status="completed")
    except Exception as e:
        logger.error(f"批量任务 {batch_id} 异常: {e}")
        add_batch_log(f"[错误] 批量任务异常: {str(e)}")
        update_batch_status(finished=True, status="failed")
    finally:
        batch_tasks[batch_id]["finished"] = True


async def run_batch_registration(
    batch_id: str,
    task_uuids: List[str],
    email_service_type: str,
    proxy: Optional[str],
    email_service_config: Optional[dict],
    email_service_id: Optional[int],
    interval_min: int,
    interval_max: int,
    concurrency: int = 1,
    mode: str = "pipeline",
    token_mode: str = "browser_http_only",
    email_service_pool: Optional[List[Tuple[str, Optional[int]]]] = None,
    auto_upload_cpa: bool = False,
    cpa_service_ids: List[int] = None,
    auto_upload_sub2api: bool = False,
    sub2api_service_ids: List[int] = None,
    auto_upload_tm: bool = False,
    tm_service_ids: List[int] = None,
    oauth_jitter_min_seconds: Optional[int] = None,
    oauth_jitter_max_seconds: Optional[int] = None,
):
    """根据 mode 分发到并行或流水线执行"""
    settings = get_settings()
    token_mode = _normalize_token_mode(token_mode)
    effective_concurrency = max(1, min(50, int(concurrency or 1)))
    effective_jitter_min = int(
        oauth_jitter_min_seconds
        if oauth_jitter_min_seconds is not None
        else settings.batch_oauth_start_jitter_min_seconds
    )
    effective_jitter_max = int(
        oauth_jitter_max_seconds
        if oauth_jitter_max_seconds is not None
        else settings.batch_oauth_start_jitter_max_seconds
    )
    effective_jitter_min = max(0, effective_jitter_min)
    effective_jitter_max = max(effective_jitter_min, max(0, effective_jitter_max))

    if mode == "parallel":
        await run_batch_parallel(
            batch_id, task_uuids, email_service_type, proxy,
            email_service_config, email_service_id, effective_concurrency, token_mode, email_service_pool,
            auto_upload_cpa=auto_upload_cpa, cpa_service_ids=cpa_service_ids,
            auto_upload_sub2api=auto_upload_sub2api, sub2api_service_ids=sub2api_service_ids,
            auto_upload_tm=auto_upload_tm, tm_service_ids=tm_service_ids,
            oauth_jitter_min_seconds=effective_jitter_min,
            oauth_jitter_max_seconds=effective_jitter_max,
        )
    else:
        await run_batch_pipeline(
            batch_id, task_uuids, email_service_type, proxy,
            email_service_config, email_service_id,
            interval_min, interval_max, effective_concurrency, token_mode, email_service_pool,
            auto_upload_cpa=auto_upload_cpa, cpa_service_ids=cpa_service_ids,
            auto_upload_sub2api=auto_upload_sub2api, sub2api_service_ids=sub2api_service_ids,
            auto_upload_tm=auto_upload_tm, tm_service_ids=tm_service_ids,
            oauth_jitter_min_seconds=effective_jitter_min,
            oauth_jitter_max_seconds=effective_jitter_max,
        )


# ============== API Endpoints ==============

@router.post("/start", response_model=RegistrationTaskResponse)
async def start_registration(
    request: RegistrationTaskCreate,
    background_tasks: BackgroundTasks
):
    """
    启动注册任务

    - email_service_type: 邮箱服务类型 (tempmail, outlook, custom_domain)
    - proxy: 代理地址
    - email_service_config: 邮箱服务配置（outlook 需要提供账户信息）
    """
    # 优先使用多选邮箱服务池
    try:
        email_service_pool = _normalize_email_service_pool(request.email_service_pool)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    token_mode = _normalize_token_mode(request.token_mode)

    if email_service_pool:
        email_service_type, email_service_id = _pick_rr_service(email_service_pool)
    else:
        # 验证邮箱服务类型
        try:
            EmailServiceType(request.email_service_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"无效的邮箱服务类型: {request.email_service_type}"
            )
        email_service_type = request.email_service_type
        email_service_id = request.email_service_id

    # 创建任务
    task_uuid = str(uuid.uuid4())

    with get_db() as db:
        task = crud.create_registration_task(
            db,
            task_uuid=task_uuid,
            proxy=request.proxy
        )

    # 在后台运行注册任务
    background_tasks.add_task(
        run_registration_task,
        task_uuid,
        email_service_type,
        request.proxy,
        request.email_service_config,
        email_service_id,
        token_mode,
        "",
        "",
        request.auto_upload_cpa,
        request.cpa_service_ids,
        request.auto_upload_sub2api,
        request.sub2api_service_ids,
        request.auto_upload_tm,
        request.tm_service_ids,
    )

    return task_to_response(task)


@router.post("/batch", response_model=BatchRegistrationResponse)
async def start_batch_registration(
    request: BatchRegistrationRequest,
    background_tasks: BackgroundTasks
):
    """
    启动批量注册任务

    - count: 注册数量 (>=1)
    - email_service_type: 邮箱服务类型
    - proxy: 代理地址
    - interval_min: 最小间隔秒数
    - interval_max: 最大间隔秒数
    """
    # 验证参数
    if request.count < 1:
        raise HTTPException(status_code=400, detail="注册数量必须大于等于 1")

    # 解析多选邮箱服务
    try:
        email_service_pool = _normalize_email_service_pool(request.email_service_pool)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    email_service_type = request.email_service_type
    email_service_id = request.email_service_id
    if email_service_pool:
        email_service_type, email_service_id = email_service_pool[0]
    else:
        try:
            EmailServiceType(request.email_service_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"无效的邮箱服务类型: {request.email_service_type}"
            )

    if request.interval_min < 0 or request.interval_max < request.interval_min:
        raise HTTPException(status_code=400, detail="间隔时间参数无效")

    if not 1 <= request.concurrency <= 50:
        raise HTTPException(status_code=400, detail="并发数必须在 1-50 之间")

    if request.mode not in ("parallel", "pipeline"):
        raise HTTPException(status_code=400, detail="模式必须为 parallel 或 pipeline")

    token_mode = _normalize_token_mode(request.token_mode)

    from ...config.settings import get_settings
    settings = get_settings()
    global_limit = settings.global_concurrency or 0
    if global_limit > 0:
        request.concurrency = min(request.concurrency, global_limit)
    if request.concurrency < 1:
        request.concurrency = 1
    if request.concurrency > 50:
        request.concurrency = 50

    if email_service_pool:
        pool_desc = ", ".join([f"{t}:{i or 'default'}" for t, i in email_service_pool])
        logger.info(f"批量注册邮箱服务轮询池: {pool_desc}")
    logger.info(
        f"批量注册启动: 数量={request.count}, 并发={request.concurrency}, "
        f"模式={request.mode}, 间隔={request.interval_min}-{request.interval_max}s"
    )
    logger.info("Token 通道固定为 Playwright 浏览器")

    # 创建批量任务
    batch_id = str(uuid.uuid4())
    task_uuids = []

    with get_db() as db:
        for _ in range(request.count):
            task_uuid = str(uuid.uuid4())
            task = crud.create_registration_task(
                db,
                task_uuid=task_uuid,
                proxy=request.proxy
            )
            task_uuids.append(task_uuid)

    # 获取所有任务
    with get_db() as db:
        tasks = [crud.get_registration_task(db, uuid) for uuid in task_uuids]

    # 在后台运行批量注册
    background_tasks.add_task(
        run_batch_registration,
        batch_id,
        task_uuids,
        email_service_type,
        request.proxy,
        request.email_service_config,
        email_service_id,
        request.interval_min,
        request.interval_max,
        request.concurrency,
        request.mode,
        token_mode,
        email_service_pool,
        request.auto_upload_cpa,
        request.cpa_service_ids,
        request.auto_upload_sub2api,
        request.sub2api_service_ids,
        request.auto_upload_tm,
        request.tm_service_ids,
        settings.batch_oauth_start_jitter_min_seconds,
        settings.batch_oauth_start_jitter_max_seconds,
    )

    return BatchRegistrationResponse(
        batch_id=batch_id,
        count=request.count,
        tasks=[task_to_response(t) for t in tasks if t]
    )


@router.get("/batch/{batch_id}")
async def get_batch_status(batch_id: str):
    """获取批量任务状态"""
    if batch_id not in batch_tasks:
        raise HTTPException(status_code=404, detail="批量任务不存在")

    batch = batch_tasks[batch_id]
    return {
        "batch_id": batch_id,
        "total": batch["total"],
        "completed": batch["completed"],
        "success": batch["success"],
        "failed": batch["failed"],
        "current_index": batch["current_index"],
        "cancelled": batch["cancelled"],
        "finished": batch.get("finished", False),
        "progress": f"{batch['completed']}/{batch['total']}"
    }


@router.post("/batch/{batch_id}/cancel")
async def cancel_batch(batch_id: str):
    """取消批量任务"""
    if batch_id not in batch_tasks:
        raise HTTPException(status_code=404, detail="批量任务不存在")

    batch = batch_tasks[batch_id]
    if batch.get("finished"):
        raise HTTPException(status_code=400, detail="批量任务已完成")

    batch["cancelled"] = True
    task_manager.cancel_batch(batch_id)
    return {"success": True, "message": "批量任务取消请求已提交"}


@router.get("/tasks", response_model=TaskListResponse)
async def list_tasks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
):
    """获取任务列表"""
    with get_db() as db:
        query = db.query(RegistrationTask)

        if status:
            query = query.filter(RegistrationTask.status == status)

        total = query.count()
        offset = (page - 1) * page_size
        tasks = query.order_by(RegistrationTask.created_at.desc()).offset(offset).limit(page_size).all()

        return TaskListResponse(
            total=total,
            tasks=[task_to_response(t) for t in tasks]
        )


@router.get("/tasks/{task_uuid}", response_model=RegistrationTaskResponse)
async def get_task(task_uuid: str):
    """获取任务详情"""
    with get_db() as db:
        task = crud.get_registration_task(db, task_uuid)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        return task_to_response(task)


@router.get("/tasks/{task_uuid}/logs")
async def get_task_logs(task_uuid: str):
    """获取任务日志"""
    with get_db() as db:
        task = crud.get_registration_task(db, task_uuid)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")

        logs = task.logs or ""
        return {
            "task_uuid": task_uuid,
            "status": task.status,
            "logs": logs.split("\n") if logs else []
        }


@router.post("/tasks/{task_uuid}/cancel")
async def cancel_task(task_uuid: str):
    """取消任务"""
    with get_db() as db:
        task = crud.get_registration_task(db, task_uuid)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")

        if task.status not in ["pending", "running"]:
            raise HTTPException(status_code=400, detail="任务已完成或已取消")

        task = crud.update_registration_task(db, task_uuid, status="cancelled")

        return {"success": True, "message": "任务已取消"}


@router.delete("/tasks/{task_uuid}")
async def delete_task(task_uuid: str):
    """删除任务"""
    with get_db() as db:
        task = crud.get_registration_task(db, task_uuid)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")

        if task.status == "running":
            raise HTTPException(status_code=400, detail="无法删除运行中的任务")

        crud.delete_registration_task(db, task_uuid)

        return {"success": True, "message": "任务已删除"}


@router.get("/stats")
async def get_registration_stats():
    """获取注册统计信息"""
    with get_db() as db:
        from sqlalchemy import func

        # 按状态统计
        status_stats = db.query(
            RegistrationTask.status,
            func.count(RegistrationTask.id)
        ).group_by(RegistrationTask.status).all()

        # 今日注册数
        today = datetime.utcnow().date()
        today_count = db.query(func.count(RegistrationTask.id)).filter(
            func.date(RegistrationTask.created_at) == today
        ).scalar()

        return {
            "by_status": {status: count for status, count in status_stats},
            "today_count": today_count
        }


@router.get("/available-services")
async def get_available_email_services():
    """
    获取可用于注册的邮箱服务列表

    返回所有已启用的邮箱服务，包括：
    - tempmail: 临时邮箱渠道（Tempmail.lol / Generator.email，当前版本默认隐藏）
    - outlook: 已导入的 Outlook 账户
    - custom_domain: 已配置的自定义域名服务
    - temp_mail: 自部署 Temp-Mail 服务
    - duck_mail: DuckMail 服务
    - cloud_mail: CloudMail 服务
    """
    from ...database.models import EmailService as EmailServiceModel
    from ...config.settings import get_settings

    settings = get_settings()
    result = {
        "tempmail": {
            "available": False,
            "count": 0,
            "services": []
        },
        "outlook": {
            "available": False,
            "count": 0,
            "services": []
        },
        "custom_domain": {
            "available": False,
            "count": 0,
            "services": []
        },
        "temp_mail": {
            "available": False,
            "count": 0,
            "services": []
        },
        "duck_mail": {
            "available": False,
            "count": 0,
            "services": []
        },
        "cloud_mail": {
            "available": False,
            "count": 0,
            "services": []
        }
    }

    with get_db() as db:
        # 获取 Outlook 账户
        outlook_services = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == "outlook",
            EmailServiceModel.enabled == True
        ).order_by(EmailServiceModel.priority.asc()).all()

        for service in outlook_services:
            config = service.config or {}
            result["outlook"]["services"].append({
                "id": service.id,
                "name": service.name,
                "type": "outlook",
                "has_oauth": bool(config.get("client_id") and config.get("refresh_token")),
                "priority": service.priority
            })

        result["outlook"]["count"] = len(outlook_services)
        result["outlook"]["available"] = len(outlook_services) > 0

        # 获取自定义域名服务
        custom_services = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == "custom_domain",
            EmailServiceModel.enabled == True
        ).order_by(EmailServiceModel.priority.asc()).all()

        for service in custom_services:
            config = service.config or {}
            result["custom_domain"]["services"].append({
                "id": service.id,
                "name": service.name,
                "type": "custom_domain",
                "default_domain": config.get("default_domain"),
                "priority": service.priority
            })

        result["custom_domain"]["count"] = len(custom_services)
        result["custom_domain"]["available"] = len(custom_services) > 0

        # 如果数据库中没有自定义域名服务，检查 settings
        if not result["custom_domain"]["available"]:
            if settings.custom_domain_base_url and settings.custom_domain_api_key:
                result["custom_domain"]["available"] = True
                result["custom_domain"]["count"] = 1
                result["custom_domain"]["services"].append({
                    "id": None,
                    "name": "默认自定义域名服务",
                    "type": "custom_domain",
                    "from_settings": True
                })

        # 获取 TempMail 服务（自部署 Cloudflare Worker 临时邮箱）
        temp_mail_services = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == "temp_mail",
            EmailServiceModel.enabled == True
        ).order_by(EmailServiceModel.priority.asc()).all()

        for service in temp_mail_services:
            config = service.config or {}
            result["temp_mail"]["services"].append({
                "id": service.id,
                "name": service.name,
                "type": "temp_mail",
                "domain": config.get("domain"),
                "priority": service.priority
            })

        result["temp_mail"]["count"] = len(temp_mail_services)
        result["temp_mail"]["available"] = len(temp_mail_services) > 0

        duck_mail_services = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == "duck_mail",
            EmailServiceModel.enabled == True
        ).order_by(EmailServiceModel.priority.asc()).all()

        for service in duck_mail_services:
            config = service.config or {}
            result["duck_mail"]["services"].append({
                "id": service.id,
                "name": service.name,
                "type": "duck_mail",
                "default_domain": config.get("default_domain"),
                "priority": service.priority
            })

        result["duck_mail"]["count"] = len(duck_mail_services)
        result["duck_mail"]["available"] = len(duck_mail_services) > 0

        cloud_mail_services = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == "cloud_mail",
            EmailServiceModel.enabled == True
        ).order_by(EmailServiceModel.priority.asc()).all()

        for service in cloud_mail_services:
            config = service.config or {}
            result["cloud_mail"]["services"].append({
                "id": service.id,
                "name": service.name,
                "type": "cloud_mail",
                "default_domain": config.get("default_domain") or config.get("domain"),
                "priority": service.priority
            })

        result["cloud_mail"]["count"] = len(cloud_mail_services)
        result["cloud_mail"]["available"] = len(cloud_mail_services) > 0

    return result


# ============== Outlook 批量注册 API ==============

@router.get("/outlook-accounts", response_model=OutlookAccountsListResponse)
async def get_outlook_accounts_for_registration():
    """
    获取可用于注册的 Outlook 账户列表

    返回所有已启用的 Outlook 服务，并检查每个邮箱是否已在 accounts 表中注册
    """
    from ...database.models import EmailService as EmailServiceModel
    from ...database.models import Account

    with get_db() as db:
        # 获取所有启用的 Outlook 服务
        outlook_services = db.query(EmailServiceModel).filter(
            EmailServiceModel.service_type == "outlook",
            EmailServiceModel.enabled == True
        ).order_by(EmailServiceModel.priority.asc()).all()

        accounts = []
        registered_count = 0
        unregistered_count = 0

        for service in outlook_services:
            config = service.config or {}
            email = config.get("email") or service.name

            # 检查是否已注册（查询 accounts 表）
            existing_account = db.query(Account).filter(
                Account.email == email
            ).first()

            is_registered = existing_account is not None
            if is_registered:
                registered_count += 1
            else:
                unregistered_count += 1

            accounts.append(OutlookAccountForRegistration(
                id=service.id,
                email=email,
                name=service.name,
                has_oauth=bool(config.get("client_id") and config.get("refresh_token")),
                is_registered=is_registered,
                registered_account_id=existing_account.id if existing_account else None
            ))

        return OutlookAccountsListResponse(
            total=len(accounts),
            registered_count=registered_count,
            unregistered_count=unregistered_count,
            accounts=accounts
        )


async def run_outlook_batch_registration(
    batch_id: str,
    service_ids: List[int],
    skip_registered: bool,
    proxy: Optional[str],
    interval_min: int,
    interval_max: int,
    concurrency: int = 1,
    mode: str = "pipeline",
    token_mode: str = "browser_http_only",
    auto_upload_cpa: bool = False,
    cpa_service_ids: List[int] = None,
    auto_upload_sub2api: bool = False,
    sub2api_service_ids: List[int] = None,
    auto_upload_tm: bool = False,
    tm_service_ids: List[int] = None,
):
    """
    异步执行 Outlook 批量注册任务，复用通用并发逻辑

    将每个 service_id 映射为一个独立的 task_uuid，然后调用
    run_batch_registration 的并发逻辑
    """
    loop = task_manager.get_loop()
    if loop is None:
        loop = asyncio.get_event_loop()
        task_manager.set_loop(loop)
    token_mode = _normalize_token_mode(token_mode)

    # 预先为每个 service_id 创建注册任务记录
    task_uuids = []
    with get_db() as db:
        for service_id in service_ids:
            task_uuid = str(uuid.uuid4())
            crud.create_registration_task(
                db,
                task_uuid=task_uuid,
                proxy=proxy,
                email_service_id=service_id
            )
            task_uuids.append(task_uuid)

    # 复用通用并发逻辑（outlook 服务类型，每个任务通过 email_service_id 定位账户）
    await run_batch_registration(
        batch_id=batch_id,
        task_uuids=task_uuids,
        email_service_type="outlook",
        proxy=proxy,
        email_service_config=None,
        email_service_id=None,   # 每个任务已绑定了独立的 email_service_id
        interval_min=interval_min,
        interval_max=interval_max,
        concurrency=concurrency,
        mode=mode,
        token_mode=token_mode,
        auto_upload_cpa=auto_upload_cpa,
        cpa_service_ids=cpa_service_ids,
        auto_upload_sub2api=auto_upload_sub2api,
        sub2api_service_ids=sub2api_service_ids,
        auto_upload_tm=auto_upload_tm,
        tm_service_ids=tm_service_ids,
    )


@router.post("/outlook-batch", response_model=OutlookBatchRegistrationResponse)
async def start_outlook_batch_registration(
    request: OutlookBatchRegistrationRequest,
    background_tasks: BackgroundTasks
):
    """
    启动 Outlook 批量注册任务

    - service_ids: 选中的 EmailService ID 列表
    - skip_registered: 是否自动跳过已注册邮箱（默认 True）
    - proxy: 代理地址
    - interval_min: 最小间隔秒数
    - interval_max: 最大间隔秒数
    """
    from ...database.models import EmailService as EmailServiceModel
    from ...database.models import Account

    # 验证参数
    if not request.service_ids:
        raise HTTPException(status_code=400, detail="请选择至少一个 Outlook 账户")

    if request.interval_min < 0 or request.interval_max < request.interval_min:
        raise HTTPException(status_code=400, detail="间隔时间参数无效")

    if not 1 <= request.concurrency <= 50:
        raise HTTPException(status_code=400, detail="并发数必须在 1-50 之间")

    if request.mode not in ("parallel", "pipeline"):
        raise HTTPException(status_code=400, detail="模式必须为 parallel 或 pipeline")

    token_mode = _normalize_token_mode(request.token_mode)

    from ...config.settings import get_settings
    settings = get_settings()
    request.concurrency = max(1, int(settings.global_concurrency or 1))
    request.concurrency = max(1, min(50, int(request.concurrency)))

    # 过滤掉已注册的邮箱
    actual_service_ids = request.service_ids
    skipped_count = 0

    if request.skip_registered:
        actual_service_ids = []
        with get_db() as db:
            for service_id in request.service_ids:
                service = db.query(EmailServiceModel).filter(
                    EmailServiceModel.id == service_id
                ).first()

                if not service:
                    continue

                config = service.config or {}
                email = config.get("email") or service.name

                # 检查是否已注册
                existing_account = db.query(Account).filter(
                    Account.email == email
                ).first()

                if existing_account:
                    skipped_count += 1
                else:
                    actual_service_ids.append(service_id)

    if not actual_service_ids:
        return OutlookBatchRegistrationResponse(
            batch_id="",
            total=len(request.service_ids),
            skipped=skipped_count,
            to_register=0,
            service_ids=[]
        )

    # 创建批量任务
    batch_id = str(uuid.uuid4())

    # 初始化批量任务状态
    batch_tasks[batch_id] = {
        "total": len(actual_service_ids),
        "completed": 0,
        "success": 0,
        "failed": 0,
        "skipped": 0,
        "cancelled": False,
        "service_ids": actual_service_ids,
        "current_index": 0,
        "logs": [],
        "finished": False
    }

    # 在后台运行批量注册
    background_tasks.add_task(
        run_outlook_batch_registration,
        batch_id,
        actual_service_ids,
        request.skip_registered,
        request.proxy,
        request.interval_min,
        request.interval_max,
        request.concurrency,
        request.mode,
        token_mode,
        request.auto_upload_cpa,
        request.cpa_service_ids,
        request.auto_upload_sub2api,
        request.sub2api_service_ids,
        request.auto_upload_tm,
        request.tm_service_ids,
    )

    return OutlookBatchRegistrationResponse(
        batch_id=batch_id,
        total=len(request.service_ids),
        skipped=skipped_count,
        to_register=len(actual_service_ids),
        service_ids=actual_service_ids
    )


@router.get("/outlook-batch/{batch_id}")
async def get_outlook_batch_status(batch_id: str):
    """获取 Outlook 批量任务状态"""
    if batch_id not in batch_tasks:
        raise HTTPException(status_code=404, detail="批量任务不存在")

    batch = batch_tasks[batch_id]
    return {
        "batch_id": batch_id,
        "total": batch["total"],
        "completed": batch["completed"],
        "success": batch["success"],
        "failed": batch["failed"],
        "skipped": batch.get("skipped", 0),
        "current_index": batch["current_index"],
        "cancelled": batch["cancelled"],
        "finished": batch.get("finished", False),
        "logs": batch.get("logs", []),
        "progress": f"{batch['completed']}/{batch['total']}"
    }


@router.post("/outlook-batch/{batch_id}/cancel")
async def cancel_outlook_batch(batch_id: str):
    """取消 Outlook 批量任务"""
    if batch_id not in batch_tasks:
        raise HTTPException(status_code=404, detail="批量任务不存在")

    batch = batch_tasks[batch_id]
    if batch.get("finished"):
        raise HTTPException(status_code=400, detail="批量任务已完成")

    # 同时更新两个系统的取消状态
    batch["cancelled"] = True
    task_manager.cancel_batch(batch_id)

    return {"success": True, "message": "批量任务取消请求已提交"}
