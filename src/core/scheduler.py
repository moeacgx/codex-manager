import asyncio
import logging
import uuid
from typing import Any, List, Optional
from datetime import datetime
from collections import deque

from curl_cffi import requests as cffi_requests

from ..database.session import get_db
from ..database import crud
from ..config.settings import get_settings
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
    return None


def fetch_cliproxy_auth_files(api_url: str, api_token: str) -> List[dict]:
    url = _normalize_cpa_auth_files_url(api_url)
    resp = cffi_requests.get(url, headers=_build_cpa_headers(api_token), timeout=30, impersonate="chrome110")
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        return []
    files = data.get("files")
    if not isinstance(files, list):
        return []
    return files


def test_cliproxy_auth_file(item: dict, api_url: str, api_token: str) -> tuple[bool, str]:
    auth_index = item.get("auth_index")
    if not auth_index:
        return False, "missing auth_index"

    account_id = _extract_cliproxy_account_id(item)
    call_header: dict = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_CLIPROXY_UA,
    }
    if account_id:
        call_header["Chatgpt-Account-Id"] = account_id

    settings = get_settings()
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
    if status_code == 401:
        return False, "status_code=401"
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

    settings = get_settings()
    
    email_service_type = "temp_mail"
    email_service_id = None
    
    # 优先使用配置中保存的邮箱服务
    saved_email_svc = settings.cpa_auto_register_email_service
    if saved_email_svc and ':' in saved_email_svc:
        parts = saved_email_svc.split(':')
        email_service_type = parts[0]
        if parts[1] != 'default':
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
        for task_uuid in task_uuids:
            crud.create_registration_task(
                db,
                task_uuid=task_uuid,
                email_service_id=email_service_id,
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
            concurrency=2, # auto register uses a limit concurrency
            mode="pipeline",
            auto_upload_cpa=True,
            cpa_service_ids=[cpa_service_id],
        )
    )


def check_cpa_services_job(main_loop, manual_logs: list = None):
    """定时检查所有启用的 CPA 服务"""
    settings = get_settings()
    if not settings.cpa_auto_check_enabled and manual_logs is None: # if manual trigger, ignore enabled flag
        return

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
                valid_count = 0
                fetch_success = False
                try:
                    _log(f"检查 CPA 服务: {svc.name}")
                    files = fetch_cliproxy_auth_files(svc.api_url, svc.api_token)
                    fetch_success = True
                    if not files:
                        _log(f"CPA 服务 {svc.name} 没有凭证", 'warning')
                    else:
                        _log(f"CPA 服务 {svc.name} 获取到 {len(files)} 个凭证")
                        
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
                        
                        _log(f"开始逐一穿透测试这 {len(files)} 个凭证的健康状态，过程可能较长，请耐心等待...")
                        invalid_count = 0
                        for item in files:
                            if settings.cpa_auto_check_sleep_seconds > 0:
                                import time
                                time.sleep(settings.cpa_auto_check_sleep_seconds)

                            name = str(item.get("name", "")).strip()
                            if not name:
                                continue
                            try:
                                is_valid, msg = test_cliproxy_auth_file(item, svc.api_url, svc.api_token)
                                if is_valid:
                                    valid_count += 1
                                else:
                                    _log(f"CPA 凭证 {name} 失效 ({msg})，正在剔除...", 'warning')
                                    try:
                                        delete_cliproxy_auth_file(name, svc.api_url, svc.api_token)
                                        invalid_count += 1
                                        _log(f"已剔除失效凭证: {name}")
                                    except Exception as e:
                                        _log(f"剔除凭证 {name} 失败: {e}", 'error')
                            except Exception as e:
                                _log(f"测试凭证 {name} 失败: {e}", 'error')
                                # 如果测试异常不当作失效处理，避免误删
                                valid_count += 1
                                
                        _log(f"CPA 服务 {svc.name} 检查完成，有效: {valid_count}，剔除: {invalid_count}")
                    
                except Exception as e:
                    _log(f"检查 CPA 服务 {svc.id} ({svc.name}) 异常/鉴权失败: {e}", 'error')
                    _log(f"无法正确访问接通接口，为保障供应，视为其剩余有效凭证数量为 0", "warning")
                    valid_count = 0

                # 无论检查成功还是失败，只要启用自动补充且 valid_count < threshold 就补货
                if settings.cpa_auto_register_enabled:
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


def start_scheduler():
    """启动调度器"""
    logger.info("启动后台调度器，负责定时任务...")
    loop = asyncio.get_event_loop()
    loop.create_task(_scheduler_loop())
