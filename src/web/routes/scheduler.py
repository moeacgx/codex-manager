import logging
import asyncio
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from ...config.settings import get_settings, update_settings

logger = logging.getLogger(__name__)
router = APIRouter()

class CPASchedulerConfig(BaseModel):
    check_enabled: bool
    check_mode: str = "panel"
    check_remove_401: bool = False
    check_remove_401_interval: int = 3
    check_interval: int
    check_sleep: int
    check_min_remaining_weekly_percent: int = 20
    test_url: str
    test_model: str
    register_enabled: bool
    register_threshold: int
    register_batch_count: int
    email_service: str

@router.get("/config")
async def get_cpa_scheduler_config():
    """获取CPA自动化配置"""
    settings = get_settings()
    return {
        "check_enabled": settings.cpa_auto_check_enabled,
        "check_mode": settings.cpa_auto_check_mode,
        "check_remove_401": settings.cpa_auto_check_remove_401,
        "check_remove_401_interval": settings.cpa_auto_check_remove_401_interval,
        "check_interval": settings.cpa_auto_check_interval,
        "check_sleep": settings.cpa_auto_check_sleep_seconds,
        "check_min_remaining_weekly_percent": settings.cpa_auto_check_min_remaining_weekly_percent,
        "test_url": settings.cpa_auto_check_test_url,
        "test_model": settings.cpa_auto_check_test_model,
        "register_enabled": settings.cpa_auto_register_enabled,
        "register_threshold": settings.cpa_auto_register_threshold,
        "register_batch_count": settings.cpa_auto_register_batch_count,
        "email_service": settings.cpa_auto_register_email_service
    }

@router.get("/logs")
async def get_system_logs(since_id: int = 0):
    """获取后台产生的进度系统日志"""
    from ...core.scheduler import system_logs, global_log_counter
    
    # 如果前端请求的游标超出了当前服务器计数（通常由于你刚刚在终端重启了脚本导致内存清空），我们将它重置为从头开始拿
    if since_id > global_log_counter:
        since_id = 0
        
    # 这里我们只取从 since_id 后产生的新日志
    logs = [item for item in system_logs if item["id"] > since_id]
    last_id = logs[-1]["id"] if logs else since_id
    return {"success": True, "logs": logs, "last_id": last_id}

@router.post("/config")
async def update_cpa_scheduler_config(request: CPASchedulerConfig, background_tasks: BackgroundTasks):
    """保存CPA自动化配置"""
    if request.check_mode not in ("probe", "panel"):
        raise HTTPException(status_code=400, detail="检测方式必须为 probe 或 panel")
    update_settings(
        cpa_auto_check_enabled=request.check_enabled,
        cpa_auto_check_mode=request.check_mode,
        cpa_auto_check_remove_401=request.check_remove_401,
        cpa_auto_check_remove_401_interval=request.check_remove_401_interval,
        cpa_auto_check_interval=request.check_interval,
        cpa_auto_check_sleep_seconds=request.check_sleep,
        cpa_auto_check_min_remaining_weekly_percent=request.check_min_remaining_weekly_percent,
        cpa_auto_check_test_url=request.test_url,
        cpa_auto_check_test_model=request.test_model,
        cpa_auto_register_enabled=request.register_enabled,
        cpa_auto_register_threshold=request.register_threshold,
        cpa_auto_register_batch_count=request.register_batch_count,
        cpa_auto_register_email_service=request.email_service,
    )

    # 若关闭自动注册，尝试取消正在执行的自动注册批量任务
    if not request.register_enabled:
        try:
            from ...core.scheduler import cancel_auto_register_batches
            cancelled = cancel_auto_register_batches()
            if cancelled > 0:
                logger.info(f"已请求停止 {cancelled} 个自动注册批量任务")
        except Exception as e:
            logger.warning(f"停止自动注册批量任务失败: {e}")
    
    # 若启用了自动任务，保存后立刻在后台触发一次体检及补充，而不必等待下一个定时周期
    if request.check_enabled:
        from ...core.scheduler import request_cpa_check_once
        loop = asyncio.get_event_loop()
        background_tasks.add_task(loop.run_in_executor, None, request_cpa_check_once, loop, "config")

    return {"success": True, "message": "定时任务配置已保存"}

@router.post("/trigger")
async def trigger_cpa_scheduler_check():
    """手动触发一次 CPA 检查并返回结果日志"""
    from ...core.scheduler import check_cpa_services_job
    
    manual_logs = []
    try:
        loop = asyncio.get_event_loop()
        # 在线程池中执行，并正确传入 manual_logs 参数。
        await loop.run_in_executor(None, check_cpa_services_job, None, manual_logs)
        return {"success": True, "logs": manual_logs, "message": "检查执行完毕！"}
    except Exception as e:
        return {"success": False, "logs": manual_logs, "message": str(e)}

@router.post("/trigger-401")
async def trigger_cpa_scheduler_remove_401():
    """手动触发一次 401/403 快速剔除并返回结果日志"""
    from ...core.scheduler import check_cpa_services_401_job

    manual_logs = []
    if not get_settings().cpa_auto_check_remove_401:
        return {
            "success": False,
            "logs": manual_logs,
            "message": "请先勾选“直接剔除面板明确报错的凭证（401、403）”"
        }
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, check_cpa_services_401_job, None, manual_logs, True)
        return {"success": True, "logs": manual_logs, "message": "401/403 快速剔除执行完毕！"}
    except Exception as e:
        return {"success": False, "logs": manual_logs, "message": str(e)}
