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
    check_interval: int
    check_sleep: int
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
        "check_interval": settings.cpa_auto_check_interval,
        "check_sleep": settings.cpa_auto_check_sleep_seconds,
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
    from ...core.scheduler import system_logs
    # 这里我们只取从 since_id 后产生的新日志
    logs = [item for item in system_logs if item["id"] > since_id]
    last_id = logs[-1]["id"] if logs else since_id
    return {"success": True, "logs": logs, "last_id": last_id}

@router.post("/config")
async def update_cpa_scheduler_config(request: CPASchedulerConfig, background_tasks: BackgroundTasks):
    """保存CPA自动化配置"""
    update_settings(
        cpa_auto_check_enabled=request.check_enabled,
        cpa_auto_check_interval=request.check_interval,
        cpa_auto_check_sleep_seconds=request.check_sleep,
        cpa_auto_check_test_url=request.test_url,
        cpa_auto_check_test_model=request.test_model,
        cpa_auto_register_enabled=request.register_enabled,
        cpa_auto_register_threshold=request.register_threshold,
        cpa_auto_register_batch_count=request.register_batch_count,
        cpa_auto_register_email_service=request.email_service,
    )
    
    # 若启用了自动任务，保存后立刻在后台触发一次体检及补充，而不必等待下一个定时周期
    if request.check_enabled:
        from ...core.scheduler import check_cpa_services_job
        loop = asyncio.get_event_loop()
        background_tasks.add_task(loop.run_in_executor, None, check_cpa_services_job, loop, None)

    return {"success": True, "message": "定时任务配置已保存"}

@router.post("/trigger")
async def trigger_cpa_scheduler_check():
    """手动触发一次 CPA 检查并返回结果日志"""
    from ...core.scheduler import check_cpa_services_job
    
    manual_logs = []
    try:
        loop = asyncio.get_event_loop()
        # We run it in executor, but wait for it.
        await loop.run_in_executor(None, check_cpa_services_job, manual_logs)
        return {"success": True, "logs": manual_logs, "message": "检查执行完毕！"}
    except Exception as e:
        return {"success": False, "logs": manual_logs, "message": str(e)}
