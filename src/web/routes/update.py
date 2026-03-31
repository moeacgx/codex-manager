"""
更新 API 路由
"""

from fastapi import APIRouter, HTTPException

from ...services.update_service import get_update_service

router = APIRouter(prefix="/update", tags=["update"])


@router.get("/status")
async def update_status():
    try:
        return await get_update_service().get_status()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/check")
async def check_update():
    try:
        return await get_update_service().check_and_notify()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/confirm")
async def confirm_update():
    try:
        return await get_update_service().confirm_and_trigger_update()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
