"""
更新服务：检查 GitHub Release 并执行一键更新
"""

import asyncio
import json
import logging
import os
import platform
import re
import shutil
import stat
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib import error as url_error
from urllib import request as url_request

from ..config.settings import get_settings
from .restart_service import AppRestartService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GitHubReleaseAsset:
    name: str
    browser_download_url: str
    size: int


@dataclass(slots=True)
class GitHubReleaseInfo:
    tag_name: str
    html_url: str
    body: str
    published_at: str
    assets: list[GitHubReleaseAsset]


class UpdateService:
    def __init__(self, restart_service: AppRestartService | None = None):
        self.restart_service = restart_service or AppRestartService()
        self._status_cache: dict[str, object] | None = None
        self._status_cache_at = 0.0
        self._status_lock = asyncio.Lock()
        self._last_error = ""
        self._last_check_at = ""

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _normalize_tag(value: str | None) -> str:
        return str(value or "").strip().lower().lstrip("v")

    @classmethod
    def _parse_version_tuple(cls, value: str | None) -> tuple[int, ...] | None:
        normalized = cls._normalize_tag(value)
        if not normalized or not normalized[:1].isdigit():
            return None
        parts = re.findall(r"\d+", normalized)
        if not parts:
            return None
        return tuple(int(part) for part in parts[:4])

    @classmethod
    def _has_newer_version(cls, current_version: str, latest_tag: str) -> bool:
        current_tuple = cls._parse_version_tuple(current_version)
        latest_tuple = cls._parse_version_tuple(latest_tag)
        if current_tuple is not None and latest_tuple is not None:
            width = max(len(current_tuple), len(latest_tuple))
            current_padded = current_tuple + (0,) * (width - len(current_tuple))
            latest_padded = latest_tuple + (0,) * (width - len(latest_tuple))
            return latest_padded > current_padded
        return cls._normalize_tag(current_version) != cls._normalize_tag(latest_tag)

    @staticmethod
    def _is_running_in_docker() -> bool:
        if os.path.exists("/.dockerenv"):
            return True
        for path in ("/proc/1/cgroup", "/proc/self/cgroup"):
            try:
                text = Path(path).read_text(encoding="utf-8")
            except Exception:
                continue
            lowered = text.lower()
            if any(token in lowered for token in ("docker", "containerd", "kubepods")):
                return True
        return False

    def _status_cache_ttl_seconds(self) -> int:
        settings = get_settings()
        interval = int(settings.update_check_interval_seconds or 600)
        return min(max(interval, 30), 600)

    def _build_headers(self, *, accept: str) -> dict[str, str]:
        settings = get_settings()
        headers = {
            "Accept": accept,
            "User-Agent": "codex-register-updater",
        }
        token = ""
        if settings.update_github_token:
            token = settings.update_github_token.get_secret_value()
        token = (token or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _build_opener(self):
        settings = get_settings()
        proxy_url = settings.proxy_url
        if proxy_url:
            return url_request.build_opener(url_request.ProxyHandler({
                "http": proxy_url,
                "https": proxy_url,
            }))
        return url_request.build_opener()

    def _fetch_latest_release_sync(self, repository: str, timeout_seconds: int) -> GitHubReleaseInfo | None:
        url = f"https://api.github.com/repos/{repository}/releases/latest"
        req = url_request.Request(
            url,
            headers=self._build_headers(accept="application/vnd.github+json"),
            method="GET",
        )
        opener = self._build_opener()
        try:
            with opener.open(req, timeout=timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except url_error.HTTPError as exc:
            if int(exc.code) == 404:
                return None
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"GitHub Release 查询失败(status={exc.code}): {body[:200]}") from exc
        except Exception as exc:
            raise RuntimeError(f"GitHub Release 查询失败: {exc}") from exc

        assets: list[GitHubReleaseAsset] = []
        for item in payload.get("assets", []):
            assets.append(
                GitHubReleaseAsset(
                    name=str(item.get("name") or "").strip(),
                    browser_download_url=str(item.get("browser_download_url") or "").strip(),
                    size=int(item.get("size") or 0),
                )
            )

        return GitHubReleaseInfo(
            tag_name=str(payload.get("tag_name") or "").strip(),
            html_url=str(payload.get("html_url") or "").strip(),
            body=str(payload.get("body") or "").strip(),
            published_at=str(payload.get("published_at") or "").strip(),
            assets=assets,
        )

    def _download_asset_sync(self, asset_url: str, destination: Path, timeout_seconds: int) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        req = url_request.Request(
            asset_url,
            headers=self._build_headers(accept="application/octet-stream"),
            method="GET",
        )
        opener = self._build_opener()
        try:
            with opener.open(req, timeout=timeout_seconds) as response, destination.open("wb") as file_obj:
                shutil.copyfileobj(response, file_obj)
        except Exception as exc:
            raise RuntimeError(f"下载更新包失败: {exc}") from exc

    def _resolve_asset_info(self) -> tuple[str | None, str | None, str]:
        system = platform.system().lower()
        machine = platform.machine().lower()

        if system.startswith("win"):
            if machine in {"x86_64", "amd64"}:
                return "windows-x64", "codex-register.exe", machine
            return None, None, machine
        if system == "linux":
            if machine in {"x86_64", "amd64"}:
                return "linux-x64", "codex-register", machine
            if machine in {"aarch64", "arm64"}:
                return "linux-arm64", "codex-register", machine
            return None, None, machine
        if system in {"darwin", "mac", "macos"}:
            if machine in {"arm64", "aarch64"}:
                return "macos-arm64", "codex-register", machine
            if machine in {"x86_64", "amd64"}:
                return "macos-x64", "codex-register", machine
            return None, None, machine
        return None, None, machine

    def _pick_asset(self, assets: list[GitHubReleaseAsset]) -> tuple[GitHubReleaseAsset | None, str, str]:
        settings = get_settings()
        arch_label, default_executable, machine = self._resolve_asset_info()
        if not arch_label:
            return None, machine, default_executable or ""

        prefix = (settings.self_update_asset_prefix or "codex-register").strip().lower()
        exact_name = f"{prefix}-{arch_label}.zip"
        for asset in assets:
            if asset.name.strip().lower() == exact_name:
                return asset, arch_label, default_executable or ""

        for asset in assets:
            normalized = asset.name.strip().lower()
            if normalized.endswith(".zip") and arch_label in normalized and prefix in normalized:
                return asset, arch_label, default_executable or ""

        return None, arch_label, default_executable or ""

    def _resolve_work_paths(self) -> tuple[Path, Path, Path, Path]:
        settings = get_settings()
        work_root = Path(settings.self_update_work_dir or "data/self_update").expanduser()
        if not work_root.is_absolute():
            work_root = Path.cwd() / work_root
        workspace_dir = work_root / "workspace"
        current_dir = work_root / "current"
        backup_dir = work_root / "previous"
        return work_root, workspace_dir, current_dir, backup_dir

    @staticmethod
    def _unwrap_stage_dir(stage_dir: Path) -> Path:
        children = [item for item in stage_dir.iterdir() if item.name != "__MACOSX"]
        if len(children) == 1 and children[0].is_dir():
            return children[0]
        return stage_dir

    @staticmethod
    def _promote_current_directory(source_dir: Path, current_dir: Path, backup_dir: Path) -> None:
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)

        moved_current = False
        try:
            if current_dir.exists():
                current_dir.rename(backup_dir)
                moved_current = True
            source_dir.rename(current_dir)
        except Exception:
            if moved_current and backup_dir.exists() and not current_dir.exists():
                backup_dir.rename(current_dir)
            raise

    def _apply_release_sync(self, *, latest_tag: str, asset_name: str, asset_url: str) -> None:
        _work_root, workspace_dir, current_dir, backup_dir = self._resolve_work_paths()
        workspace_dir.mkdir(parents=True, exist_ok=True)

        package_path = workspace_dir / f"pkg-{int(time.time())}-{asset_name}"
        stage_dir = workspace_dir / f"stage-{int(time.time())}"
        promote_source = stage_dir

        try:
            self._download_asset_sync(asset_url, package_path, int(get_settings().update_http_timeout_seconds))
            stage_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(package_path, "r") as archive:
                archive.extractall(stage_dir)

            promote_source = self._unwrap_stage_dir(stage_dir)

            settings = get_settings()
            executable_name = (settings.self_update_executable_name or "codex-register").strip() or "codex-register"
            arch_label, default_executable, _machine = self._resolve_asset_info()
            if default_executable and (executable_name.lower() == "codex-register") and default_executable.lower().endswith(".exe"):
                executable_name = default_executable
            executable_path = promote_source / executable_name
            if not executable_path.exists():
                raise RuntimeError(f"更新包结构无效：缺少 {executable_name}")

            if os.name != "nt":
                executable_path.chmod(executable_path.stat().st_mode | stat.S_IEXEC)

            (promote_source / "VERSION").write_text(f"{latest_tag}\n", encoding="utf-8")
            self._promote_current_directory(promote_source, current_dir, backup_dir)
        except zipfile.BadZipFile as exc:
            raise RuntimeError(f"更新包不是有效 zip 文件: {exc}") from exc
        finally:
            if package_path.exists():
                package_path.unlink(missing_ok=True)
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)

    async def _check_status_core(self) -> dict[str, object]:
        now = self._now()
        settings = get_settings()
        current_version = (settings.app_version or "dev").strip() or "dev"
        is_docker = self._is_running_in_docker()
        repository = (settings.update_repository or "").strip()

        base: dict[str, object] = {
            "ok": True,
            "enabled": bool(settings.self_update_enabled),
            "current_version": current_version,
            "repository": repository,
            "is_docker": is_docker,
            "docker_only": bool(settings.self_update_docker_only),
            "restart_requested": bool(self.restart_service.restart_requested),
            "last_error": self._last_error,
            "last_check_at": self._last_check_at,
        }

        if not settings.self_update_enabled:
            self._last_error = ""
            self._last_check_at = now
            base.update(
                {
                    "has_update": False,
                    "update_available": False,
                    "can_apply": False,
                    "blocked_reason": "自动更新功能未启用",
                    "message": "自动更新功能未启用",
                    "last_check_at": now,
                    "last_error": "",
                }
            )
            return base

        if not repository or "/" not in repository:
            error = "UPDATE_REPOSITORY 配置无效，应为 owner/repo"
            self._last_error = error
            self._last_check_at = now
            base.update(
                {
                    "ok": False,
                    "error": error,
                    "has_update": False,
                    "update_available": False,
                    "can_apply": False,
                    "last_check_at": now,
                    "last_error": error,
                }
            )
            return base

        try:
            release = await asyncio.to_thread(
                self._fetch_latest_release_sync,
                repository,
                int(settings.update_http_timeout_seconds),
            )
        except Exception as exc:
            error = f"更新检查失败: {exc}"
            self._last_error = error[:500]
            self._last_check_at = now
            base.update(
                {
                    "ok": False,
                    "error": error,
                    "has_update": False,
                    "update_available": False,
                    "can_apply": False,
                    "last_check_at": now,
                    "last_error": self._last_error,
                }
            )
            return base

        if release is None or not release.tag_name:
            error = "仓库未找到可用 Release，无法执行更新"
            self._last_error = error
            self._last_check_at = now
            base.update(
                {
                    "ok": False,
                    "error": error,
                    "has_update": False,
                    "update_available": False,
                    "can_apply": False,
                    "last_check_at": now,
                    "last_error": error,
                }
            )
            return base

        asset, arch_label, _exe_name = self._pick_asset(release.assets)
        has_update = self._has_newer_version(current_version, release.tag_name)
        message = ""
        blocked_reason = ""
        if not has_update:
            message = "当前已是最新版本"
            blocked_reason = message
        elif settings.self_update_docker_only and not is_docker:
            blocked_reason = "当前仅支持 Docker 容器内执行自更新"
            message = blocked_reason
        elif asset is None:
            blocked_reason = f"未找到匹配当前架构的更新包（arch={arch_label}）"
            message = blocked_reason

        can_apply = has_update and not blocked_reason

        self._last_error = ""
        self._last_check_at = now

        base.update(
            {
                "has_update": has_update,
                "update_available": has_update,
                "can_apply": can_apply,
                "blocked_reason": blocked_reason or None,
                "message": message or None,
                "latest_tag": release.tag_name,
                "release_url": release.html_url,
                "published_at": release.published_at,
                "notes": release.body,
                "asset_name": asset.name if asset else None,
                "asset_download_url": asset.browser_download_url if asset else None,
                "asset_size_bytes": asset.size if asset else None,
                "arch": arch_label,
                "last_check_at": now,
                "last_error": "",
            }
        )
        return base

    async def _load_status(self, *, force_refresh: bool) -> dict[str, object]:
        ttl_seconds = self._status_cache_ttl_seconds()
        if not force_refresh and self._status_cache is not None and (time.monotonic() - self._status_cache_at) < ttl_seconds:
            return dict(self._status_cache)

        async with self._status_lock:
            if not force_refresh and self._status_cache is not None and (time.monotonic() - self._status_cache_at) < ttl_seconds:
                return dict(self._status_cache)
            status = await self._check_status_core()
            self._status_cache = dict(status)
            self._status_cache_at = time.monotonic()
            return dict(status)

    def _invalidate_status_cache(self) -> None:
        self._status_cache = None
        self._status_cache_at = 0.0

    async def get_status(self) -> dict[str, object]:
        return await self._load_status(force_refresh=False)

    async def check_and_notify(self) -> dict[str, object]:
        return await self._load_status(force_refresh=True)

    async def confirm_and_trigger_update(self) -> dict[str, object]:
        status = await self._load_status(force_refresh=True)
        if not bool(status.get("ok")):
            raise RuntimeError(str(status.get("error") or "更新检查失败"))

        if not bool(status.get("has_update")):
            return {
                "ok": True,
                "triggered": False,
                "current_version": status.get("current_version"),
                "latest_tag": status.get("latest_tag") or status.get("current_version"),
                "message": status.get("message") or "当前已是最新版本",
            }

        if not bool(status.get("can_apply")):
            raise RuntimeError(str(status.get("blocked_reason") or "当前环境不允许执行自更新"))

        latest_tag = str(status.get("latest_tag") or "").strip()
        asset_name = str(status.get("asset_name") or "").strip()
        asset_url = str(status.get("asset_download_url") or "").strip()
        if not latest_tag or not asset_name or not asset_url:
            raise RuntimeError("缺少可用更新包信息，无法执行更新")

        await asyncio.to_thread(
            self._apply_release_sync,
            latest_tag=latest_tag,
            asset_name=asset_name,
            asset_url=asset_url,
        )

        now = self._now()
        self._invalidate_status_cache()
        self.restart_service.request_restart(
            int(get_settings().self_update_restart_delay_seconds),
            f"self-update {latest_tag}",
        )

        return {
            "ok": True,
            "triggered": True,
            "current_version": status.get("current_version"),
            "latest_tag": latest_tag,
            "asset_name": asset_name,
            "restart_requested": bool(self.restart_service.restart_requested),
            "confirmed_at": now,
        }


_update_service: UpdateService | None = None


def get_update_service() -> UpdateService:
    global _update_service
    if _update_service is None:
        _update_service = UpdateService()
    return _update_service
