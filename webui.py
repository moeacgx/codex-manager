"""
Web UI 启动入口
"""

import uvicorn
import logging
import sys
import subprocess
import time
from collections import deque
from pathlib import Path

# 添加项目根目录到 Python 路径
# PyInstaller 打包后 __file__ 在临时解压目录，需要用 sys.executable 所在目录作为数据目录
import os
if getattr(sys, 'frozen', False):
    # 打包后：使用可执行文件所在目录
    project_root = Path(sys.executable).parent
    _src_root = Path(sys._MEIPASS)
else:
    project_root = Path(__file__).parent
    _src_root = project_root
sys.path.insert(0, str(_src_root))

from src.core.utils import setup_logging
from src.database.init_db import initialize_database
from src.config.settings import get_settings


def _load_dotenv():
    """加载 .env 文件（可执行文件同目录或项目根目录）"""
    env_path = project_root / ".env"
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def setup_application():
    """设置应用程序"""
    # 加载 .env 文件（优先级低于已有环境变量）
    _load_dotenv()

    # 确保数据目录和日志目录可持久化（支持环境变量覆盖）
    data_dir, logs_dir = _resolve_runtime_dirs(project_root)
    data_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)

    # 将数据目录路径注入环境变量，供数据库配置使用
    os.environ.setdefault("APP_DATA_DIR", str(data_dir))
    os.environ.setdefault("APP_LOGS_DIR", str(logs_dir))

    # 初始化数据库（必须先于获取设置）
    try:
        initialize_database()
    except Exception as e:
        print(f"数据库初始化失败: {e}")
        raise

    # 获取配置（需要数据库已初始化）
    settings = get_settings()

    # 配置日志（日志文件写到实际 logs 目录）
    log_file = str(logs_dir / Path(settings.log_file).name)
    setup_logging(
        log_level=settings.log_level,
        log_file=log_file
    )

    logger = logging.getLogger(__name__)
    logger.info("数据库初始化完成")
    logger.info(f"数据目录: {data_dir}")
    logger.info(f"日志目录: {logs_dir}")

    logger.info("应用程序设置完成")
    return settings


def _derive_persistent_root(root: Path) -> Path | None:
    """从 self_update/current 路径推导持久化根目录。"""
    try:
        parts = list(root.parts)
        for i in range(len(parts) - 1):
            if parts[i] == "self_update" and parts[i + 1] == "current":
                if i == 0:
                    return None
                return Path(*parts[:i])
    except Exception:
        return None
    return None


def _resolve_runtime_dirs(root: Path) -> tuple[Path, Path]:
    """解析数据/日志目录，避免自更新后落到 self_update/current 下。"""
    env_data_dir = os.environ.get("APP_DATA_DIR")
    env_logs_dir = os.environ.get("APP_LOGS_DIR")

    base_root = _derive_persistent_root(root) or root

    if env_data_dir:
        data_dir = Path(env_data_dir)
    else:
        if base_root.name == "data":
            data_dir = base_root
        else:
            data_dir = base_root / "data"

    if env_logs_dir:
        logs_dir = Path(env_logs_dir)
    else:
        if base_root.name == "data":
            logs_dir = base_root.parent / "logs"
        else:
            logs_dir = base_root / "logs"

    return data_dir, logs_dir


def start_webui():
    """启动 Web UI"""
    # 设置应用程序
    settings = setup_application()

    # 导入 FastAPI 应用（延迟导入以避免循环依赖）
    from src.web.app import app

    # 配置 uvicorn
    uvicorn_config = {
        "app": "src.web.app:app",
        "host": settings.webui_host,
        "port": settings.webui_port,
        "reload": settings.debug,
        "log_level": "info" if settings.debug else "warning",
        "access_log": settings.debug,
        "ws": "websockets",
    }

    logger = logging.getLogger(__name__)
    logger.info(f"启动 Web UI 在 http://{settings.webui_host}:{settings.webui_port}")
    logger.info(f"调试模式: {settings.debug}")

    # 启动服务器
    uvicorn.run(**uvicorn_config)


def _strip_guardian_args(argv: list[str]) -> list[str]:
    """移除守护进程参数，避免子进程递归启动守护。"""
    result: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg in ("--guardian",):
            continue
        if arg in ("--guardian-max-restarts", "--guardian-window-seconds", "--guardian-restart-delay"):
            skip_next = True
            continue
        result.append(arg)
    return result


def _load_guardian_update_config() -> tuple[Path, str]:
    """读取自更新目录与可执行文件名，失败时回退到默认值。"""
    work_root = Path("data/self_update")
    executable_name = "codex-register"

    try:
        _load_dotenv()
        initialize_database()
        settings = get_settings()
        if settings.self_update_work_dir:
            work_root = Path(settings.self_update_work_dir)
        if settings.self_update_executable_name:
            executable_name = settings.self_update_executable_name.strip() or executable_name
    except Exception as exc:
        print(f"[Guardian] 读取更新配置失败，使用默认值: {exc}")

    if not work_root.is_absolute():
        base_root = _derive_persistent_root(project_root) or project_root
        if base_root.name == "data" and work_root.parts and work_root.parts[0] == "data":
            work_root = base_root.parent / work_root
        else:
            work_root = base_root / work_root

    return work_root, executable_name


def _find_updated_executable(work_root: Path, executable_name: str) -> Path | None:
    """查找已下载的更新可执行文件。"""
    current_dir = work_root / "current"
    if not current_dir.exists():
        return None

    candidates: list[Path] = [current_dir / executable_name]

    if os.name == "nt" and not executable_name.lower().endswith(".exe"):
        candidates.append(current_dir / f"{executable_name}.exe")

    if executable_name != "codex-register":
        candidates.append(current_dir / "codex-register")
        if os.name == "nt":
            candidates.append(current_dir / "codex-register.exe")

    for path in candidates:
        if path.exists():
            return path

    return None


def _build_child_command(child_args: list[str], work_root: Path, executable_name: str) -> tuple[list[str], Path]:
    """构建子进程启动命令与工作目录。"""
    updated_executable = _find_updated_executable(work_root, executable_name)
    if updated_executable:
        return [str(updated_executable), *child_args], updated_executable.parent

    if getattr(sys, "frozen", False):
        return [sys.executable, *child_args], project_root

    return [sys.executable, str(Path(__file__).resolve()), *child_args], project_root


def _run_guardian(max_restarts: int, window_seconds: int, restart_delay: int) -> None:
    """守护进程：监听子进程退出并按需重启。"""
    logger = logging.getLogger("guardian")

    work_root, executable_name = _load_guardian_update_config()
    child_args = _strip_guardian_args(sys.argv[1:])

    restarts: deque[float] = deque()

    while True:
        cmd, cwd = _build_child_command(child_args, work_root, executable_name)
        env = os.environ.copy()
        if "APP_DATA_DIR" not in env or "APP_LOGS_DIR" not in env:
            data_dir, logs_dir = _resolve_runtime_dirs(project_root)
            env.setdefault("APP_DATA_DIR", str(data_dir))
            env.setdefault("APP_LOGS_DIR", str(logs_dir))
        logger.warning("守护进程启动子进程: %s", " ".join(cmd))
        proc = subprocess.Popen(cmd, cwd=str(cwd), env=env)

        try:
            exit_code = proc.wait()
        except KeyboardInterrupt:
            logger.warning("守护进程收到退出信号，正在停止子进程")
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            return

        updated_executable = _find_updated_executable(work_root, executable_name)
        if exit_code == 0 and updated_executable is None:
            logger.warning("子进程正常退出，未检测到更新，守护进程停止")
            return

        now = time.monotonic()
        restarts.append(now)
        while restarts and (now - restarts[0]) > window_seconds:
            restarts.popleft()

        if len(restarts) > max_restarts:
            logger.error("子进程在 %s 秒内退出超过 %s 次，守护进程停止", window_seconds, max_restarts)
            return

        logger.warning("子进程退出(code=%s)，%s 秒后尝试重启", exit_code, restart_delay)
        time.sleep(max(1, restart_delay))


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="OpenAI/Codex CLI 自动注册系统 Web UI")
    parser.add_argument("--host", help="监听主机")
    parser.add_argument("--port", type=int, help="监听端口")
    parser.add_argument("--debug", action="store_true", help="启用调试模式")
    parser.add_argument("--reload", action="store_true", help="启用热重载")
    parser.add_argument("--log-level", help="日志级别")
    parser.add_argument("--access-password", help="Web UI 访问密钥")
    parser.add_argument("--guardian", action="store_true", help="启用守护进程(自动重启)")
    parser.add_argument("--guardian-max-restarts", type=int, default=5, help="守护进程最大重启次数")
    parser.add_argument("--guardian-window-seconds", type=int, default=300, help="重启次数统计窗口(秒)")
    parser.add_argument("--guardian-restart-delay", type=int, default=2, help="重启间隔(秒)")
    args = parser.parse_args()

    if args.guardian:
        _run_guardian(
            max_restarts=max(1, int(args.guardian_max_restarts)),
            window_seconds=max(30, int(args.guardian_window_seconds)),
            restart_delay=max(1, int(args.guardian_restart_delay)),
        )
        return

    # 更新配置
    from src.config.settings import update_settings

    updates = {}
    if args.host:
        updates["webui_host"] = args.host
    if args.port:
        updates["webui_port"] = args.port
    if args.debug:
        updates["debug"] = args.debug
    if args.log_level:
        updates["log_level"] = args.log_level
    if args.access_password:
        updates["webui_access_password"] = args.access_password

    if updates:
        update_settings(**updates)

    # 启动 Web UI
    start_webui()


if __name__ == "__main__":
    main()
