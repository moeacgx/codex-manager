"""
配置管理 - 完全基于数据库存储
所有配置都从数据库读取，不再使用环境变量或 .env 文件
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Type, List
from enum import Enum
from pydantic import BaseModel, field_validator
from pydantic.types import SecretStr
from dataclasses import dataclass


class SettingCategory(str, Enum):
    """设置分类"""
    GENERAL = "general"
    DATABASE = "database"
    WEBUI = "webui"
    LOG = "log"
    OPENAI = "openai"
    PROXY = "proxy"
    REGISTRATION = "registration"
    EMAIL = "email"
    TEMPMAIL = "tempmail"
    CUSTOM_DOMAIN = "custom_domain"
    SECURITY = "security"
    CPA = "cpa"
    UPDATE = "update"


@dataclass
class SettingDefinition:
    """设置定义"""
    db_key: str
    default_value: Any
    category: SettingCategory
    description: str = ""
    is_secret: bool = False


def _resolve_project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent.parent


def _read_app_version() -> str:
    env_version = (os.environ.get("APP_VERSION") or os.environ.get("BUILD_VERSION") or "").strip()
    if env_version:
        return env_version
    candidates = [
        Path.cwd() / "VERSION",
        _resolve_project_root() / "VERSION",
    ]
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return ""


# 所有配置项定义（包含数据库键名、默认值、分类、描述）
SETTING_DEFINITIONS: Dict[str, SettingDefinition] = {
    # 应用信息
    "app_name": SettingDefinition(
        db_key="app.name",
        default_value="OpenAI/Codex CLI 自动注册系统",
        category=SettingCategory.GENERAL,
        description="应用名称"
    ),
    "app_version": SettingDefinition(
        db_key="app.version",
        default_value="2.0.0",
        category=SettingCategory.GENERAL,
        description="应用版本"
    ),
    "debug": SettingDefinition(
        db_key="app.debug",
        default_value=False,
        category=SettingCategory.GENERAL,
        description="调试模式"
    ),

    # 数据库配置
    "database_url": SettingDefinition(
        db_key="database.url",
        default_value="data/database.db",
        category=SettingCategory.DATABASE,
        description="数据库路径或连接字符串"
    ),

    # Web UI 配置
    "webui_host": SettingDefinition(
        db_key="webui.host",
        default_value="0.0.0.0",
        category=SettingCategory.WEBUI,
        description="Web UI 监听地址"
    ),
    "webui_port": SettingDefinition(
        db_key="webui.port",
        default_value=8000,
        category=SettingCategory.WEBUI,
        description="Web UI 监听端口"
    ),
    "webui_secret_key": SettingDefinition(
        db_key="webui.secret_key",
        default_value="your-secret-key-change-in-production",
        category=SettingCategory.WEBUI,
        description="Web UI 密钥",
        is_secret=True
    ),
    "webui_access_password": SettingDefinition(
        db_key="webui.access_password",
        default_value="admin123",
        category=SettingCategory.WEBUI,
        description="Web UI 访问密码",
        is_secret=True
    ),

    # 日志配置
    "log_level": SettingDefinition(
        db_key="log.level",
        default_value="INFO",
        category=SettingCategory.LOG,
        description="日志级别"
    ),
    "log_file": SettingDefinition(
        db_key="log.file",
        default_value="logs/app.log",
        category=SettingCategory.LOG,
        description="日志文件路径"
    ),
    "log_retention_days": SettingDefinition(
        db_key="log.retention_days",
        default_value=30,
        category=SettingCategory.LOG,
        description="日志保留天数"
    ),

    # OpenAI 配置
    "openai_client_id": SettingDefinition(
        db_key="openai.client_id",
        default_value="app_EMoamEEZ73f0CkXaXp7hrann",
        category=SettingCategory.OPENAI,
        description="OpenAI OAuth 客户端 ID"
    ),
    "openai_auth_url": SettingDefinition(
        db_key="openai.auth_url",
        default_value="https://auth.openai.com/oauth/authorize",
        category=SettingCategory.OPENAI,
        description="OpenAI OAuth 授权 URL"
    ),
    "openai_token_url": SettingDefinition(
        db_key="openai.token_url",
        default_value="https://auth.openai.com/oauth/token",
        category=SettingCategory.OPENAI,
        description="OpenAI OAuth Token URL"
    ),
    "openai_redirect_uri": SettingDefinition(
        db_key="openai.redirect_uri",
        default_value="http://localhost:1455/auth/callback",
        category=SettingCategory.OPENAI,
        description="OpenAI OAuth 回调 URI"
    ),
    "openai_scope": SettingDefinition(
        db_key="openai.scope",
        default_value="openid email profile offline_access",
        category=SettingCategory.OPENAI,
        description="OpenAI OAuth 权限范围"
    ),

    # 代理配置
    "proxy_enabled": SettingDefinition(
        db_key="proxy.enabled",
        default_value=False,
        category=SettingCategory.PROXY,
        description="是否启用代理"
    ),
    "proxy_type": SettingDefinition(
        db_key="proxy.type",
        default_value="http",
        category=SettingCategory.PROXY,
        description="代理类型 (http/socks5)"
    ),
    "proxy_host": SettingDefinition(
        db_key="proxy.host",
        default_value="127.0.0.1",
        category=SettingCategory.PROXY,
        description="代理服务器地址"
    ),
    "proxy_port": SettingDefinition(
        db_key="proxy.port",
        default_value=7890,
        category=SettingCategory.PROXY,
        description="代理服务器端口"
    ),
    "proxy_username": SettingDefinition(
        db_key="proxy.username",
        default_value="",
        category=SettingCategory.PROXY,
        description="代理用户名"
    ),
    "proxy_password": SettingDefinition(
        db_key="proxy.password",
        default_value="",
        category=SettingCategory.PROXY,
        description="代理密码",
        is_secret=True
    ),
    "proxy_dynamic_enabled": SettingDefinition(
        db_key="proxy.dynamic_enabled",
        default_value=False,
        category=SettingCategory.PROXY,
        description="是否启用动态代理"
    ),
    "proxy_dynamic_api_url": SettingDefinition(
        db_key="proxy.dynamic_api_url",
        default_value="",
        category=SettingCategory.PROXY,
        description="动态代理 API 地址，返回代理 URL 字符串"
    ),
    "proxy_dynamic_api_key": SettingDefinition(
        db_key="proxy.dynamic_api_key",
        default_value="",
        category=SettingCategory.PROXY,
        description="动态代理 API 密钥（可选）",
        is_secret=True
    ),
    "proxy_dynamic_api_key_header": SettingDefinition(
        db_key="proxy.dynamic_api_key_header",
        default_value="X-API-Key",
        category=SettingCategory.PROXY,
        description="动态代理 API 密钥请求头名称"
    ),
    "proxy_dynamic_result_field": SettingDefinition(
        db_key="proxy.dynamic_result_field",
        default_value="",
        category=SettingCategory.PROXY,
        description="从 JSON 响应中提取代理 URL 的字段路径（留空则使用响应原文）"
    ),

    # 注册配置
    "registration_max_retries": SettingDefinition(
        db_key="registration.max_retries",
        default_value=3,
        category=SettingCategory.REGISTRATION,
        description="注册最大重试次数"
    ),
    "registration_timeout": SettingDefinition(
        db_key="registration.timeout",
        default_value=120,
        category=SettingCategory.REGISTRATION,
        description="注册超时时间（秒）"
    ),
    "registration_default_password_length": SettingDefinition(
        db_key="registration.default_password_length",
        default_value=12,
        category=SettingCategory.REGISTRATION,
        description="默认密码长度"
    ),
    "registration_sleep_min": SettingDefinition(
        db_key="registration.sleep_min",
        default_value=5,
        category=SettingCategory.REGISTRATION,
        description="注册间隔最小值（秒）"
    ),
    "registration_sleep_max": SettingDefinition(
        db_key="registration.sleep_max",
        default_value=30,
        category=SettingCategory.REGISTRATION,
        description="注册间隔最大值（秒）"
    ),
    "global_concurrency": SettingDefinition(
        db_key="registration.global_concurrency",
        default_value=1,
        category=SettingCategory.REGISTRATION,
        description="全局并发线程数（控制剔除、注册等）"
    ),

    # 邮箱服务配置
    "email_service_priority": SettingDefinition(
        db_key="email.service_priority",
        default_value={"tempmail": 0, "outlook": 1, "custom_domain": 2},
        category=SettingCategory.EMAIL,
        description="邮箱服务优先级"
    ),

    # Tempmail.lol 配置
    "tempmail_base_url": SettingDefinition(
        db_key="tempmail.base_url",
        default_value="https://api.tempmail.lol/v2",
        category=SettingCategory.TEMPMAIL,
        description="Tempmail API 地址"
    ),
    "tempmail_timeout": SettingDefinition(
        db_key="tempmail.timeout",
        default_value=30,
        category=SettingCategory.TEMPMAIL,
        description="Tempmail 超时时间（秒）"
    ),
    "tempmail_max_retries": SettingDefinition(
        db_key="tempmail.max_retries",
        default_value=3,
        category=SettingCategory.TEMPMAIL,
        description="Tempmail 最大重试次数"
    ),

    # 自定义域名邮箱配置
    "custom_domain_base_url": SettingDefinition(
        db_key="custom_domain.base_url",
        default_value="",
        category=SettingCategory.CUSTOM_DOMAIN,
        description="自定义域名 API 地址"
    ),
    "custom_domain_api_key": SettingDefinition(
        db_key="custom_domain.api_key",
        default_value="",
        category=SettingCategory.CUSTOM_DOMAIN,
        description="自定义域名 API 密钥",
        is_secret=True
    ),

    # 安全配置
    "encryption_key": SettingDefinition(
        db_key="security.encryption_key",
        default_value="your-encryption-key-change-in-production",
        category=SettingCategory.SECURITY,
        description="加密密钥",
        is_secret=True
    ),

    # Team Manager 配置
    "tm_enabled": SettingDefinition(
        db_key="tm.enabled",
        default_value=False,
        category=SettingCategory.GENERAL,
        description="是否启用 Team Manager 上传"
    ),
    "tm_api_url": SettingDefinition(
        db_key="tm.api_url",
        default_value="",
        category=SettingCategory.GENERAL,
        description="Team Manager API 地址"
    ),
    "tm_api_key": SettingDefinition(
        db_key="tm.api_key",
        default_value="",
        category=SettingCategory.GENERAL,
        description="Team Manager API Key",
        is_secret=True
    ),

    # CPA 上传配置
    "cpa_enabled": SettingDefinition(
        db_key="cpa.enabled",
        default_value=False,
        category=SettingCategory.CPA,
        description="是否启用 CPA 上传"
    ),
    "cpa_api_url": SettingDefinition(
        db_key="cpa.api_url",
        default_value="",
        category=SettingCategory.CPA,
        description="CPA API 地址"
    ),
    "cpa_api_token": SettingDefinition(
        db_key="cpa.api_token",
        default_value="",
        category=SettingCategory.CPA,
        description="CPA API Token",
        is_secret=True
    ),
    "cpa_auto_check_enabled": SettingDefinition(
        db_key="cpa.auto_check_enabled",
        default_value=False,
        category=SettingCategory.CPA,
        description="是否启用定时检查并剔除失效 CPA 凭证"
    ),
    "cpa_auto_check_mode": SettingDefinition(
        db_key="cpa.auto_check_mode",
        default_value="panel",
        category=SettingCategory.CPA,
        description="自动检测方式：probe=直连穿透测活，panel=面板报错剔除"
    ),
    "cpa_auto_check_remove_401": SettingDefinition(
        db_key="cpa.auto_check_remove_401",
        default_value=False,
        category=SettingCategory.CPA,
        description="是否直接剔除面板标记为 401/403/usage_limit_reached 的凭证（跳过测活）"
    ),
    "cpa_auto_check_remove_401_interval": SettingDefinition(
        db_key="cpa.auto_check_remove_401_interval",
        default_value=3,
        category=SettingCategory.CPA,
        description="面板 401/403 快速剔除的定时间隔（分钟）"
    ),
    "cpa_auto_check_interval": SettingDefinition(
        db_key="cpa.auto_check_interval",
        default_value=60,
        category=SettingCategory.CPA,
        description="定时检查失效凭证间隔（分钟）"
    ),
    "cpa_auto_check_sleep_seconds": SettingDefinition(
        db_key="cpa.auto_check_sleep_seconds",
        default_value=1,
        category=SettingCategory.CPA,
        description="每一次测活的间隔时间（秒）"
    ),
    "cpa_auto_check_min_remaining_weekly_percent": SettingDefinition(
        db_key="cpa.auto_check_min_remaining_weekly_percent",
        default_value=20,
        category=SettingCategory.CPA,
        description="周限额剩余百分比低于该值时剔除（0 表示关闭）"
    ),
    "cpa_auto_check_test_url": SettingDefinition(
        db_key="cpa.auto_check_test_url",
        default_value="https://chatgpt.com/backend-api/wham/usage",
        category=SettingCategory.CPA,
        description="自动检测凭证存活的请求测试口"
    ),
    "cpa_auto_check_test_model": SettingDefinition(
        db_key="cpa.auto_check_test_model",
        default_value="gpt-5.2-codex",
        category=SettingCategory.CPA,
        description="测试模型名称（部分测试口需要）"
    ),
    "cpa_auto_register_enabled": SettingDefinition(
        db_key="cpa.auto_register_enabled",
        default_value=False,
        category=SettingCategory.CPA,
        description="是否启用凭证不足时自动开启注册"
    ),
    "cpa_auto_register_threshold": SettingDefinition(
        db_key="cpa.auto_register_threshold",
        default_value=10,
        category=SettingCategory.CPA,
        description="触发自动注册的凭证阈值"
    ),
    "cpa_auto_register_batch_count": SettingDefinition(
        db_key="cpa.auto_register_batch_count",
        default_value=5,
        category=SettingCategory.CPA,
        description="每次自动补充注册的数量"
    ),
    "cpa_auto_register_email_service": SettingDefinition(
        db_key="cpa.auto_register_email_service",
        default_value="",
        category=SettingCategory.CPA,
        description="自动补充注册使用的邮箱服务组合标记"
    ),
    "cpa_auto_register_token_mode": SettingDefinition(
        db_key="cpa.auto_register_token_mode",
        default_value="auto",
        category=SettingCategory.CPA,
        description="自动补充注册的 Token 获取方式（session / oauth / auto）"
    ),

    # 验证码配置
    "email_code_timeout": SettingDefinition(
        db_key="email_code.timeout",
        default_value=120,
        category=SettingCategory.EMAIL,
        description="验证码等待超时时间（秒）"
    ),
    "email_code_poll_interval": SettingDefinition(
        db_key="email_code.poll_interval",
        default_value=3,
        category=SettingCategory.EMAIL,
        description="验证码轮询间隔（秒）"
    ),

    # Outlook 配置
    "outlook_provider_priority": SettingDefinition(
        db_key="outlook.provider_priority",
        default_value=["imap_old", "imap_new", "graph_api"],
        category=SettingCategory.EMAIL,
        description="Outlook 提供者优先级"
    ),
    "outlook_health_failure_threshold": SettingDefinition(
        db_key="outlook.health_failure_threshold",
        default_value=5,
        category=SettingCategory.EMAIL,
        description="Outlook 提供者连续失败次数阈值"
    ),
    "outlook_health_disable_duration": SettingDefinition(
        db_key="outlook.health_disable_duration",
        default_value=60,
        category=SettingCategory.EMAIL,
        description="Outlook 提供者禁用时长（秒）"
    ),
    "outlook_default_client_id": SettingDefinition(
        db_key="outlook.default_client_id",
        default_value="24d9a0ed-8787-4584-883c-2fd79308940a",
        category=SettingCategory.EMAIL,
        description="Outlook OAuth 默认 Client ID"
    ),

    # 更新与自更新配置
    "update_repository": SettingDefinition(
        db_key="update.repository",
        default_value="moeacgx/codex-manager",
        category=SettingCategory.UPDATE,
        description="更新检查的 GitHub 仓库 (owner/repo)"
    ),
    "update_github_token": SettingDefinition(
        db_key="update.github_token",
        default_value="",
        category=SettingCategory.UPDATE,
        description="GitHub Release 访问令牌（可选）",
        is_secret=True
    ),
    "update_check_interval_seconds": SettingDefinition(
        db_key="update.check_interval_seconds",
        default_value=600,
        category=SettingCategory.UPDATE,
        description="更新检查间隔（秒）"
    ),
    "update_http_timeout_seconds": SettingDefinition(
        db_key="update.http_timeout_seconds",
        default_value=15,
        category=SettingCategory.UPDATE,
        description="更新 HTTP 超时（秒）"
    ),
    "update_notify_enabled": SettingDefinition(
        db_key="update.notify_enabled",
        default_value=True,
        category=SettingCategory.UPDATE,
        description="是否启用更新提醒"
    ),
    "self_update_enabled": SettingDefinition(
        db_key="update.self_enabled",
        default_value=True,
        category=SettingCategory.UPDATE,
        description="是否启用一键自更新"
    ),
    "self_update_docker_only": SettingDefinition(
        db_key="update.self_docker_only",
        default_value=True,
        category=SettingCategory.UPDATE,
        description="仅允许在 Docker 容器内自更新"
    ),
    "self_update_work_dir": SettingDefinition(
        db_key="update.self_work_dir",
        default_value="data/self_update",
        category=SettingCategory.UPDATE,
        description="自更新工作目录"
    ),
    "self_update_executable_name": SettingDefinition(
        db_key="update.self_executable_name",
        default_value="codex-register",
        category=SettingCategory.UPDATE,
        description="自更新可执行文件名"
    ),
    "self_update_asset_prefix": SettingDefinition(
        db_key="update.self_asset_prefix",
        default_value="codex-register",
        category=SettingCategory.UPDATE,
        description="Release 资产名称前缀"
    ),
    "self_update_restart_delay_seconds": SettingDefinition(
        db_key="update.self_restart_delay_seconds",
        default_value=2,
        category=SettingCategory.UPDATE,
        description="自更新后重启延迟（秒）"
    ),
}

# 属性名到数据库键名的映射（用于向后兼容）
DB_SETTING_KEYS = {name: defn.db_key for name, defn in SETTING_DEFINITIONS.items()}

# 类型定义映射
SETTING_TYPES: Dict[str, Type] = {
    "debug": bool,
    "webui_port": int,
    "log_retention_days": int,
    "proxy_enabled": bool,
    "proxy_port": int,
    "proxy_dynamic_enabled": bool,
    "registration_max_retries": int,
    "registration_timeout": int,
    "registration_default_password_length": int,
    "registration_sleep_min": int,
    "registration_sleep_max": int,
    "global_concurrency": int,
    "email_service_priority": dict,
    "tempmail_timeout": int,
    "tempmail_max_retries": int,
    "tm_enabled": bool,
    "cpa_enabled": bool,
    "cpa_auto_check_enabled": bool,
    "cpa_auto_check_mode": str,
    "cpa_auto_check_remove_401": bool,
    "cpa_auto_check_remove_401_interval": int,
    "cpa_auto_check_interval": int,
    "cpa_auto_check_sleep_seconds": int,
    "cpa_auto_check_min_remaining_weekly_percent": int,
    "cpa_auto_check_test_url": str,
    "cpa_auto_check_test_model": str,
    "cpa_auto_register_enabled": bool,
    "cpa_auto_register_threshold": int,
    "cpa_auto_register_batch_count": int,
    "cpa_auto_register_email_service": str,
    "cpa_auto_register_token_mode": str,
    "email_code_timeout": int,
    "email_code_poll_interval": int,
    "outlook_provider_priority": list,
    "outlook_health_failure_threshold": int,
    "outlook_health_disable_duration": int,
    "update_repository": str,
    "update_github_token": str,
    "update_check_interval_seconds": int,
    "update_http_timeout_seconds": int,
    "update_notify_enabled": bool,
    "self_update_enabled": bool,
    "self_update_docker_only": bool,
    "self_update_work_dir": str,
    "self_update_executable_name": str,
    "self_update_asset_prefix": str,
    "self_update_restart_delay_seconds": int,
}

# 需要作为 SecretStr 处理的字段
SECRET_FIELDS = {name for name, defn in SETTING_DEFINITIONS.items() if defn.is_secret}


def _convert_value(attr_name: str, value: str) -> Any:
    """将数据库字符串值转换为正确的类型"""
    if attr_name in SECRET_FIELDS:
        return SecretStr(value) if value else SecretStr("")

    target_type = SETTING_TYPES.get(attr_name, str)

    if target_type == bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")
    elif target_type == int:
        if isinstance(value, int):
            return value
        return int(value) if value else 0
    elif target_type == dict:
        if isinstance(value, dict):
            return value
        if not value:
            return {}
        import json
        import ast
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            try:
                return ast.literal_eval(value)
            except Exception:
                return {}
    elif target_type == list:
        if isinstance(value, list):
            return value
        if not value:
            return []
        import json
        import ast
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            try:
                return ast.literal_eval(value)
            except Exception:
                return []
    else:
        return value


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def _value_to_string(value: Any) -> str:
    """将值转换为数据库存储的字符串"""
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (dict, list)):
        import json
        return json.dumps(value)
    elif value is None:
        return ""
    else:
        return str(value)


def init_default_settings() -> None:
    """
    初始化数据库中的默认设置
    如果设置项不存在，则创建并设置默认值
    """
    try:
        from ..database.session import get_db
        from ..database.crud import get_setting, set_setting

        with get_db() as db:
            for attr_name, defn in SETTING_DEFINITIONS.items():
                existing = get_setting(db, defn.db_key)
                if not existing:
                    default_value = defn.default_value
                    if attr_name == "database_url":
                        env_url = os.environ.get("APP_DATABASE_URL") or os.environ.get("DATABASE_URL")
                        if env_url:
                            default_value = _normalize_database_url(env_url)
                    default_value = _value_to_string(default_value)
                    set_setting(
                        db,
                        defn.db_key,
                        default_value,
                        category=defn.category.value,
                        description=defn.description
                    )
                    print(f"[Settings] 初始化默认设置: {defn.db_key} = {default_value if not defn.is_secret else '***'}")
    except Exception as e:
        if "未初始化" not in str(e):
            print(f"[Settings] 初始化默认设置失败: {e}")


def _load_settings_from_db() -> Dict[str, Any]:
    """从数据库加载所有设置"""
    try:
        from ..database.session import get_db
        from ..database.crud import get_setting

        settings_dict = {}
        with get_db() as db:
            for attr_name, defn in SETTING_DEFINITIONS.items():
                db_setting = get_setting(db, defn.db_key)
                if db_setting:
                    settings_dict[attr_name] = _convert_value(attr_name, db_setting.value)
                else:
                    # 数据库中没有此设置，使用默认值
                    settings_dict[attr_name] = _convert_value(attr_name, _value_to_string(defn.default_value))
            env_url = os.environ.get("APP_DATABASE_URL") or os.environ.get("DATABASE_URL")
            if env_url:
                settings_dict["database_url"] = _normalize_database_url(env_url)
            env_host = os.environ.get("APP_HOST")
            if env_host:
                settings_dict["webui_host"] = env_host
            env_port = os.environ.get("APP_PORT")
            if env_port:
                try:
                    settings_dict["webui_port"] = int(env_port)
                except ValueError:
                    pass
            env_password = os.environ.get("APP_ACCESS_PASSWORD")
            if env_password:
                settings_dict["webui_access_password"] = env_password
            env_update_repo = os.environ.get("APP_UPDATE_REPOSITORY")
            if env_update_repo:
                settings_dict["update_repository"] = env_update_repo
            env_data_dir = os.environ.get("APP_DATA_DIR")
            if env_data_dir:
                db_url = settings_dict.get("database_url")
                if isinstance(db_url, str):
                    if db_url.startswith("sqlite:///"):
                        db_path = db_url[10:]
                        if not os.path.isabs(db_path):
                            db_name = Path(db_path).name or "database.db"
                            settings_dict["database_url"] = f"sqlite:///{Path(env_data_dir) / db_name}"
                    elif "://" not in db_url:
                        db_name = Path(db_url).name or "database.db"
                        settings_dict["database_url"] = f"sqlite:///{Path(env_data_dir) / db_name}"
        return settings_dict
    except Exception as e:
        if "未初始化" not in str(e):
            print(f"[Settings] 从数据库加载设置失败: {e}，使用默认值")
        return {name: defn.default_value for name, defn in SETTING_DEFINITIONS.items()}


def _save_settings_to_db(**kwargs) -> None:
    """保存设置到数据库"""
    try:
        from ..database.session import get_db
        from ..database.crud import set_setting

        with get_db() as db:
            for attr_name, value in kwargs.items():
                if attr_name in SETTING_DEFINITIONS:
                    defn = SETTING_DEFINITIONS[attr_name]
                    str_value = _value_to_string(value)
                    set_setting(
                        db,
                        defn.db_key,
                        str_value,
                        category=defn.category.value,
                        description=defn.description
                    )
    except Exception as e:
        if "未初始化" not in str(e):
            print(f"[Settings] 保存设置到数据库失败: {e}")


class Settings(BaseModel):
    """
    应用配置 - 完全基于数据库存储
    """

    # 应用信息
    app_name: str = "OpenAI/Codex CLI 自动注册系统"
    app_version: str = "2.0.7"
    debug: bool = False

    # 数据库配置
    database_url: str = "data/database.db"

    @field_validator('database_url', mode='before')
    @classmethod
    def validate_database_url(cls, v):
        if isinstance(v, str):
            if v.startswith(("postgres://", "postgresql://")):
                return _normalize_database_url(v)
            if v.startswith(("postgresql+psycopg://", "postgresql+psycopg2://")):
                return v
        if isinstance(v, str) and v.startswith("sqlite:///"):
            return v
        if isinstance(v, str) and not v.startswith(("sqlite:///", "postgresql://", "postgresql+psycopg://", "postgresql+psycopg2://", "mysql://")):
            # 如果是文件路径，转换为 SQLite URL
            if os.path.isabs(v) or ":/" not in v:
                return f"sqlite:///{v}"
        return v

    # Web UI 配置
    webui_host: str = "0.0.0.0"
    webui_port: int = 8000
    webui_secret_key: SecretStr = SecretStr("your-secret-key-change-in-production")
    webui_access_password: SecretStr = SecretStr("admin123")

    # 日志配置
    log_level: str = "INFO"
    log_file: str = "logs/app.log"
    log_retention_days: int = 30

    # OpenAI 配置
    openai_client_id: str = "app_EMoamEEZ73f0CkXaXp7hrann"
    openai_auth_url: str = "https://auth.openai.com/oauth/authorize"
    openai_token_url: str = "https://auth.openai.com/oauth/token"
    openai_redirect_uri: str = "http://localhost:1455/auth/callback"
    openai_scope: str = "openid email profile offline_access"

    # 代理配置
    proxy_enabled: bool = False
    proxy_type: str = "http"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 7890
    proxy_username: Optional[str] = None
    proxy_password: Optional[SecretStr] = None
    proxy_dynamic_enabled: bool = False
    proxy_dynamic_api_url: str = ""
    proxy_dynamic_api_key: Optional[SecretStr] = None
    proxy_dynamic_api_key_header: str = "X-API-Key"
    proxy_dynamic_result_field: str = ""

    @property
    def proxy_url(self) -> Optional[str]:
        """获取完整的代理 URL"""
        if not self.proxy_enabled:
            return None

        if self.proxy_type == "http":
            scheme = "http"
        elif self.proxy_type == "socks5":
            scheme = "socks5"
        else:
            return None

        auth = ""
        if self.proxy_username and self.proxy_password:
            auth = f"{self.proxy_username}:{self.proxy_password.get_secret_value()}@"

        return f"{scheme}://{auth}{self.proxy_host}:{self.proxy_port}"

    # 注册配置
    registration_max_retries: int = 3
    registration_timeout: int = 120
    registration_default_password_length: int = 12
    registration_sleep_min: int = 5
    registration_sleep_max: int = 30
    global_concurrency: int = 1

    # 邮箱服务配置
    email_service_priority: Dict[str, int] = {"tempmail": 0, "outlook": 1, "custom_domain": 2}

    # Tempmail.lol 配置
    tempmail_base_url: str = "https://api.tempmail.lol/v2"
    tempmail_timeout: int = 30
    tempmail_max_retries: int = 3

    # 自定义域名邮箱配置
    custom_domain_base_url: str = ""
    custom_domain_api_key: Optional[SecretStr] = None

    # 安全配置
    encryption_key: SecretStr = SecretStr("your-encryption-key-change-in-production")

    # Team Manager 配置
    tm_enabled: bool = False
    tm_api_url: str = ""
    tm_api_key: Optional[SecretStr] = None

    # CPA 上传配置
    cpa_enabled: bool = False
    cpa_api_url: str = ""
    cpa_api_token: SecretStr = SecretStr("")
    cpa_auto_check_enabled: bool = False
    cpa_auto_check_mode: str = "panel"
    cpa_auto_check_remove_401: bool = False
    cpa_auto_check_remove_401_interval: int = 3
    cpa_auto_check_interval: int = 60
    cpa_auto_check_sleep_seconds: int = 1
    cpa_auto_check_min_remaining_weekly_percent: int = 20
    cpa_auto_check_test_url: str = "https://chatgpt.com/backend-api/wham/usage"
    cpa_auto_check_test_model: str = "gpt-5.2-codex"
    cpa_auto_register_enabled: bool = False
    cpa_auto_register_threshold: int = 10
    cpa_auto_register_batch_count: int = 5
    cpa_auto_register_email_service: str = ""
    cpa_auto_register_token_mode: str = "auto"

    # 验证码配置
    email_code_timeout: int = 120
    email_code_poll_interval: int = 3

    # Outlook 配置
    outlook_provider_priority: List[str] = ["imap_old", "imap_new", "graph_api"]
    outlook_health_failure_threshold: int = 5
    outlook_health_disable_duration: int = 60
    outlook_default_client_id: str = "24d9a0ed-8787-4584-883c-2fd79308940a"

    # 更新配置
    update_repository: str = "moeacgx/codex-manager"
    update_github_token: Optional[SecretStr] = None
    update_check_interval_seconds: int = 600
    update_http_timeout_seconds: int = 15
    update_notify_enabled: bool = True

    # 自更新配置
    self_update_enabled: bool = True
    self_update_docker_only: bool = True
    self_update_work_dir: str = "data/self_update"
    self_update_executable_name: str = "codex-register"
    self_update_asset_prefix: str = "codex-register"
    self_update_restart_delay_seconds: int = 2


# 全局配置实例
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    获取全局配置实例（单例模式）
    完全从数据库加载配置
    """
    global _settings
    if _settings is None:
        # 先初始化默认设置（如果数据库中没有的话）
        init_default_settings()
        # 从数据库加载所有设置
        settings_dict = _load_settings_from_db()
        file_version = _read_app_version()
        if file_version:
            settings_dict["app_version"] = file_version
        _settings = Settings(**settings_dict)
    else:
        file_version = _read_app_version()
        if file_version and _settings.app_version != file_version:
            _settings.app_version = file_version
    return _settings


def update_settings(**kwargs) -> Settings:
    """
    更新配置并保存到数据库
    """
    global _settings
    if _settings is None:
        _settings = get_settings()

    # 创建新的配置实例
    updated_data = _settings.model_dump()
    updated_data.update(kwargs)
    _settings = Settings(**updated_data)

    # 保存到数据库
    _save_settings_to_db(**kwargs)

    return _settings


def get_database_url() -> str:
    """
    获取数据库 URL（处理相对路径）
    """
    settings = get_settings()
    url = settings.database_url

    # 如果 URL 是相对路径，转换为绝对路径
    if url.startswith("sqlite:///"):
        path = url[10:]  # 移除 "sqlite:///"
        if not os.path.isabs(path):
            # 转换为相对于项目根目录的路径
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            abs_path = os.path.join(project_root, path)
            return f"sqlite:///{abs_path}"

    return url


def get_setting_definition(attr_name: str) -> Optional[SettingDefinition]:
    """获取设置项的定义信息"""
    return SETTING_DEFINITIONS.get(attr_name)


def get_all_setting_definitions() -> Dict[str, SettingDefinition]:
    """获取所有设置项的定义"""
    return SETTING_DEFINITIONS.copy()
