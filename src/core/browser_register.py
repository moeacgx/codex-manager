import base64
import html
import json
import logging
import os
import random
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlparse
from zoneinfo import ZoneInfo

from curl_cffi import requests as cffi_requests

from ..services.base import BaseEmailService
from ..config.constants import (
    DEFAULT_PASSWORD_LENGTH,
    OPENAI_API_ENDPOINTS,
    OTP_CODE_PATTERN,
    PASSWORD_CHARSET,
    generate_random_user_info,
)
from .register import RegistrationResult
from .utils import get_logs_dir

logger = logging.getLogger(__name__)
_SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")

class BrowserRegistrationEngine:
    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger = None,
        task_uuid: Optional[str] = None,
        oauth_http_first: Optional[bool] = None,
        oauth_http_only: Optional[bool] = None,
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict] = None
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None

        debug_flag = str(os.environ.get("BROWSER_DEBUG", "")).lower() in ("1", "true", "yes", "on")
        keep_open_flag = str(os.environ.get("BROWSER_KEEP_OPEN", "")).lower() in ("1", "true", "yes", "on")
        pause_flag = str(os.environ.get("BROWSER_STEP_PAUSE", "")).lower() in ("1", "true", "yes", "on")
        refresh_flag = str(os.environ.get("BROWSER_AUTO_REFRESH", "1")).lower() in ("1", "true", "yes", "on")
        skip_oauth_flag = str(os.environ.get("BROWSER_SKIP_OAUTH", "")).lower() in ("1", "true", "yes", "on")
        headless_env = str(os.environ.get("BROWSER_HEADLESS", "")).strip().lower()
        # 项目已切换为仅支持桌面有头运行：忽略无头配置，统一强制有头。
        headless_flag = False
        self.debug_enabled = debug_flag
        self.keep_browser_open = keep_open_flag or debug_flag
        self.step_pause = pause_flag
        self.auto_refresh_on_stuck = refresh_flag
        self.skip_oauth = skip_oauth_flag
        self.headless = headless_flag
        self.oauth_http_first = str(os.environ.get("BROWSER_OAUTH_HTTP_FIRST", "0")).lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        self.oauth_http_only = str(os.environ.get("BROWSER_OAUTH_HTTP_ONLY", "0")).lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        if oauth_http_first is not None:
            self.oauth_http_first = bool(oauth_http_first)
        if oauth_http_only is not None:
            self.oauth_http_only = bool(oauth_http_only)
        if self.oauth_http_only:
            self.oauth_http_first = True
        # 延迟与超时倍率（用于减速）
        try:
            self.delay_multiplier = float(os.environ.get("BROWSER_DELAY_MULTIPLIER", "1.0"))
        except Exception:
            self.delay_multiplier = 1.0
        try:
            self.timeout_multiplier = float(os.environ.get("BROWSER_TIMEOUT_MULTIPLIER", "1.0"))
        except Exception:
            self.timeout_multiplier = 1.0
        try:
            self.delay_min = float(os.environ.get("BROWSER_DELAY_MIN", "0"))
        except Exception:
            self.delay_min = 0.0
        try:
            self.delay_max = float(os.environ.get("BROWSER_DELAY_MAX", "0"))
        except Exception:
            self.delay_max = 0.0
        if self.delay_multiplier <= 0:
            self.delay_multiplier = 1.0
        if self.timeout_multiplier <= 0:
            self.timeout_multiplier = 1.0
        if self.delay_min < 0:
            self.delay_min = 0.0
        if self.delay_max < 0:
            self.delay_max = 0.0
        # 注册成功后进入 OAuth 前的节流等待（可选）
        try:
            self.oauth_pre_delay_seconds = max(
                0.0, float(os.environ.get("BROWSER_OAUTH_PRE_DELAY_SECONDS", "0"))
            )
        except Exception:
            self.oauth_pre_delay_seconds = 0.0
        try:
            self.oauth_pre_delay_jitter_seconds = max(
                0.0, float(os.environ.get("BROWSER_OAUTH_PRE_DELAY_JITTER_SECONDS", "0"))
            )
        except Exception:
            self.oauth_pre_delay_jitter_seconds = 0.0
        if headless_env in ("1", "true", "yes", "on"):
            self._log("已禁用无头模式配置（BROWSER_HEADLESS），当前固定为有头桌面运行", "warning")
        save_elements_env = str(os.environ.get("BROWSER_SAVE_PAGE_ELEMENTS", "")).strip().lower()
        if save_elements_env in ("1", "true", "yes", "on"):
            page_dump_enabled = True
        elif save_elements_env in ("0", "false", "no", "off", ""):
            page_dump_enabled = False
        else:
            # 非法值按关闭处理，避免默认产生调试文件。
            page_dump_enabled = False
        self.page_dump_enabled = page_dump_enabled
        self.page_dump_include_screenshot = str(
            os.environ.get("BROWSER_PAGE_DUMP_SCREENSHOT", "0")
        ).lower() in ("1", "true", "yes", "on")
        try:
            self.page_dump_max_html_chars = max(
                20_000, int(os.environ.get("BROWSER_PAGE_DUMP_MAX_HTML", "350000"))
            )
        except Exception:
            self.page_dump_max_html_chars = 350_000
        try:
            self.page_dump_max_items = max(
                20, min(1000, int(os.environ.get("BROWSER_PAGE_DUMP_MAX_ITEMS", "180")))
            )
        except Exception:
            self.page_dump_max_items = 180
        self.page_dump_dir: Optional[Path] = None
        self._page_dump_index = 0

    def _debug_pause(self, page, reason: str):
        if not self.step_pause:
            return
        self._log(f"调试暂停: {reason}，请在浏览器手动处理后继续", "warning")
        try:
            page.pause()
        except Exception:
            # 兜底等待，避免阻断逻辑
            page.wait_for_timeout(self._scale_timeout(30000))

    def _maybe_refresh(self, page, reason: str, refresh_state: Dict[str, int], limit: int = 2) -> bool:
        if not self.auto_refresh_on_stuck:
            return False
        count = refresh_state.get("count", 0)
        if count >= limit:
            return False
        refresh_state["count"] = count + 1
        self._log(f"页面卡住，刷新重试 ({refresh_state['count']}/{limit}): {reason}", "warning")
        try:
            page.reload(wait_until="commit")
            page.wait_for_timeout(self._scale_timeout(3000))
        except Exception as e:
            self._log(f"刷新失败: {e}", "warning")
        return True

    def _safe_click(self, page, selector: str, refresh_state: Dict[str, int], label: str, timeout: int = 10000) -> bool:
        scaled_timeout = self._scale_timeout(timeout)
        try:
            page.click(selector, timeout=scaled_timeout)
            return True
        except Exception as e:
            self._log(f"{label}点击失败: {e}", "warning")
            if self._maybe_refresh(page, f"{label}点击失败", refresh_state):
                try:
                    page.click(selector, timeout=scaled_timeout)
                    return True
                except Exception as e2:
                    self._log(f"{label}点击重试失败: {e2}", "warning")
            return False

    def _set_hidden_birthday(self, page, value: str) -> bool:
        try:
            page.eval_on_selector(
                "input[name='birthday'], input[name='birthdate']",
                "(el, val) => { el.value = val; el.dispatchEvent(new Event('input', {bubbles: true})); el.dispatchEvent(new Event('change', {bubbles: true})); }",
                value
            )
            return True
        except Exception:
            return False

    def _fill_react_aria_segment(self, page, locator, value: str) -> bool:
        if locator.count() <= 0:
            return False
        target = locator.first

        def _value_ok() -> bool:
            try:
                text = (target.inner_text() or target.text_content() or "").strip()
                if not text:
                    return False
                text_digits = re.sub(r"\D", "", text)
                val_digits = re.sub(r"\D", "", value)
                return text_digits == val_digits or text == value
            except Exception:
                return False

        try:
            target.scroll_into_view_if_needed()
        except Exception:
            pass

        # 方式1：Playwright 的 fill（支持 contenteditable）
        try:
            target.click(force=True)
            target.fill(value)
            if _value_ok():
                return True
        except Exception:
            pass

        # 方式2：模拟键盘输入
        try:
            target.click(force=True)
            try:
                page.keyboard.press("Control+A")
            except Exception:
                page.keyboard.press("Meta+A")
            page.keyboard.type(value, delay=50)
            if _value_ok():
                return True
        except Exception:
            pass

        # 方式3：JS 强制写入 + 事件触发
        try:
            target.evaluate(
                "(el, val) => { el.focus(); el.textContent = ''; el.innerText = val; "
                "el.setAttribute('aria-valuenow', String(parseInt(val, 10) || val)); "
                "el.setAttribute('aria-valuetext', val); "
                "el.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: val})); "
                "el.dispatchEvent(new Event('change', {bubbles: true})); "
                "el.dispatchEvent(new Event('blur', {bubbles: true})); }",
                value
            )
            if _value_ok():
                return True
        except Exception:
            pass

        # 方式4：execCommand 兜底
        try:
            target.evaluate(
                "(el, val) => { el.focus(); document.execCommand('selectAll'); document.execCommand('insertText', false, val); "
                "el.dispatchEvent(new Event('input', {bubbles: true})); el.dispatchEvent(new Event('change', {bubbles: true})); }",
                value
            )
            if _value_ok():
                return True
        except Exception:
            return False

        return False

    def _force_set_react_aria_birthday(self, page, birthdate: str) -> bool:
        try:
            ok = page.evaluate(
                """
                (birthdate) => {
                    const parts = birthdate.split('-');
                    if (parts.length < 3) return false;
                    const y = parts[0];
                    const m = String(parseInt(parts[1], 10)).padStart(2, '0');
                    const d = String(parseInt(parts[2], 10)).padStart(2, '0');
                    const setSeg = (type, val) => {
                        const el = document.querySelector(`div[role=\"spinbutton\"][data-type=\"${type}\"], div[data-type=\"${type}\"]`);
                        if (!el) return false;
                        el.focus();
                        el.textContent = val;
                        el.innerText = val;
                        el.setAttribute('aria-valuenow', String(parseInt(val, 10) || val));
                        el.setAttribute('aria-valuetext', val);
                        el.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: val}));
                        el.dispatchEvent(new Event('change', {bubbles: true}));
                        el.dispatchEvent(new Event('blur', {bubbles: true}));
                        return true;
                    };
                    const ok1 = setSeg('year', y);
                    const ok2 = setSeg('month', m);
                    const ok3 = setSeg('day', d);
                    const hidden = document.querySelector("input[name='birthday'], input[name='birthdate']");
                    if (hidden) {
                        hidden.value = `${y}-${m}-${d}`;
                        hidden.dispatchEvent(new Event('input', {bubbles: true}));
                        hidden.dispatchEvent(new Event('change', {bubbles: true}));
                    }
                    return ok1 && ok2 && ok3;
                }
                """,
                birthdate
            )
            return bool(ok)
        except Exception as e:
            self._log(f"React-Aria 生日JS写入失败: {e}", "warning")
            return False

    def _handle_oauth_relogin(self, page) -> bool:
        """处理 OAuth 再次登录流程（输入邮箱/密码/验证码及打回错误重试）。"""
        handled = False
        otp_log_printed = False
        otp_phase_started_at: Optional[float] = None
        otp_submitted_once = False
        cached_otp_code: Optional[str] = None
        try:
            # 使用循环应对多步可能出现的超时错误重试
            for _ in range(4):
                step_acted = False

                # 已进入 consent 页面则无需继续登录/验证码流程
                if self._is_oauth_consent_page(page):
                    break
                
                # 处理 Operation Timed Out 错误重试
                retry_loc = page.locator("button:has-text('Retry'), a:has-text('Retry'), button:has-text('Try again'), a:has-text('Try again'), button:has-text('重试'), a:has-text('重试'), button[data-dd-action-name='Try again']")
                if retry_loc.count() > 0 and retry_loc.first.is_visible():
                    self._log("检测到 OAuth 登录页显示 Operation timed out 或错误，直接点击重试...", "warning")
                    retry_loc.first.click()
                    step_acted = True
                    handled = True
                    self._random_delay(2.0, 3.0)


                if page.locator("input[type='email']").count() > 0 and page.locator("input[type='email']").first.is_visible():
                    self._log("检测到 OAuth 登录页，填写邮箱...", "warning")
                    try:
                        page.fill("input[type='email']", self.email)
                        page.click("button[type='submit']")
                        step_acted = True
                        handled = True
                        self._random_delay(1.5, 3.0)
                    except Exception as e:
                        self._log(f"OAuth 邮箱输入暂不可用，稍后重试: {str(e).splitlines()[0][:180]}", "warning")

                if page.locator("input[type='password']").count() > 0 and page.locator("input[type='password']").first.is_visible():
                    self._log("OAuth 登录页要求密码，自动填写...", "warning")
                    try:
                        page.fill("input[type='password']", self.password)
                        page.click("button[type='submit']")
                        step_acted = True
                        handled = True
                        self._random_delay(1.5, 3.0)
                    except Exception as e:
                        self._log(f"OAuth 密码输入暂不可用，稍后重试: {str(e).splitlines()[0][:180]}", "warning")

                is_otp = self._is_oauth_otp_page(page)
                if is_otp:
                    if otp_submitted_once:
                        self._log("验证码已提交，等待页面跳转到授权页...", "info")
                        try:
                            page.wait_for_timeout(self._scale_timeout(1500))
                        except Exception:
                            pass
                        if self._is_oauth_consent_page(page):
                            break
                        # 避免同一轮重复拉取验证码导致长时间卡住
                        break

                    if cached_otp_code:
                        if self._fill_oauth_otp_code(page, cached_otp_code):
                            otp_submitted_once = True
                            step_acted = True
                            handled = True
                            self._random_delay(0.8, 1.5)
                            continue
                        self._log("复用上一次验证码填充仍失败，等待页面稳定后由下一轮重试", "warning")
                        step_acted = True
                        handled = True
                        break

                    if otp_phase_started_at is None:
                        otp_phase_started_at = time.time()
                    self._otp_sent_at = otp_phase_started_at
                    if not otp_log_printed:
                        self._log("OAuth 登录需要邮箱验证码，开始获取...", "warning")
                        otp_log_printed = True
                    email_id = self.email_info.get("service_id") if self.email_info else None
                    otp_code = self.email_service.get_verification_code(
                        email=self.email,
                        email_id=email_id,
                        timeout=120,
                        pattern=OTP_CODE_PATTERN,
                        otp_sent_at=self._otp_sent_at,
                    )
                    if otp_code and self._fill_oauth_otp_code(page, str(otp_code)):
                        cached_otp_code = str(otp_code)
                        otp_submitted_once = True
                        step_acted = True
                        handled = True
                        self._random_delay(1.0, 2.0)
                        continue
                    elif otp_code:
                        cached_otp_code = str(otp_code)
                        self._log("检测到验证码页面但未找到可填写输入框，暂不点击继续，等待页面稳定后重试", "warning")
                        step_acted = True
                        handled = True
                        try:
                            page.wait_for_timeout(600)
                        except Exception:
                            pass
                
                # 如果当前循环没有做任何操作，则认为页面已经进入了等待跳转状态，跳出
                if not step_acted:
                    break
        except Exception as e:
            # Playwright 异常会附带超长 call log，这里仅保留首行避免刷屏。
            err = str(e).splitlines()[0][:260]
            self._log(f"OAuth 再登录处理异常: {err}", "warning")
        return handled

    def _build_oauth_authorize_url(self, auth_url: str) -> str:
        """保留 prompt=login，强制重新登录（不复用已登录会话）。"""
        return auth_url

    def _extract_oauth_callback_from_text(self, text: str) -> str:
        if not text:
            return ""
        patterns = (
            r"https?://localhost(?::\d+)?/auth/callback[^\s\"'<>]+",
            r"/auth/callback\?[^\"'<>\\s]+",
        )
        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                candidate = (match or "").strip().replace("&amp;", "&")
                if not candidate:
                    continue
                if candidate.startswith("/auth/callback"):
                    candidate = f"http://localhost:1455{candidate}"
                if "code=" in candidate and "state=" in candidate:
                    return candidate
        return ""

    def _extract_code_from_url(self, url: str) -> str:
        if not url:
            return ""
        candidate = html.unescape(str(url)).replace("\\u0026", "&").replace("&amp;", "&")
        try:
            code = parse_qs(urlparse(candidate).query).get("code", [""])[0]
            if code:
                return str(code).strip()
        except Exception:
            pass
        try:
            m = re.search(r"[?&]code=([^&#]+)", candidate)
            if m:
                return unquote(m.group(1))
        except Exception:
            pass
        return ""

    def _extract_cookie_values_from_session(self, session: cffi_requests.Session, name: str) -> list[str]:
        values: list[str] = []
        if not name:
            return values
        try:
            for cookie in session.cookies:
                if str(getattr(cookie, "name", "") or "") == name:
                    value = str(getattr(cookie, "value", "") or "").strip()
                    if value:
                        values.append(value)
        except Exception:
            pass
        try:
            direct = session.cookies.get(name)
            direct_text = str(direct or "").strip()
            if direct_text:
                values.append(direct_text)
        except Exception:
            pass
        # 去重保持顺序
        seen = set()
        uniq: list[str] = []
        for v in values:
            if v in seen:
                continue
            seen.add(v)
            uniq.append(v)
        return uniq

    def _decode_oauth_session_cookie(self, raw_value: str) -> Optional[Dict[str, Any]]:
        """解析 oai-client-auth-session cookie（兼容 URL 编码/引号/JWT 片段）。"""
        if not raw_value:
            return None
        candidates = [raw_value]
        try:
            decoded = unquote(raw_value)
            if decoded != raw_value:
                candidates.append(decoded)
        except Exception:
            pass

        for candidate in candidates:
            try:
                value = str(candidate).strip()
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                part = value.split(".")[1] if value.count(".") >= 2 else (value.split(".")[0] if "." in value else value)
                pad = "=" * ((4 - (len(part) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((part + pad).encode("ascii"))
                data = json.loads(decoded.decode("utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
        return None

    def _http_get_workspace_id(self, session: cffi_requests.Session) -> str:
        """从 OAuth 会话中提取 workspace_id。"""
        try:
            for cookie_name in ("oai-client-auth-session", "oai_client_auth_session"):
                cookie_values = self._extract_cookie_values_from_session(session, cookie_name)
                for raw_cookie in cookie_values:
                    payload = self._decode_oauth_session_cookie(raw_cookie)
                    if not isinstance(payload, dict):
                        continue
                    workspaces = payload.get("workspaces") or []
                    if isinstance(workspaces, list) and workspaces:
                        ws_id = str((workspaces[0] or {}).get("id") or "").strip()
                        if ws_id:
                            return ws_id
                    for key in ("workspace_id", "workspaceId", "default_workspace_id", "defaultWorkspaceId"):
                        ws_id = str(payload.get(key) or "").strip()
                        if ws_id:
                            return ws_id
        except Exception:
            pass
        return ""

    def _build_http_oauth_session(self, context_cookies: list[dict], user_agent: str) -> cffi_requests.Session:
        session = cffi_requests.Session()
        try:
            session.headers.update(
                {
                    "User-Agent": user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
            )
        except Exception:
            pass
        if self.proxy_url:
            try:
                session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            except Exception:
                pass

        for ck in context_cookies or []:
            try:
                name = str(ck.get("name") or "").strip()
                value = str(ck.get("value") or "")
                if not name:
                    continue
                domain = str(ck.get("domain") or "").strip() or None
                path = str(ck.get("path") or "/").strip() or "/"
                if domain:
                    session.cookies.set(name, value, domain=domain, path=path)
                else:
                    session.cookies.set(name, value, path=path)
            except Exception:
                continue
        return session

    def _http_follow_and_extract_callback(self, session: cffi_requests.Session, url: str, max_depth: int = 12) -> str:
        """HTTP 跟随跳转链并提取 callback URL。"""
        if not url:
            return ""
        current_url = str(url).strip()
        for _ in range(max_depth):
            if current_url.startswith("/"):
                current_url = f"https://auth.openai.com{current_url}"
            try:
                resp = session.get(current_url, allow_redirects=False, timeout=20)
            except Exception as e:
                match = re.search(r"(https?://localhost[^\s'\"<>]+)", str(e))
                if match:
                    candidate = html.unescape(match.group(1)).replace("&amp;", "&")
                    if self._extract_code_from_url(candidate):
                        return candidate
                return ""

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = str(resp.headers.get("Location") or "").strip()
                if not loc:
                    return ""
                next_url = urljoin(current_url, loc)
                if self._extract_code_from_url(next_url):
                    return next_url
                current_url = next_url
                continue

            if resp.status_code == 200:
                current = str(getattr(resp, "url", "") or current_url)
                if self._extract_code_from_url(current):
                    return current
                text = str(resp.text or "")
                callback = self._extract_oauth_callback_from_text(text)
                if callback:
                    return callback
                return ""

            return ""
        return ""

    def _extract_hidden_inputs(self, form_html: str) -> Dict[str, str]:
        payload: Dict[str, str] = {}
        if not form_html:
            return payload
        for m in re.finditer(r"<input[^>]*>", form_html, flags=re.IGNORECASE):
            tag = m.group(0)
            try:
                name_m = re.search(r'name=["\']([^"\']+)["\']', tag, flags=re.IGNORECASE)
                if not name_m:
                    continue
                name = str(name_m.group(1) or "").strip()
                if not name:
                    continue
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag, flags=re.IGNORECASE)
                value = html.unescape(str(value_m.group(1) if value_m else ""))
                payload[name] = value
            except Exception:
                continue
        return payload

    def _extract_submit_field(self, form_html: str) -> Dict[str, str]:
        try:
            submit_btn = re.search(
                r"<button[^>]*name=['\"]([^'\"]+)['\"][^>]*value=['\"]([^'\"]*)['\"][^>]*>",
                form_html,
                flags=re.IGNORECASE,
            )
            if submit_btn:
                return {
                    str(submit_btn.group(1) or "").strip(): str(submit_btn.group(2) or "").strip()
                }
        except Exception:
            pass
        return {}

    def _http_submit_authorize_continue_api(
        self,
        session: cffi_requests.Session,
        *,
        page_url: str,
        authorize_url: str,
    ) -> str:
        """Consent 405/空响应兜底：调用 authorize/continue API。"""
        try:
            resp = session.post(
                OPENAI_API_ENDPOINTS["signup"],
                headers={
                    "referer": page_url,
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=json.dumps({}),
                timeout=20,
                allow_redirects=False,
            )
        except Exception as e:
            self._log(f"HTTP OAuth continue API 请求异常: {e}", "warning")
            return ""

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = str(resp.headers.get("Location") or "").strip()
            next_url = urljoin(str(resp.url or page_url), loc) if loc else ""
            if next_url:
                return self._http_follow_and_extract_callback(session, next_url)
            return ""

        if resp.status_code == 200:
            try:
                data = resp.json() if (resp.text or "").strip() else {}
            except Exception:
                data = {}
            continue_url = str((data or {}).get("continue_url") or "").strip()
            if continue_url:
                next_url = continue_url if continue_url.startswith("http") else urljoin(str(resp.url or page_url), continue_url)
                callback = self._http_follow_and_extract_callback(session, next_url)
                if callback:
                    return callback

        # 回跳链兜底
        for candidate in (authorize_url, page_url):
            callback = self._http_follow_and_extract_callback(session, candidate)
            if callback:
                return callback
        return ""

    def _http_submit_consent_form(
        self,
        session: cffi_requests.Session,
        *,
        page_url: str,
        html_text: str,
        authorize_url: str,
    ) -> str:
        forms = re.findall(r"<form[^>]*>.*?</form>", html_text or "", flags=re.IGNORECASE | re.DOTALL)
        if not forms:
            return self._http_submit_authorize_continue_api(
                session,
                page_url=page_url,
                authorize_url=authorize_url,
            )

        best_action = page_url
        best_payload: Dict[str, str] = {}
        best_score = -1
        for form_html in forms:
            open_tag_m = re.search(r"<form[^>]*>", form_html, flags=re.IGNORECASE)
            if not open_tag_m:
                continue
            open_tag = open_tag_m.group(0)
            action_m = re.search(r'action=["\']([^"\']*)["\']', open_tag, flags=re.IGNORECASE)
            action_raw = html.unescape(str(action_m.group(1) if action_m else "").strip())
            action_url = urljoin(page_url, action_raw) if action_raw else page_url
            payload = self._extract_hidden_inputs(form_html)
            payload.update(self._extract_submit_field(form_html))

            score = 0
            action_lower = action_url.lower()
            if "/sign-in-with-chatgpt/codex/consent" in action_lower:
                score += 100
            if "/api/accounts/authorize/continue" in action_lower:
                score += 80
            if payload.get("workspace_id"):
                score += 40
            if score > best_score:
                best_score = score
                best_action = action_url
                best_payload = payload

        try:
            action_path = (urlparse(best_action).path or "").lower()
        except Exception:
            action_path = (best_action or "").lower()
        if "/api/accounts/authorize/continue" in action_path and "action" not in best_payload:
            best_payload["action"] = "default"

        try:
            resp = session.post(
                best_action,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://auth.openai.com",
                    "Referer": page_url,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                data=best_payload,
                timeout=30,
                allow_redirects=False,
            )
        except Exception as e:
            self._log(f"HTTP OAuth Consent 表单提交失败: {e}", "warning")
            return ""

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = str(resp.headers.get("Location") or "").strip()
            next_url = urljoin(str(resp.url or best_action), loc) if loc else ""
            if next_url:
                return self._http_follow_and_extract_callback(session, next_url)
            return ""

        if resp.status_code == 405:
            return self._http_submit_authorize_continue_api(
                session,
                page_url=page_url,
                authorize_url=authorize_url,
            )

        callback = self._extract_oauth_callback_from_text(str(resp.text or ""))
        if callback:
            return callback
        return self._http_follow_and_extract_callback(session, str(resp.url or page_url))

    def _http_exchange_auth_callback_url(self, session: cffi_requests.Session, oauth_auth_url: str) -> str:
        """纯 HTTP OAuth 授权链路：提取 callback URL（code/state）。"""
        consent_url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"

        # 1) 优先从 authorize 入口走跳转链
        callback = self._http_follow_and_extract_callback(session, oauth_auth_url)
        if callback:
            return callback

        # 2) 直接访问 consent；若是 HTML 页面则提交表单
        try:
            resp = session.get(
                consent_url,
                headers={"referer": "https://auth.openai.com/log-in"},
                allow_redirects=False,
                timeout=30,
            )
        except Exception as e:
            self._log(f"HTTP OAuth 访问 consent 异常: {e}", "warning")
            resp = None

        if resp is not None:
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = str(resp.headers.get("Location") or "").strip()
                next_url = urljoin(consent_url, loc) if loc else ""
                if next_url:
                    callback = self._http_follow_and_extract_callback(session, next_url)
                    if callback:
                        return callback
            elif resp.status_code == 200:
                text = str(resp.text or "")
                callback = self._extract_oauth_callback_from_text(text)
                if callback:
                    return callback
                callback = self._http_submit_consent_form(
                    session,
                    page_url=str(resp.url or consent_url),
                    html_text=text,
                    authorize_url=oauth_auth_url,
                )
                if callback:
                    return callback

        # 3) workspace fallback
        ws_id = self._http_get_workspace_id(session)
        if ws_id:
            try:
                ws_resp = session.post(
                    OPENAI_API_ENDPOINTS["select_workspace"],
                    headers={
                        "referer": consent_url,
                        "content-type": "application/json",
                    },
                    data=json.dumps({"workspace_id": ws_id}),
                    timeout=30,
                    allow_redirects=False,
                )
                if ws_resp.status_code in (301, 302, 303, 307, 308):
                    loc = str(ws_resp.headers.get("Location") or "").strip()
                    next_url = urljoin(str(ws_resp.url or consent_url), loc) if loc else ""
                    if next_url:
                        callback = self._http_follow_and_extract_callback(session, next_url)
                        if callback:
                            return callback
                elif ws_resp.status_code == 200:
                    ws_data = ws_resp.json() if (ws_resp.text or "").strip() else {}
                    next_url = str((ws_data or {}).get("continue_url") or "").strip()
                    if next_url:
                        full_next = next_url if next_url.startswith("http") else urljoin(str(ws_resp.url or consent_url), next_url)
                        callback = self._http_follow_and_extract_callback(session, full_next)
                        if callback:
                            return callback
            except Exception as e:
                self._log(f"HTTP OAuth workspace fallback 异常: {e}", "warning")

        # 4) 兜底：允许自动重定向
        try:
            final_resp = session.get(
                oauth_auth_url,
                allow_redirects=True,
                timeout=30,
            )
            final_url = str(getattr(final_resp, "url", "") or "")
            if self._extract_code_from_url(final_url):
                return final_url
            if getattr(final_resp, "history", None):
                for hist in final_resp.history:
                    loc = str(hist.headers.get("Location") or "").strip()
                    next_url = urljoin(str(hist.url or oauth_auth_url), loc) if loc else ""
                    if self._extract_code_from_url(next_url):
                        return next_url
        except Exception as e:
            self._log(f"HTTP OAuth 自动重定向兜底异常: {e}", "warning")

        return ""

    def _get_oauth_tokens_via_http_flow(self, *, oauth_settings, context_cookies: list[dict]) -> Optional[Dict[str, Any]]:
        """使用旧 HTTP OAuth 授权链路（不依赖 Playwright 页面操作）提取 token。"""
        from .openai.oauth import generate_oauth_url, submit_callback_url

        oauth_start = generate_oauth_url(
            redirect_uri=oauth_settings.openai_redirect_uri,
            scope=oauth_settings.openai_scope,
            client_id=oauth_settings.openai_client_id,
        )
        session = self._build_http_oauth_session(context_cookies, user_agent="Mozilla/5.0")
        try:
            callback_url = self._http_exchange_auth_callback_url(session, oauth_start.auth_url)
            if not callback_url:
                self._log("HTTP OAuth 授权链路未提取到 callback URL", "warning")
                return None

            tokens_json = submit_callback_url(
                callback_url=callback_url,
                expected_state=oauth_start.state,
                code_verifier=oauth_start.code_verifier,
                redirect_uri=oauth_settings.openai_redirect_uri,
                client_id=oauth_settings.openai_client_id,
                token_url=oauth_settings.openai_token_url,
                proxy_url=self.proxy_url,
            )
            return json.loads(tokens_json)
        except Exception as e:
            self._log(f"HTTP OAuth 授权链路失败: {e}", "warning")
            return None
        finally:
            try:
                session.close()
            except Exception:
                pass

    def _is_oauth_otp_page(self, page) -> bool:
        """判断是否处于 OAuth 邮箱验证码页面。"""
        try:
            current_url = (page.url or "").lower()
        except Exception:
            current_url = ""
        # 先排除 consent 页面，避免误判导致重复拉码
        if "/sign-in-with-chatgpt/codex/consent" in current_url:
            return False
        if any(
            key in current_url
            for key in (
                "/email-verification",
                "/verify-email",
                "/verification",
                "/challenge",
            )
        ):
            return True

        otp_selectors = (
            "input[name='code']",
            "input[data-index='0']",
            "input[autocomplete='one-time-code']",
            "input[name*='otp']",
            "input[name*='verification']",
            "input[id*='otp']",
            "input[id*='code']",
            "input[inputmode='numeric']",
            "input[type='tel']",
            "input[type='text']",
        )
        for selector in otp_selectors:
            try:
                locator = page.locator(selector)
                if locator.count() > 0 and locator.first.is_visible():
                    return True
            except Exception:
                continue

        marker_texts = (
            "检查您的收件箱",
            "输入我们刚刚向",
            "需要填写验证码",
            "重新发送电子邮件",
            "Check your inbox",
            "Verify your email",
            "Resend email",
        )
        for text in marker_texts:
            try:
                if page.locator(f"text={text}").count() > 0 and page.locator(f"text={text}").first.is_visible():
                    return True
            except Exception:
                continue
        return False

    def _fill_oauth_otp_code(self, page, otp_code: str) -> bool:
        """填写 OAuth 邮箱验证码（兼容单输入框/多分段输入框）。"""
        code = re.sub(r"\D", "", str(otp_code or ""))
        if not code:
            code = str(otp_code or "").strip()
        if not code:
            return False

        # 1) 官方分段输入（data-index）
        try:
            if page.locator("input[data-index='0']").count() > 0:
                for i, ch in enumerate(code):
                    sel = f"input[data-index='{i}']"
                    if page.locator(sel).count() > 0:
                        page.fill(sel, ch)
                return True
        except Exception:
            pass

        # 2) 通用分段输入（maxlength=1）
        try:
            seg = page.locator(
                "input[maxlength='1'][inputmode='numeric'], "
                "input[maxlength='1'][type='tel'], "
                "input[maxlength='1'][autocomplete='one-time-code']"
            )
            seg_count = seg.count()
            if seg_count >= len(code) >= 4:
                filled = 0
                for i, ch in enumerate(code):
                    item = seg.nth(i)
                    if item.is_visible():
                        item.fill(ch)
                        filled += 1
                if filled >= len(code):
                    return True
        except Exception:
            pass

        # 3) 单输入框
        single_selectors = (
            "input[name='code']",
            "input[autocomplete='one-time-code']",
            "input[name*='code']",
            "input[id*='code']",
            "input[inputmode='numeric']",
            "input[type='tel']",
            "input[type='text']",
        )
        for selector in single_selectors:
            try:
                locator = page.locator(selector)
                if locator.count() <= 0:
                    continue
                item = locator.first
                if not item.is_visible():
                    continue
                try:
                    if not item.is_enabled():
                        continue
                except Exception:
                    pass
                try:
                    item.fill(code)
                except Exception:
                    try:
                        item.click(force=True)
                        try:
                            page.keyboard.press("Control+A")
                        except Exception:
                            page.keyboard.press("Meta+A")
                        page.keyboard.type(code, delay=35)
                    except Exception:
                        continue
                try:
                    if page.locator("button[type='submit']").count() > 0 and page.locator("button[type='submit']").first.is_enabled():
                        page.click("button[type='submit']")
                except Exception:
                    pass
                return True
            except Exception:
                continue

        return False

    def _is_password_login_page(self, page) -> bool:
        try:
            current_url = (page.url or "").lower()
        except Exception:
            current_url = ""

        try:
            pwd_locator = page.locator("input[type='password'], input[name='current-password']")
            has_password_input = pwd_locator.count() > 0 and pwd_locator.first.is_visible()
        except Exception:
            has_password_input = False

        if not has_password_input:
            return False

        if any(key in current_url for key in ("/log-in/password", "/u/login/password", "/log-in")):
            return True

        try:
            login_form = page.locator(
                "form[action*='/log-in/password'], form[action*='/u/login/password']"
            )
            if login_form.count() > 0:
                return True
        except Exception:
            pass

        return False

    def _is_oauth_consent_page(self, page) -> bool:
        if self._is_oauth_otp_page(page):
            return False

        try:
            current_url = (page.url or "").lower()
        except Exception:
            current_url = ""

        if "/sign-in-with-chatgpt/codex/consent" in current_url:
            return True

        try:
            consent_form = page.locator("form[action*='/sign-in-with-chatgpt/codex/consent']")
            if consent_form.count() > 0:
                return True
        except Exception:
            pass

        try:
            workspace_id_input = page.locator("input[name='workspace_id']")
            if workspace_id_input.count() > 0:
                return True
        except Exception:
            pass

        return False

    def _click_oauth_consent_continue(self, page) -> bool:
        # 避免把登录页的“继续”误当成 consent 的“继续”
        if self._is_password_login_page(page):
            self._log("当前处于登录密码页，跳过 Consent 按钮点击，先走密码提交流程", "warning")
            return False
        if self._is_oauth_otp_page(page):
            self._log("当前处于邮箱验证码页，跳过 Consent 按钮点击，先走验证码提交流程", "warning")
            return False
        try:
            current_url = (page.url or "").lower()
        except Exception:
            current_url = ""

        has_consent_context = False
        if "/sign-in-with-chatgpt/codex/consent" in current_url:
            has_consent_context = True
        if not has_consent_context:
            try:
                form = page.locator("form[action*='/sign-in-with-chatgpt/codex/consent']")
                has_consent_context = form.count() > 0
            except Exception:
                has_consent_context = False
        if not has_consent_context:
            self._log("当前不在 OAuth Consent 页面，跳过授权按钮点击", "warning")
            return False

        selectors = [
            "button:has-text('Continue')",
            "button:has-text('Allow')",
            "button:has-text('Authorize')",
            "button:has-text('Accept')",
            "button:has-text('继续')",
            "button:has-text('同意')",
            "button:has-text('允许')",
            "button:has-text('授权')",
            "button:has-text('确认')",
            "div[role='button']:has-text('Continue')",
            "div[role='button']:has-text('Allow')",
            "div[role='button']:has-text('Authorize')",
            "div[role='button']:has-text('继续')",
            "div[role='button']:has-text('同意')",
            "div[role='button']:has-text('允许')",
            "div[role='button']:has-text('授权')",
        ]
        deny_keywords = ("cancel", "deny", "decline", "拒绝", "取消")
        for selector in selectors:
            try:
                locator = page.locator(selector)
                count = locator.count()
                for idx in range(count):
                    item = locator.nth(idx)
                    if not item.is_visible():
                        continue
                    form_action = ""
                    try:
                        form_action = (item.evaluate(
                            "(el) => { const f = el.closest('form'); return f ? (f.getAttribute('action') || '') : ''; }"
                        ) or "").strip().lower()
                    except Exception:
                        form_action = ""
                    if any(key in form_action for key in ("/log-in/password", "/u/login/password", "/log-in")):
                        continue
                    if form_action and "/sign-in-with-chatgpt/codex/consent" not in form_action:
                        continue
                    text = ""
                    try:
                        text = (item.inner_text() or "").strip()
                    except Exception:
                        text = ""
                    text_lower = text.lower()
                    if any(keyword in text_lower for keyword in deny_keywords):
                        continue
                    item.click(timeout=3000)
                    self._log(f"已点击 OAuth 授权按钮: {text or selector}")
                    return True
            except Exception:
                continue
        return False

    def _capture_oauth_callback(self, page, timeout_ms: int = 20000) -> str:
        """通过导航与请求监听捕获 OAuth 回调 URL。"""
        callback_holder = {"url": ""}

        def _try_set(url: str):
            if not url:
                return
            if "code=" in url and "state=" in url and "auth/callback" in url:
                callback_holder["url"] = url

        try:
            page.on("framenavigated", lambda frame: _try_set(frame.url))
            page.on("request", lambda request: _try_set(request.url))
        except Exception:
            pass

        start = time.time()
        tick = 0
        while (time.time() - start) * 1000 < timeout_ms:
            if callback_holder["url"]:
                return callback_holder["url"]
            try:
                current = page.url
                if current and "code=" in current and "state=" in current:
                    return current
            except Exception:
                pass
            # 有些场景会显示 callback 链接但不真正跳转，直接从页面内容提取
            if tick % 3 == 0:
                try:
                    content = page.content()
                    extracted = self._extract_oauth_callback_from_text(content)
                    if extracted:
                        return extracted
                except Exception:
                    pass
            tick += 1
            time.sleep(0.2)
        return ""

    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now(_SHANGHAI_TZ).strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [Browser] {message}"
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if level == "error": logger.error(message)
        elif level == "warning": logger.warning(message)
        else: logger.info(message)

    def _safe_dump_stage_name(self, stage: str) -> str:
        name = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(stage or "page"))
        name = name.strip("_")
        if not name:
            name = "page"
        return name[:64]

    def _prepare_page_dump_dir(self) -> Optional[Path]:
        if not self.page_dump_enabled:
            return None
        if self.page_dump_dir is not None:
            return self.page_dump_dir
        try:
            custom_dir = str(os.environ.get("BROWSER_PAGE_DUMP_DIR", "")).strip()
            base_dir = Path(custom_dir) if custom_dir else (get_logs_dir() / "playwright_pages")
            base_dir.mkdir(parents=True, exist_ok=True)

            task_part = re.sub(r"[^a-zA-Z0-9_-]+", "", str(self.task_uuid or "manual"))[:24] or "manual"
            run_part = datetime.now(_SHANGHAI_TZ).strftime("%Y%m%d_%H%M%S")
            self.page_dump_dir = base_dir / f"{run_part}_{task_part}_{uuid.uuid4().hex[:6]}"
            self.page_dump_dir.mkdir(parents=True, exist_ok=True)
            self._log(f"页面元素快照已启用，目录: {self.page_dump_dir}")
            return self.page_dump_dir
        except Exception as e:
            self.page_dump_enabled = False
            self._log(f"初始化页面快照目录失败: {e}", "warning")
            return None

    def _collect_page_elements(self, page) -> Dict[str, Any]:
        max_items = int(self.page_dump_max_items or 120)
        script = """
        (maxItems) => {
            const list = (selector) => Array.from(document.querySelectorAll(selector));
            const txt = (el) => ((el.innerText || el.textContent || "").replace(/\\s+/g, " ").trim().slice(0, 140));
            const attr = (el, key) => String(el.getAttribute(key) || "").slice(0, 180);
            const visible = (el) => {
                try {
                    const style = window.getComputedStyle(el);
                    const rect = el.getBoundingClientRect();
                    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
                } catch (_e) {
                    return false;
                }
            };
            const toInput = (el) => {
                const type = String(el.type || el.getAttribute("type") || "").toLowerCase();
                const rawValue = ("value" in el) ? String(el.value || "") : txt(el);
                const value = type === "password" ? "<masked>" : rawValue.slice(0, 120);
                return {
                    tag: (el.tagName || "").toLowerCase(),
                    type,
                    name: attr(el, "name"),
                    id: attr(el, "id"),
                    placeholder: attr(el, "placeholder"),
                    required: !!el.required,
                    visible: visible(el),
                    value,
                    form_action: attr(el.closest("form") || document.createElement("form"), "action"),
                };
            };
            const toButton = (el) => ({
                tag: (el.tagName || "").toLowerCase(),
                type: attr(el, "type"),
                id: attr(el, "id"),
                name: attr(el, "name"),
                text: txt(el),
                visible: visible(el),
                form_action: attr(el.closest("form") || document.createElement("form"), "action"),
            });
            const toForm = (el) => ({
                id: attr(el, "id"),
                action: attr(el, "action"),
                method: attr(el, "method"),
                input_count: el.querySelectorAll("input, textarea, select").length,
                button_count: el.querySelectorAll("button, input[type='submit'], input[type='button']").length,
            });
            const toLink = (el) => ({
                text: txt(el),
                href: attr(el, "href"),
                visible: visible(el),
            });
            const hiddenInputs = list("input[type='hidden'][name]").slice(0, maxItems).map((el) => ({
                name: attr(el, "name"),
                id: attr(el, "id"),
                value: String(el.value || "").slice(0, 180),
            }));
            return {
                title: String(document.title || ""),
                location: String(window.location.href || ""),
                counts: {
                    inputs: list("input, textarea, [contenteditable='true']").length,
                    buttons: list("button, input[type='submit'], input[type='button'], [role='button']").length,
                    forms: list("form").length,
                    links: list("a[href]").length,
                    iframes: list("iframe").length,
                },
                inputs: list("input, textarea, [contenteditable='true']").slice(0, maxItems).map(toInput),
                buttons: list("button, input[type='submit'], input[type='button'], [role='button']").slice(0, maxItems).map(toButton),
                forms: list("form").slice(0, maxItems).map(toForm),
                links: list("a[href]").slice(0, maxItems).map(toLink),
                hidden_inputs: hiddenInputs,
                body_preview: ((document.body && document.body.innerText) || "").replace(/\\s+/g, " ").slice(0, 3000),
            };
        }
        """
        return page.evaluate(script, max_items) or {}

    def _dump_page_state(self, page, stage: str, note: str = ""):
        dump_dir = self._prepare_page_dump_dir()
        if dump_dir is None:
            return
        try:
            self._page_dump_index += 1
            stage_name = self._safe_dump_stage_name(stage)
            prefix = f"{self._page_dump_index:03d}_{stage_name}"

            url_text = ""
            try:
                url_text = str(page.url or "")
            except Exception:
                url_text = ""

            cookies = []
            try:
                cookies = [str(item.get("name") or "") for item in page.context.cookies()]
            except Exception:
                cookies = []

            elements = {}
            try:
                elements = self._collect_page_elements(page)
            except Exception as e:
                elements = {"error": f"collect elements failed: {e}"}

            html_text = ""
            try:
                html_text = page.content() or ""
            except Exception as e:
                html_text = f"<!-- failed to read html: {e} -->"
            if len(html_text) > self.page_dump_max_html_chars:
                html_text = html_text[: self.page_dump_max_html_chars] + "\n<!-- html truncated -->"

            json_payload = {
                "index": self._page_dump_index,
                "stage": stage,
                "note": note,
                "captured_at": datetime.now(_SHANGHAI_TZ).isoformat(),
                "url": url_text,
                "cookie_names": cookies,
                "elements": elements,
            }

            json_path = dump_dir / f"{prefix}.json"
            html_path = dump_dir / f"{prefix}.html"
            json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            html_path.write_text(html_text, encoding="utf-8")

            if self.page_dump_include_screenshot:
                try:
                    page.screenshot(path=str(dump_dir / f"{prefix}.png"), full_page=True, timeout=15000)
                except Exception:
                    pass
        except Exception as e:
            self._log(f"保存页面快照失败({stage}): {e}", "warning")

    def _bind_page_dump_events(self, page):
        if not self.page_dump_enabled:
            return

        def _on_main_nav(frame):
            try:
                if frame != page.main_frame:
                    return
                nav_url = str(getattr(frame, "url", "") or "")
                nav_path = ""
                try:
                    nav_path = (urlparse(nav_url).path or "").strip("/")
                except Exception:
                    nav_path = ""
                stage = f"nav_{nav_path or 'root'}"
                self._dump_page_state(page, stage)
            except Exception:
                return

        try:
            page.on("framenavigated", _on_main_nav)
        except Exception as e:
            self._log(f"绑定页面快照事件失败: {e}", "warning")

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        return ''.join(random.choices(PASSWORD_CHARSET, k=length))

    def _create_email(self) -> bool:
        try:
            self.email_info = self.email_service.create_email()
            if not self.email_info or "email" not in self.email_info:
                return False
            self.email = self.email_info["email"]
            return True
        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _scale_timeout(self, ms: int) -> int:
        """按倍率放大超时时间（毫秒）。"""
        try:
            value = int(float(ms) * float(self.timeout_multiplier))
        except Exception:
            value = int(ms)
        return max(1000, value)

    def _random_delay(self, low=0.5, high=2.0):
        try:
            low = float(low) * float(self.delay_multiplier)
            high = float(high) * float(self.delay_multiplier)
        except Exception:
            low = float(low)
            high = float(high)

        if self.delay_min > 0:
            low = max(low, self.delay_min)
        if self.delay_max > 0:
            high = min(high, self.delay_max)
        if high < low:
            high = low
        time.sleep(random.uniform(low, high))

    def _is_add_phone_blocked(self, url: str) -> bool:
        value = str(url or "").lower()
        return ("add-phone" in value) or ("onboarding" in value)

    def _mark_add_phone_blocked_failure(self, result: RegistrationResult, blocked_url: str) -> None:
        blocked_url = str(blocked_url or "").strip()
        self._log(
            f"命中 add-phone 风控拦截，任务判定失败并结束当前任务: {blocked_url or '-'}",
            "error",
        )
        result.success = False
        result.error_message = "命中 add-phone 风控拦截，任务失败"
        # 命中风控时不保留本次 token，避免误入库。
        result.access_token = ""
        result.refresh_token = ""
        result.id_token = ""
        result.session_token = ""
        if not isinstance(result.metadata, dict):
            result.metadata = {}
        result.metadata["oauth_blocked"] = "add_phone"
        result.metadata["oauth_blocked_url"] = blocked_url
        result.metadata["token_source"] = "blocked_add_phone"

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
        except ImportError:
            self._log("未找到 playwright，请运行: uv pip install playwright && uv run playwright install chromium", "error")
            result.error_message = "Playwright not installed"
            return result

        if not self._create_email():
            result.error_message = "创建邮箱失败"
            return result
            
        result.email = self.email
        self.password = self._generate_password()
        result.password = self.password
        
        user_info = generate_random_user_info()
        name = user_info['name']
        birthdate = user_info['birthdate']

        browser_mode_label = "无头" if self.headless else "有头"
        self._log(f"使用 Playwright 浏览器注册（{browser_mode_label}），分配邮箱: {self.email}")
        if self.oauth_http_only:
            self._log("OAuth 提取策略: 仅 HTTP（注册阶段仍需 Playwright）")
        elif self.oauth_http_first:
            self._log("OAuth 提取策略: HTTP 优先，失败回退 Playwright（注册阶段仍需 Playwright）")
        
        with sync_playwright() as p:
            launch_args = {
                "headless": self.headless,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--incognito",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ]
            }
            if self.proxy_url:
                launch_args["proxy"] = {"server": self.proxy_url}
                
            browser = p.chromium.launch(**launch_args)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                device_scale_factor=1,
            )
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            page = context.new_page()
            page.set_default_timeout(self._scale_timeout(30000))
            page.set_default_navigation_timeout(self._scale_timeout(60000))
            refresh_state = {"count": 0}
            force_close_browser = False
            self._prepare_page_dump_dir()
            self._bind_page_dump_events(page)
            self._dump_page_state(page, "startup")
            
            try:
                self._log("访问 ChatGPT 首页获取验证环境...")
                # 先访问首页，获取正常的 session 状态
                page.goto("https://chatgpt.com/", wait_until="commit", timeout=60000)
                self._dump_page_state(page, "home_loaded")
                
                try:
                    page.wait_for_selector('[data-testid="signup-button"], [data-testid="login-button"]', timeout=30000)
                    self._random_delay(2.0, 3.5)
                    self._log("触发注册/登录按钮...")
                    
                    if page.locator('[data-testid="signup-button"]').count() > 0:
                        page.locator('[data-testid="signup-button"]').first.click(force=True)
                    elif page.locator('[data-testid="login-button"]').count() > 0:
                        page.locator('[data-testid="login-button"]').first.click(force=True)
                        
                    self._random_delay(2.0, 4.0)
                    self._dump_page_state(page, "home_clicked_signup_or_login")

                    # 给前端一点缓冲时间，避免“URL 未跳转但登录弹窗已出现”时误报
                    ui_ready = False
                    try:
                        page.wait_for_function(
                            """
                            () => {
                                const href = String(window.location.href || "");
                                if (href.includes("/auth/") || href.includes("/login")) return true;
                                const email = document.querySelector("input[type='email'], input[name='email']");
                                if (email && email.offsetParent !== null) return true;
                                const dialog = document.querySelector("[role='dialog'], [aria-modal='true']");
                                if (dialog) {
                                    const txt = String(dialog.innerText || "").toLowerCase();
                                    if (
                                        txt.includes("登录") ||
                                        txt.includes("注册") ||
                                        txt.includes("log in") ||
                                        txt.includes("sign up")
                                    ) {
                                        return true;
                                    }
                                }
                                return false;
                            }
                            """,
                            timeout=self._scale_timeout(12000),
                        )
                        ui_ready = True
                    except Exception:
                        ui_ready = False

                    if not ui_ready and "/auth/" not in page.url and "/login" not in page.url:
                        self._log("前端响应缓慢或失败，尝试刷新页面重试...", "warning")
                        self._maybe_refresh(page, "首页按钮未跳转", refresh_state)
                        if page.locator('[data-testid="signup-button"]').count() > 0:
                            page.locator('[data-testid="signup-button"]').first.click(force=True)
                        elif page.locator('[data-testid="login-button"]').count() > 0:
                            page.locator('[data-testid="login-button"]').first.click(force=True)
                        self._dump_page_state(page, "home_retry_click")
                except Exception as e:
                    self._log(f"未找到首页按钮或操作异常: {e}", "warning")
                
                # 等待输入邮箱的界面
                page.wait_for_selector("input[type='email']", timeout=60000)
                self._random_delay(2.0, 4.0)
                self._dump_page_state(page, "email_page_ready")
                self._log("填写邮箱...")
                page.fill("input[type='email']", self.email)
                self._random_delay(1.0, 2.0)
                if not self._safe_click(page, "button[type='submit']", refresh_state, "提交邮箱"):
                    self._log("提交邮箱失败，尝试继续流程", "warning")
                self._debug_pause(page, "已提交邮箱")
                self._dump_page_state(page, "email_submitted")
                
                # 使用更智能的状态机处理不确定的验证链路：可能是密码->OTP->信息，也可能是OTP->信息 等等。
                # 使用状态机记录已完成的操作，防止由于页面跳转慢导致重复匹配和死循环
                done_password = False
                done_otp = False
                done_profile = False
                
                for _step in range(6):
                    try:
                        self._log("等待进入下一个验证环节...")
                        self._dump_page_state(page, f"register_step_{_step+1}_before_detect")
                        
                        # 动态构建当前需要等待的元素
                        selectors = []
                        if not done_password:
                            selectors.append("input[type='password']")
                        if not done_otp:
                            selectors.extend(["input[name='code']", "input[data-index='0']", "h2:has-text('Verify your email')"])
                        if not done_profile:
                            selectors.extend(["input[name='name']", "input[name='first-name']", "input[name='fullname']", "input[name='age']"])
                            
                        # 如果全部环节判定完成（或者不需要），就退出循环
                        if not selectors:
                            break
                            
                        page.wait_for_selector(", ".join(selectors), timeout=60000)
                        self._random_delay(1.0, 2.0)
                    except PlaywrightTimeoutError:
                        # 特殊处理：密码页停留超时，尝试刷新并重新提交密码
                        if (not done_password) and ("create-account/password" in page.url or page.locator("input[type='password']").count() > 0):
                            self._log("密码页停留超时，尝试刷新并重新提交密码...", "warning")
                            self._maybe_refresh(page, "密码页停留超时", refresh_state)
                            try:
                                page.wait_for_selector("input[type='password']", timeout=20000)
                                page.fill("input[type='password']", self.password)
                                if not self._safe_click(page, "button[type='submit']", refresh_state, "提交密码"):
                                    self._log("密码页重提失败，继续等待...", "warning")
                                self._debug_pause(page, "已重新提交密码")
                            except Exception as e:
                                self._log(f"密码页重试异常: {e}", "warning")
                            continue
                        if self._maybe_refresh(page, "等待下一环节超时", refresh_state):
                            continue
                        if "chatgpt.com" in page.url or "auth.openai.com" not in page.url:
                            self._log("似乎已经脱离了 Auth 流程，终止等待。")
                            break
                        self._log("没找到任何可用输入框，尝试判断下一步...")
                    
                    # 1. 检查密码环节
                    if not done_password and page.locator("input[type='password']").is_visible() and page.locator("input[type='password']").is_editable():
                        self._log("填写密码...")
                        self._random_delay(1.0, 2.5)
                        page.fill("input[type='password']", self.password)
                        self._random_delay(1.0, 2.0)
                        if not self._safe_click(page, "button[type='submit']", refresh_state, "提交密码"):
                            continue
                        self._debug_pause(page, "已提交密码")
                        self._dump_page_state(page, "password_submitted")

                        # 等待密码输入框消失，判断是否真正进入下一环节
                        try:
                            page.wait_for_selector("input[type='password']", state="hidden", timeout=10000)
                            done_password = True
                        except Exception:
                            done_password = False
                            self._log("密码提交后仍停留在密码页，准备重试...", "warning")
                            self._maybe_refresh(page, "密码页未跳转", refresh_state)
                        continue # 进入下一个循环检测
                    
                    # 2. 检查验证码环节
                    is_otp = False
                    if not done_otp:
                        is_otp = page.locator("input[name='code']").is_visible() or page.locator("input[data-index='0']").is_visible() or page.locator("h2:has-text('Verify your email')").is_visible()
                        
                    if is_otp:
                        self._otp_sent_at = time.time()
                        self._log("等待加载并请求验证码...")
                        email_id = self.email_info.get("service_id") if self.email_info else None
                        otp_code = self.email_service.get_verification_code(
                            email=self.email,
                            email_id=email_id,
                            timeout=120,
                            pattern=OTP_CODE_PATTERN,
                            otp_sent_at=self._otp_sent_at,
                        )
                        if not otp_code:
                            self._log("等待验证码超时", "error")
                            result.error_message = "收取验证码超时"
                            return result
                            
                        self._log(f"收到验证码: {otp_code}，正在自动填写...")
                        if page.locator("input[data-index='0']").count() > 0:
                            for i, char in enumerate(otp_code):
                                page.fill(f"input[data-index='{i}']", char)
                        elif page.locator("input[name='code']").count() > 0:
                            page.fill("input[name='code']", otp_code)
                            if not self._safe_click(page, "button[type='submit']", refresh_state, "提交验证码"):
                                continue
                        self._debug_pause(page, "已提交验证码")
                        self._dump_page_state(page, "otp_submitted")
                            
                        done_otp = True
                        try: page.wait_for_selector("input[name='code'], input[data-index='0']", state="hidden", timeout=10000)
                        except: pass
                        continue # 进入下一环节
                        
                    # 3. 检查个人信息环节
                    is_profile = False
                    if not done_profile:
                        is_profile = page.locator("input[name='name']").is_visible() or page.locator("input[name='fullname']").is_visible() or page.locator("input[name='first-name']").is_visible() or page.locator("input[name='age']").is_visible()
                        
                    if is_profile:
                        done_profile = True
                        self._log("填写个人信息...")
                        if page.locator("input[name='first-name']").is_visible():
                            name_parts = name.split(" ")
                            page.fill("input[name='first-name']", name_parts[0])
                            if len(name_parts) > 1:
                                page.fill("input[name='last-name']", name_parts[1])
                        elif page.locator("input[name='fullname']").is_visible():
                            page.fill("input[name='fullname']", name)
                        elif page.locator("input[name='name']").is_visible():
                            page.fill("input[name='name']", name)
                            
                        self._random_delay(0.5, 1.5)
                        
                        # 填年岁/生日
                        if page.locator("input[name='age']").is_visible():
                            self._log("检测到 Literal Age (直接填年龄数字) 输入模式...")
                            # extract birth_year
                            b_year = int(birthdate.split('-')[0])
                            age_num = datetime.now(_SHANGHAI_TZ).year - b_year
                            page.fill("input[name='age']", str(age_num))
                        else:
                            try:
                                aria_year = page.locator('div[role="spinbutton"][data-type="year"], div[data-type="year"]')
                                aria_month = page.locator('div[role="spinbutton"][data-type="month"], div[data-type="month"]')
                                aria_day = page.locator('div[role="spinbutton"][data-type="day"], div[data-type="day"]')
                                selects = page.locator("select")
                                
                                parts = birthdate.split("-")
                                y_str = parts[0]
                                m_str = str(int(parts[1]))
                                d_str = str(int(parts[2]))

                                if aria_year.count() > 0 and aria_month.count() > 0 and aria_day.count() > 0:
                                    self._log("检测到全新分段式(React-Aria)生日输入框...")
                                    ok_year = self._fill_react_aria_segment(page, aria_year, y_str)
                                    self._random_delay(0.1, 0.3)
                                    ok_month = self._fill_react_aria_segment(page, aria_month, m_str.zfill(2))
                                    self._random_delay(0.1, 0.3)
                                    ok_day = self._fill_react_aria_segment(page, aria_day, d_str.zfill(2))
                                    self._random_delay(0.2, 0.5)
                                    if not (ok_year and ok_month and ok_day):
                                        self._log("React-Aria 分段输入疑似失败，尝试 JS 强制写入...", "warning")
                                        self._force_set_react_aria_birthday(page, birthdate)
                                    self._set_hidden_birthday(page, birthdate)
                                    
                                elif selects.count() >= 3:
                                    for i in range(selects.count()):
                                        s_loc = selects.nth(i)
                                        options_texts = s_loc.locator("option").all_inner_texts()
                                        max_num = 0
                                        for text in options_texts:
                                            match = re.search(r'\d+', text)
                                            if match: max_num = max(max_num, int(match.group()))
                                        
                                        target_val = None
                                        if max_num > 31: target_val = y_str
                                        elif max_num == 12: target_val = m_str
                                        elif max_num == 31: target_val = d_str
                                        else:
                                            if len(options_texts) in (12, 13): target_val = m_str
                                            elif len(options_texts) in (31, 32): target_val = d_str
                                        
                                        if target_val:
                                            val_to_select = s_loc.evaluate(f'''(sel) => {{
                                                let target = "{target_val}";
                                                let targetPad = ("0" + target).slice(-2);
                                                for (let o of sel.options) {{
                                                    if (o.value === target || o.value === targetPad) return o.value;
                                                    if (o.text.trim() === target || o.text.trim() === targetPad || 
                                                        o.text.trim() === target + "月" || o.text.trim() === targetPad + "月") return o.value;
                                                }}
                                                return null;
                                            }}''')
                                            if val_to_select:
                                                s_loc.select_option(value=val_to_select)
                                                self._random_delay(0.2, 0.4)
                                else:
                                    bday_locator = page.locator("input[name='birthdate'], input[name='birthday'], input[id*='date'], input[placeholder*='YYYY']")
                                    if bday_locator.count() > 0:
                                        bday_input = bday_locator.first
                                        placeholder = (bday_input.get_attribute("placeholder") or "").upper()
                                        if "DD" in placeholder and "MM" in placeholder and placeholder.index("DD") < placeholder.index("MM"):
                                            formatted = f"{parts[2]}{parts[1]}{parts[0]}" # DDMMYYYY
                                        else:
                                            formatted = f"{parts[1]}{parts[2]}{parts[0]}" # MMDDYYYY
                                        
                                        bday_input.click()
                                        bday_input.fill("")
                                        page.keyboard.type(formatted, delay=50)
                                        if not bday_input.input_value():
                                            bday_input.fill(f"{parts[1]}/{parts[2]}/{parts[0]}")
                                    else:
                                        # 兜底写入隐藏字段
                                        self._set_hidden_birthday(page, birthdate)
                            except Exception as e:
                                self._log(f"填写生日输入异常: {e}", "warning")
                        
                        self._random_delay(0.3, 1.0)
                        
                        # 提交个人信息
                        if page.locator("button:has-text('Agree')").count() > 0:
                             if not self._safe_click(page, "button:has-text('Agree')", refresh_state, "提交个人信息"):
                                 continue
                        elif page.locator("button[type='submit']").count() > 0:
                             if not self._safe_click(page, "button[type='submit']", refresh_state, "提交个人信息"):
                                 continue
                        elif page.locator("button:has-text('Continue')").count() > 0:
                             if not self._safe_click(page, "button:has-text('Continue')", refresh_state, "提交个人信息"):
                                 continue
                        self._debug_pause(page, "已提交个人信息")
                        self._dump_page_state(page, "profile_submitted")
                        break # 到此处验证链条就正式结束了
                        
                    # 如果当前没命中上述可见模块，可能已经过渡到一个新 URL，或者是跳过了某些步骤
                    if "chatgpt.com" in page.url and "auth" not in page.url:
                        break
                
                # 等待最终跳转回 ChatGPT，获取 /api/auth/session
                self._log("等待最终认证完成...")
                page.wait_for_url("**/chatgpt.com**", timeout=45000)
                self._dump_page_state(page, "chatgpt_home_after_auth")
                
                self._log("导航到 /api/auth/session 读取 tokens...")
                page.goto("https://chatgpt.com/api/auth/session")
                self._dump_page_state(page, "session_api_page")
                try:
                    session_text = page.locator("body").inner_text()
                    import json
                    session_data = json.loads(session_text)
                    access_token = session_data.get("accessToken")
                    refresh_token = session_data.get("refreshToken", "")
                    id_token = session_data.get("idToken", "")
                    
                    # 从 cookies 里拿 session token
                    cookies = context.cookies()
                    session_cookie = ""
                    for c in cookies:
                        if c["name"] == "__Secure-next-auth.session-token":
                            session_cookie = c["value"]
                            break
                            
                    if access_token:
                        self._log("成功获取到 Access Token!")
                        result.success = True
                        result.access_token = access_token
                        result.refresh_token = refresh_token
                        result.id_token = id_token
                        result.session_token = session_cookie
                        result.account_id = "extracted_later"
                        result.source = "browser"
                        result.metadata = {
                            "email_service": self.email_service.service_type.value,
                            "proxy_used": self.proxy_url,
                            "token_mode": "browser",
                            "token_source": "playwright",
                            "auth_profile": "session",
                            "issued_client_id": "",
                            "token_audience": [],
                            "token_scope": "",
                            "registered_at": datetime.now(_SHANGHAI_TZ).isoformat()
                        }
                        
                        # ======== 新增步骤: 获取官方持久化 OAuth Token ========
                        if self.skip_oauth:
                            self._log("已配置跳过 OAuth 授权流程 (BROWSER_SKIP_OAUTH=1)", "warning")
                        else:
                            oauth_pre_delay = float(self.oauth_pre_delay_seconds or 0.0)
                            if self.oauth_pre_delay_jitter_seconds > 0:
                                oauth_pre_delay += random.uniform(0, self.oauth_pre_delay_jitter_seconds)
                            if oauth_pre_delay > 0:
                                self._log(f"[节流] 注册成功，{oauth_pre_delay:.1f}s 后开始 OAuth...")
                                time.sleep(oauth_pre_delay)
                            from ..config.settings import get_settings
                            from .openai.oauth import generate_oauth_url, submit_callback_url
                            oauth_settings = get_settings()
                            oauth_success = False
                            http_oauth_attempted = False
                            oauth_hard_fail_reason = ""

                            # 先走“纯 HTTP OAuth 授权链路”（不依赖 Playwright 页面点击）
                            if self.oauth_http_first:
                                http_oauth_attempted = True
                                self._log("优先尝试 HTTP OAuth 授权链路（不依赖 Playwright 页面操作）...")
                                http_oauth_tokens = self._get_oauth_tokens_via_http_flow(
                                    oauth_settings=oauth_settings,
                                    context_cookies=cookies,
                                )
                                if (
                                    http_oauth_tokens
                                    and http_oauth_tokens.get("access_token")
                                    and http_oauth_tokens.get("refresh_token")
                                ):
                                    result.access_token = http_oauth_tokens["access_token"]
                                    result.refresh_token = http_oauth_tokens["refresh_token"]
                                    result.id_token = http_oauth_tokens.get("id_token", "")
                                    result.metadata["token_source"] = "browser_oauth_http"
                                    result.metadata["auth_profile"] = "codex_oauth"
                                    result.metadata["issued_client_id"] = str(
                                        http_oauth_tokens.get("issued_client_id")
                                        or oauth_settings.openai_client_id
                                        or ""
                                    ).strip()
                                    token_audience = http_oauth_tokens.get("token_audience") or []
                                    if not isinstance(token_audience, list):
                                        token_audience = [str(token_audience)]
                                    result.metadata["token_audience"] = token_audience
                                    result.metadata["token_scope"] = str(
                                        http_oauth_tokens.get("token_scope") or ""
                                    ).strip()
                                    self._log("🎉 HTTP OAuth 授权链路提取 Refresh Token 成功！")
                                    oauth_success = True

                            if http_oauth_attempted and not oauth_success and not self.oauth_http_only:
                                self._log("HTTP OAuth 授权链路未成功，回退到 Playwright OAuth 授权链路...", "warning")
                            elif http_oauth_attempted and not oauth_success and self.oauth_http_only:
                                self._log("已启用 BROWSER_OAUTH_HTTP_ONLY=1，HTTP OAuth 失败后不再回退 Playwright", "warning")
                            # 暂时一直重复获取 OAuth 重新登录直到获取到 refresh token 为止
                            for attempt in range(30) if (not oauth_success and not self.oauth_http_only) else []:
                                try:
                                    self._log(f"启动获取正式的 OAuth Refresh Token！（尝试次数: {attempt + 1}）")
                                    oauth_info = generate_oauth_url(
                                        redirect_uri=oauth_settings.openai_redirect_uri,
                                        scope=oauth_settings.openai_scope,
                                        client_id=oauth_settings.openai_client_id,
                                    )
                                    authorize_url = self._build_oauth_authorize_url(oauth_info.auth_url)
                                    page.goto(authorize_url)
                                    self._dump_page_state(page, f"oauth_attempt_{attempt+1}_authorize")
                                    self._random_delay(1.0, 2.0)
                                    self._handle_oauth_relogin(page)
                                    self._dump_page_state(page, f"oauth_attempt_{attempt+1}_after_relogin")
                                    if self._is_add_phone_blocked(page.url):
                                        oauth_hard_fail_reason = f"add-phone 拦截: {page.url}"
                                        self._mark_add_phone_blocked_failure(result, page.url)
                                        force_close_browser = True
                                        break

                                    callback_url = ""
                                    if self._is_oauth_consent_page(page):
                                        self._log("检测到 OAuth Consent 页面，立即点击继续并捕获回调...")
                                        self._click_oauth_consent_continue(page)
                                        self._dump_page_state(page, f"oauth_attempt_{attempt+1}_consent_clicked")
                                        callback_url = self._capture_oauth_callback(page, timeout_ms=12000)
                                    else:
                                        # 快速兜底：有时页面已在 consent，但页面判定存在漏判，先尝试点一次继续。
                                        fast_clicked = self._click_oauth_consent_continue(page)
                                        if fast_clicked:
                                            self._log("已触发 Consent 快速点击，等待授权回调...")
                                            self._dump_page_state(page, f"oauth_attempt_{attempt+1}_consent_fast_click")
                                            callback_url = self._capture_oauth_callback(page, timeout_ms=12000)
                                        else:
                                            callback_url = self._capture_oauth_callback(page, timeout_ms=6000)
                                    if not callback_url:
                                        # 先补一次登录处理，避免停在密码页时误点 Continue
                                        self._handle_oauth_relogin(page)
                                        if self._is_oauth_otp_page(page):
                                            self._log("二次检查发现仍在验证码页，优先处理验证码并继续等待回调...", "warning")
                                            self._handle_oauth_relogin(page)
                                            callback_url = self._capture_oauth_callback(page, timeout_ms=12000)
                                        if not callback_url and self._is_oauth_consent_page(page):
                                            self._log("二次检查命中 OAuth Consent，立即点击继续并捕获回调...")
                                            self._click_oauth_consent_continue(page)
                                            self._dump_page_state(page, f"oauth_attempt_{attempt+1}_consent_retry_click")
                                            callback_url = self._capture_oauth_callback(page, timeout_ms=12000)
                                        elif not callback_url:
                                            callback_url = self._capture_oauth_callback(page, timeout_ms=8000)

                                    if not callback_url and not self._is_oauth_otp_page(page):
                                        self._log("试图点击授权界面的 Continue/Allow/继续 等确认许可键...")
                                        self._click_oauth_consent_continue(page)
                                        self._dump_page_state(page, f"oauth_attempt_{attempt+1}_manual_consent_click")

                                        callback_url = self._capture_oauth_callback(page, timeout_ms=15000)
                                    elif not callback_url:
                                        self._log("当前仍是验证码页面，已跳过手动 Consent 点击，等待验证码处理后的回调", "warning")

                                    if not callback_url:
                                        body_text = page.locator("body").inner_text()[:400]
                                        self._log(f"授权回调未能自动触发，当前页面内容卡在: {body_text}", "warning")
                                        if self._is_add_phone_blocked(page.url):
                                            oauth_hard_fail_reason = f"add-phone 拦截: {page.url}"
                                            self._mark_add_phone_blocked_failure(result, page.url)
                                            force_close_browser = True
                                            break
                                            
                                        if self._maybe_refresh(page, "OAuth 授权未跳转", refresh_state):
                                            self._handle_oauth_relogin(page)
                                            callback_url = self._capture_oauth_callback(page, timeout_ms=10000)

                                    final_oauth_url = callback_url or page.url
                                    if "code=" not in final_oauth_url or "state=" not in final_oauth_url:
                                        self._dump_page_state(page, f"oauth_attempt_{attempt+1}_no_callback")
                                        if self._is_add_phone_blocked(final_oauth_url):
                                            oauth_hard_fail_reason = f"add-phone 拦截: {final_oauth_url}"
                                            self._mark_add_phone_blocked_failure(result, final_oauth_url)
                                            force_close_browser = True
                                            break
                                        raise RuntimeError("未捕捉到 OAuth 回调 code/state")

                                    self._log("成功捕捉到 Code，正在调用接口进行兑换...")
                                    self._dump_page_state(page, f"oauth_attempt_{attempt+1}_callback_ready")
                                    tokens_json = submit_callback_url(
                                        callback_url=final_oauth_url,
                                        expected_state=oauth_info.state,
                                        code_verifier=oauth_info.code_verifier,
                                        redirect_uri=oauth_settings.openai_redirect_uri,
                                        client_id=oauth_settings.openai_client_id,
                                        token_url=oauth_settings.openai_token_url,
                                        proxy_url=self.proxy_url
                                    )
                                    import json as token_json
                                    oauth_tokens = token_json.loads(tokens_json)
                                    if oauth_tokens.get("access_token") and oauth_tokens.get("refresh_token"):
                                        result.access_token = oauth_tokens["access_token"]
                                        result.refresh_token = oauth_tokens["refresh_token"]
                                        result.id_token = oauth_tokens.get("id_token", "")
                                        result.metadata["token_source"] = "browser_oauth"
                                        result.metadata["auth_profile"] = "codex_oauth"
                                        result.metadata["issued_client_id"] = str(
                                            oauth_tokens.get("issued_client_id")
                                            or oauth_settings.openai_client_id
                                            or ""
                                        ).strip()
                                        token_audience = oauth_tokens.get("token_audience") or []
                                        if not isinstance(token_audience, list):
                                            token_audience = [str(token_audience)]
                                        result.metadata["token_audience"] = token_audience
                                        result.metadata["token_scope"] = str(
                                            oauth_tokens.get("token_scope") or ""
                                        ).strip()
                                        self._log("🎉 正式授权 Token (附带无限续期 Refresh Token) 提取成功！")
                                        oauth_success = True
                                        break
                                    else:
                                        self._log("未能获取到完整的 OAuth token 信息", "warning")
                                except Exception as oauth_e:
                                    self._log(f"附加 OAuth 授权流程被拦截或发生异常: {oauth_e}", "warning")
                                    if self._is_add_phone_blocked(page.url):
                                        oauth_hard_fail_reason = f"add-phone 拦截: {page.url}"
                                        self._mark_add_phone_blocked_failure(result, page.url)
                                        force_close_browser = True
                                        break
                                        
                            if oauth_hard_fail_reason:
                                self._log(
                                    "命中 add-phone，已直接判定失败并关闭当前浏览器，进入下一个任务。",
                                    "warning",
                                )
                            elif not oauth_success:
                                self._log("达到最大 OAuth 重试次数，获取 Refresh Token 失败。", "warning")
                    else:
                         self._log("注册似乎完成了，但未能从 session 获取到正确的 access_token。", "error")
                         result.error_message = "没有在最终页面提取到 accessToken"
                         
                except Exception as ex:
                     self._log(f"解析 Session 时报错: {ex}", "error")
                     result.error_message = "解析 session 报错"
            
            except Exception as e:
                self._log(f"浏览器注册过程异常: {e}", "error")
                result.error_message = str(e)
            finally:
                if self.keep_browser_open and not force_close_browser:
                    if self.debug_enabled:
                        self._log("调试模式已开启，浏览器保持打开（手动关闭窗口后继续）。", "warning")
                    else:
                        self._log("检测到 BROWSER_KEEP_OPEN=1，浏览器保持打开（手动关闭窗口后继续）。", "warning")
                    try:
                        page.wait_for_event("close", timeout=0)
                    except Exception:
                        pass
                elif force_close_browser and self.keep_browser_open:
                    self._log("命中 add-phone，已忽略保持浏览器打开配置并立即关闭浏览器。", "warning")
                browser.close()
                
        # To get the account ID, we might need a JWT decode or similar logic
        if result.success and result.access_token:
            from .register import _extract_account_id_from_jwt
            aid = _extract_account_id_from_jwt(result.access_token)
            if aid: result.account_id = aid
        if self.page_dump_dir:
            if not isinstance(result.metadata, dict):
                result.metadata = {}
            result.metadata.setdefault("debug_page_dump_dir", str(self.page_dump_dir))
            
        return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success: return False
        try:
            from ..config.settings import get_settings
            from ..database import crud
            from ..database.session import get_db
            settings = get_settings()
            metadata = result.metadata or {}
            token_source = str(metadata.get("token_source") or "").strip().lower()
            issued_client_id = str(metadata.get("issued_client_id") or "").strip()
            client_id_for_db = issued_client_id or (
                settings.openai_client_id
                if token_source in {"oauth", "browser_oauth"} and result.refresh_token
                else None
            )
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=client_id_for_db,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )
                self._log(f"浏览器注册账户已保存到数据库，ID: {account.id}")
                return True
        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
