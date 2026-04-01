import time
import logging
import os
import random
import uuid
import re
import time
from datetime import datetime
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs, urlencode

from ..services.base import BaseEmailService
from ..config.constants import generate_random_user_info, DEFAULT_PASSWORD_LENGTH, PASSWORD_CHARSET, OTP_CODE_PATTERN
from .register import RegistrationResult

logger = logging.getLogger(__name__)

class BrowserRegistrationEngine:
    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger = None,
        task_uuid: Optional[str] = None,
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
        self.debug_enabled = debug_flag
        self.keep_browser_open = keep_open_flag or debug_flag
        self.step_pause = pause_flag
        self.auto_refresh_on_stuck = refresh_flag
        self.skip_oauth = skip_oauth_flag

    def _debug_pause(self, page, reason: str):
        if not self.step_pause:
            return
        self._log(f"调试暂停: {reason}，请在浏览器手动处理后继续", "warning")
        try:
            page.pause()
        except Exception:
            # 兜底等待，避免阻断逻辑
            page.wait_for_timeout(30000)

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
            page.wait_for_timeout(3000)
        except Exception as e:
            self._log(f"刷新失败: {e}", "warning")
        return True

    def _safe_click(self, page, selector: str, refresh_state: Dict[str, int], label: str, timeout: int = 10000) -> bool:
        try:
            page.click(selector, timeout=timeout)
            return True
        except Exception as e:
            self._log(f"{label}点击失败: {e}", "warning")
            if self._maybe_refresh(page, f"{label}点击失败", refresh_state):
                try:
                    page.click(selector, timeout=timeout)
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
        """处理 OAuth 再次登录流程（输入邮箱/密码/验证码）。"""
        handled = False
        try:
            if page.locator("input[type='email']").count() > 0 and page.locator("input[type='email']").first.is_visible():
                self._log("检测到 OAuth 登录页，填写邮箱...", "warning")
                page.fill("input[type='email']", self.email)
                page.click("button[type='submit']")
                handled = True
                self._random_delay(1.0, 2.0)

            if page.locator("input[type='password']").count() > 0 and page.locator("input[type='password']").first.is_visible():
                self._log("OAuth 登录页要求密码，自动填写...", "warning")
                page.fill("input[type='password']", self.password)
                page.click("button[type='submit']")
                handled = True
                self._random_delay(1.0, 2.0)

            is_otp = page.locator("input[name='code']").is_visible() or page.locator("input[data-index='0']").is_visible()
            if is_otp:
                self._otp_sent_at = time.time()
                self._log("OAuth 登录需要邮箱验证码，开始获取...", "warning")
                email_id = self.email_info.get("service_id") if self.email_info else None
                otp_code = self.email_service.get_verification_code(
                    email=self.email,
                    email_id=email_id,
                    timeout=120,
                    pattern=OTP_CODE_PATTERN,
                    otp_sent_at=self._otp_sent_at,
                )
                if otp_code:
                    if page.locator("input[data-index='0']").count() > 0:
                        for i, char in enumerate(otp_code):
                            page.fill(f"input[data-index='{i}']", char)
                    elif page.locator("input[name='code']").count() > 0:
                        page.fill("input[name='code']", otp_code)
                        page.click("button[type='submit']")
                    handled = True
                    self._random_delay(1.0, 2.0)
        except Exception as e:
            self._log(f"OAuth 再登录处理异常: {e}", "warning")
        return handled

    def _build_oauth_authorize_url(self, auth_url: str) -> str:
        """移除 prompt=login，优先复用已登录会话。"""
        try:
            parsed = urlparse(auth_url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: (v[-1] if isinstance(v, list) and v else v) for k, v in query.items()}
            params.pop("prompt", None)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
        except Exception:
            return auth_url

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
        while (time.time() - start) * 1000 < timeout_ms:
            if callback_holder["url"]:
                return callback_holder["url"]
            try:
                current = page.url
                if current and "code=" in current and "state=" in current:
                    return current
            except Exception:
                pass
            time.sleep(0.2)
        return ""

    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [Browser] {message}"
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if level == "error": logger.error(message)
        elif level == "warning": logger.warning(message)
        else: logger.info(message)

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
            
    def _random_delay(self, low=0.5, high=2.0):
        time.sleep(random.uniform(low, high))

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

        self._log(f"使用有头浏览器注册，分配邮箱: {self.email}")
        
        with sync_playwright() as p:
            launch_args = {
                "headless": False,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--incognito",
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
            refresh_state = {"count": 0}
            
            try:
                self._log("访问 ChatGPT 首页获取验证环境...")
                # 先访问首页，获取正常的 session 状态
                page.goto("https://chatgpt.com/", wait_until="commit", timeout=60000)
                
                try:
                    page.wait_for_selector('[data-testid="signup-button"], [data-testid="login-button"]', timeout=30000)
                    self._random_delay(2.0, 3.5)
                    self._log("触发注册/登录按钮...")
                    
                    if page.locator('[data-testid="signup-button"]').count() > 0:
                        page.locator('[data-testid="signup-button"]').first.click(force=True)
                    elif page.locator('[data-testid="login-button"]').count() > 0:
                        page.locator('[data-testid="login-button"]').first.click(force=True)
                        
                    self._random_delay(2.0, 4.0)

                    # 给前端一点缓冲时间，避免误判“卡住”
                    try:
                        page.wait_for_url("**/auth/**", timeout=8000)
                    except Exception:
                        try:
                            page.wait_for_url("**/login**", timeout=8000)
                        except Exception:
                            pass
                    
                    if "/auth/" not in page.url and "/login" not in page.url:
                        self._log("前端响应缓慢或失败，尝试刷新页面重试...", "warning")
                        self._maybe_refresh(page, "首页按钮未跳转", refresh_state)
                        if page.locator('[data-testid="signup-button"]').count() > 0:
                            page.locator('[data-testid="signup-button"]').first.click(force=True)
                        elif page.locator('[data-testid="login-button"]').count() > 0:
                            page.locator('[data-testid="login-button"]').first.click(force=True)
                except Exception as e:
                    self._log(f"未找到首页按钮或操作异常: {e}", "warning")
                
                # 等待输入邮箱的界面
                page.wait_for_selector("input[type='email']", timeout=60000)
                self._random_delay(2.0, 4.0)
                self._log("填写邮箱...")
                page.fill("input[type='email']", self.email)
                self._random_delay(1.0, 2.0)
                if not self._safe_click(page, "button[type='submit']", refresh_state, "提交邮箱"):
                    self._log("提交邮箱失败，尝试继续流程", "warning")
                self._debug_pause(page, "已提交邮箱")
                
                # 使用更智能的状态机处理不确定的验证链路：可能是密码->OTP->信息，也可能是OTP->信息 等等。
                # 使用状态机记录已完成的操作，防止由于页面跳转慢导致重复匹配和死循环
                done_password = False
                done_otp = False
                done_profile = False
                
                for _step in range(6):
                    try:
                        self._log("等待进入下一个验证环节...")
                        
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
                            age_num = datetime.now().year - b_year
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
                        break # 到此处验证链条就正式结束了
                        
                    # 如果当前没命中上述可见模块，可能已经过渡到一个新 URL，或者是跳过了某些步骤
                    if "chatgpt.com" in page.url and "auth" not in page.url:
                        break
                
                # 等待最终跳转回 ChatGPT，获取 /api/auth/session
                self._log("等待最终认证完成...")
                page.wait_for_url("**/chatgpt.com**", timeout=45000)
                
                self._log("导航到 /api/auth/session 读取 tokens...")
                page.goto("https://chatgpt.com/api/auth/session")
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
                            "registered_at": datetime.now().isoformat()
                        }
                        
                        # ======== 新增步骤: 获取官方持久化 OAuth Token ========
                        if self.skip_oauth:
                            self._log("已配置跳过 OAuth 授权流程 (BROWSER_SKIP_OAUTH=1)", "warning")
                        else:
                            try:
                                from .openai.oauth import generate_oauth_url, submit_callback_url
                                self._log("启动最后一步：获取正式的 OAuth Refresh Token！")
                                oauth_info = generate_oauth_url()
                                authorize_url = self._build_oauth_authorize_url(oauth_info.auth_url)
                                page.goto(authorize_url)
                                self._random_delay(1.0, 2.0)
                                self._handle_oauth_relogin(page)

                                callback_url = self._capture_oauth_callback(page, timeout_ms=20000)
                                if not callback_url:
                                    self._log("试图点击授权界面的 Continue/Allow 等确认许可键...")
                                    btn_locator = page.locator("button:has-text('Allow'), button:has-text('Authorize'), button:has-text('Continue'), div[role='button']")
                                    if btn_locator.count() > 0:
                                        for i in range(btn_locator.count()):
                                            if btn_locator.nth(i).is_visible():
                                                btn_locator.nth(i).click()
                                                break
                                    else:
                                        self._handle_oauth_relogin(page)

                                    callback_url = self._capture_oauth_callback(page, timeout_ms=15000)

                                if not callback_url:
                                    body_text = page.locator("body").inner_text()[:400]
                                    self._log(f"授权回调未能自动触发，当前页面内容卡在: {body_text}", "warning")
                                    if self._maybe_refresh(page, "OAuth 授权未跳转", refresh_state):
                                        self._handle_oauth_relogin(page)
                                        callback_url = self._capture_oauth_callback(page, timeout_ms=10000)

                                final_oauth_url = callback_url or page.url
                                if "code=" not in final_oauth_url or "state=" not in final_oauth_url:
                                    raise RuntimeError("未捕捉到 OAuth 回调 code/state")

                                self._log("成功捕捉到 Code，正在调用接口进行兑换...")
                                tokens_json = submit_callback_url(
                                    callback_url=final_oauth_url,
                                    expected_state=oauth_info.state,
                                    code_verifier=oauth_info.code_verifier,
                                    proxy_url=self.proxy_url
                                )
                                import json as token_json
                                oauth_tokens = token_json.loads(tokens_json)
                                if oauth_tokens.get("access_token") and oauth_tokens.get("refresh_token"):
                                    result.access_token = oauth_tokens["access_token"]
                                    result.refresh_token = oauth_tokens["refresh_token"]
                                    result.id_token = oauth_tokens.get("id_token", "")
                                    result.metadata["token_source"] = "browser_oauth"
                                    self._log("🎉 正式授权 Token (附带无限续期 Refresh Token) 提取成功！")
                                else:
                                    self._log("未能获取到完整的 OAuth token 信息", "warning")
                            except Exception as oauth_e:
                                self._log(f"附加 OAuth 授权流程被拦截 (最初获得的 Session Key 可能仍然可用): {oauth_e}", "warning")
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
                if self.keep_browser_open:
                    self._log("调试模式已开启，浏览器保持打开（手动关闭窗口后继续）。", "warning")
                    try:
                        page.wait_for_event("close", timeout=0)
                    except Exception:
                        pass
                browser.close()
                
        # To get the account ID, we might need a JWT decode or similar logic
        if result.success and result.access_token:
            from .register import _extract_account_id_from_jwt
            aid = _extract_account_id_from_jwt(result.access_token)
            if aid: result.account_id = aid
            
        return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success: return False
        try:
            from ..config.settings import get_settings
            from ..database import crud
            from ..database.session import get_db
            settings = get_settings()
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
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
