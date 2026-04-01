import base64
import json
import time
from types import SimpleNamespace

from src.config.constants import EmailServiceType, OPENAI_API_ENDPOINTS, OPENAI_PAGE_TYPES
from src.core.http_client import OpenAIHTTPClient
from src.core.openai.oauth import OAuthStart
import src.core.register as register_module
from src.core.register import RegistrationEngine, SignupFormResult
from src.services.base import BaseEmailService


class DummyResponse:
    def __init__(self, status_code=200, payload=None, text="", headers=None, on_return=None, url=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}
        self.on_return = on_return
        self.url = url

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class QueueSession:
    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []
        self.cookies = {}

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._request(method.upper(), url, **kwargs)

    def close(self):
        return None

    def _request(self, method, url, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "kwargs": kwargs,
        })
        if not self.steps:
            raise AssertionError(f"unexpected request: {method} {url}")
        expected_method, expected_url, response = self.steps.pop(0)
        assert method == expected_method
        assert url == expected_url
        if callable(response):
            response = response(self)
        if not getattr(response, "url", ""):
            response.url = url
        if response.on_return:
            response.on_return(self)
        return response


class FakeEmailService(BaseEmailService):
    def __init__(self, codes):
        super().__init__(EmailServiceType.TEMPMAIL)
        self.codes = list(codes)
        self.otp_requests = []

    def create_email(self, config=None):
        return {
            "email": "tester@example.com",
            "service_id": "mailbox-1",
        }

    def get_verification_code(self, email, email_id=None, timeout=120, pattern=r"(?<!\d)(\d{6})(?!\d)", otp_sent_at=None):
        self.otp_requests.append({
            "email": email,
            "email_id": email_id,
            "otp_sent_at": otp_sent_at,
        })
        if not self.codes:
            raise AssertionError("no verification code queued")
        return self.codes.pop(0)

    def list_emails(self, **kwargs):
        return []

    def delete_email(self, email_id):
        return True

    def check_health(self):
        return True


class FakeOAuthManager:
    def __init__(self):
        self.start_calls = 0
        self.callback_calls = []

    def start_oauth(self):
        self.start_calls += 1
        return OAuthStart(
            auth_url=f"https://auth.example.test/flow/{self.start_calls}",
            state=f"state-{self.start_calls}",
            code_verifier=f"verifier-{self.start_calls}",
            redirect_uri="http://localhost:1455/auth/callback",
        )

    def handle_callback(self, callback_url, expected_state, code_verifier):
        self.callback_calls.append({
            "callback_url": callback_url,
            "expected_state": expected_state,
            "code_verifier": code_verifier,
        })
        return {
            "account_id": "acct-1",
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "id_token": "id-1",
        }


class FakeOpenAIClient:
    def __init__(self, sessions, sentinel_tokens):
        self._sessions = list(sessions)
        self._session_index = 0
        self._session = self._sessions[0]
        self._sentinel_tokens = list(sentinel_tokens)

    @property
    def session(self):
        return self._session

    def check_ip_location(self):
        return True, "US"

    def check_sentinel(self, did):
        if not self._sentinel_tokens:
            raise AssertionError("no sentinel token queued")
        return self._sentinel_tokens.pop(0)

    def close(self):
        if self._session_index + 1 < len(self._sessions):
            self._session_index += 1
            self._session = self._sessions[self._session_index]


def _workspace_cookie(workspace_id):
    payload = base64.urlsafe_b64encode(
        json.dumps({"workspaces": [{"id": workspace_id}]}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"{payload}.sig"


def _response_with_did(did):
    return DummyResponse(
        status_code=200,
        text="ok",
        on_return=lambda session: session.cookies.__setitem__("oai-did", did),
    )


def _response_with_login_cookies(workspace_id="ws-1", session_token="session-1"):
    def setter(session):
        session.cookies["oai-client-auth-session"] = _workspace_cookie(workspace_id)
        session.cookies["__Secure-next-auth.session-token"] = session_token

    return DummyResponse(status_code=200, payload={}, on_return=setter)


def test_check_sentinel_sends_non_empty_pow(monkeypatch):
    session = QueueSession([
        ("POST", OPENAI_API_ENDPOINTS["sentinel"], DummyResponse(payload={"token": "sentinel-token"})),
    ])
    client = OpenAIHTTPClient()
    client._session = session

    monkeypatch.setattr(
        "src.core.http_client.build_sentinel_pow_token",
        lambda user_agent: "gAAAAACpow-token",
    )

    token = client.check_sentinel("device-1")

    assert token == "sentinel-token"
    body = json.loads(session.calls[0]["kwargs"]["data"])
    assert body["id"] == "device-1"
    assert body["flow"] == "authorize_continue"
    assert body["p"] == "gAAAAACpow-token"


def test_run_registers_then_relogs_to_fetch_token():
    session_one = QueueSession([
        ("GET", "https://auth.example.test/flow/1", _response_with_did("did-1")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["PASSWORD_REGISTRATION"]}}),
        ),
        ("POST", OPENAI_API_ENDPOINTS["register"], DummyResponse(payload={})),
        ("GET", OPENAI_API_ENDPOINTS["send_otp"], DummyResponse(payload={})),
        ("POST", OPENAI_API_ENDPOINTS["validate_otp"], DummyResponse(payload={})),
        ("POST", OPENAI_API_ENDPOINTS["create_account"], DummyResponse(payload={})),
    ])
    session_two = QueueSession([
        ("GET", "https://auth.example.test/flow/2", _response_with_did("did-2")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]}}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["password_verify"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]}}),
        ),
        ("POST", OPENAI_API_ENDPOINTS["validate_otp"], _response_with_login_cookies()),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue"}),
        ),
        (
            "GET",
            "https://auth.example.test/continue",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-2&state=state-2"},
            ),
        ),
    ])

    email_service = FakeEmailService(["123456", "654321"])
    engine = RegistrationEngine(email_service)
    fake_oauth = FakeOAuthManager()
    engine.http_client = FakeOpenAIClient([session_one, session_two], ["sentinel-1", "sentinel-2"])
    engine.oauth_manager = fake_oauth

    result = engine.run()

    assert result.success is True
    assert result.source == "register"
    assert result.workspace_id == "ws-1"
    assert result.session_token == "session-1"
    assert fake_oauth.start_calls == 2
    assert len(email_service.otp_requests) == 2
    assert all(item["otp_sent_at"] is not None for item in email_service.otp_requests)
    assert sum(1 for call in session_one.calls if call["url"] == OPENAI_API_ENDPOINTS["send_otp"]) == 1
    assert sum(1 for call in session_two.calls if call["url"] == OPENAI_API_ENDPOINTS["send_otp"]) == 0
    assert sum(1 for call in session_one.calls if call["url"] == OPENAI_API_ENDPOINTS["select_workspace"]) == 0
    assert sum(1 for call in session_two.calls if call["url"] == OPENAI_API_ENDPOINTS["select_workspace"]) == 1
    relogin_start_body = json.loads(session_two.calls[1]["kwargs"]["data"])
    assert relogin_start_body["screen_hint"] == "login"
    assert relogin_start_body["username"]["value"] == "tester@example.com"
    password_verify_body = json.loads(session_two.calls[2]["kwargs"]["data"])
    assert password_verify_body == {"password": result.password}
    assert result.metadata["token_acquired_via_relogin"] is True


def test_existing_account_login_uses_auto_sent_otp_without_manual_send():
    session = QueueSession([
        ("GET", "https://auth.example.test/flow/1", _response_with_did("did-1")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]}}),
        ),
        ("POST", OPENAI_API_ENDPOINTS["validate_otp"], _response_with_login_cookies("ws-existing", "session-existing")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-existing"}),
        ),
        (
            "GET",
            "https://auth.example.test/continue-existing",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-1&state=state-1"},
            ),
        ),
    ])

    email_service = FakeEmailService(["246810"])
    engine = RegistrationEngine(email_service)
    fake_oauth = FakeOAuthManager()
    engine.http_client = FakeOpenAIClient([session], ["sentinel-1"])
    engine.oauth_manager = fake_oauth

    result = engine.run()

    assert result.success is True
    assert result.source == "login"
    assert fake_oauth.start_calls == 1
    assert sum(1 for call in session.calls if call["url"] == OPENAI_API_ENDPOINTS["send_otp"]) == 0
    assert len(email_service.otp_requests) == 1
    assert email_service.otp_requests[0]["otp_sent_at"] is not None
    assert result.metadata["token_acquired_via_relogin"] is False


def test_handle_about_you_treats_409_as_continue(monkeypatch):
    email_service = FakeEmailService(["123456"])
    engine = RegistrationEngine(email_service)

    callback_counter = {"count": 0}

    engine.create_account = lambda name, birthdate, so_token=None: (409, {"error": "already_exists"})
    engine.callback = lambda: callback_counter.__setitem__("count", callback_counter["count"] + 1)

    assert engine._handle_about_you("登录密码阶段") is True
    assert callback_counter["count"] == 1


def test_handle_about_you_treats_registration_disallowed_400_as_continue(monkeypatch):
    email_service = FakeEmailService(["123456"])
    engine = RegistrationEngine(email_service)

    callback_counter = {"count": 0}

    engine.create_account = lambda name, birthdate, so_token=None: (
        400,
        {"error": "registration_disallowed"},
    )
    engine.callback = lambda: callback_counter.__setitem__("count", callback_counter["count"] + 1)

    assert engine._handle_about_you("登录密码阶段") is True
    assert callback_counter["count"] == 1


def test_oauth_login_flow_about_you_can_continue_without_waiting_otp(monkeypatch):
    email_service = FakeEmailService(["123456"])
    engine = RegistrationEngine(email_service)
    engine.email = "tester@example.com"
    engine.password = "pass-1234"

    class DummyOAuthManager:
        def __init__(self, *args, **kwargs):
            pass

        def start_oauth(self):
            return OAuthStart(
                auth_url="https://auth.example.test/flow/1",
                state="state-1",
                code_verifier="verifier-1",
                redirect_uri="http://localhost:1455/auth/callback",
            )

    class DummyHttpClient:
        def __init__(self, proxy_url=None):
            self.session = SimpleNamespace(cookies={"__Secure-next-auth.session-token": "session-from-login"})

        def check_sentinel(self, did):
            return "sentinel-token"

    monkeypatch.setattr("src.core.register.OAuthManager", DummyOAuthManager)
    monkeypatch.setattr("src.core.register.OpenAIHTTPClient", DummyHttpClient)

    monkeypatch.setattr(engine, "_oauth_get_device_id", lambda session, auth_url: "did-1")
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_start",
        lambda session, did, sen: SignupFormResult(
            success=True,
            page_type=OPENAI_PAGE_TYPES["LOGIN_PASSWORD"],
            is_existing_account=False,
        ),
    )
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_password",
        lambda session: SignupFormResult(
            success=True,
            page_type="about_you",
            is_existing_account=False,
        ),
    )
    monkeypatch.setattr(engine, "_handle_about_you", lambda source: True)
    monkeypatch.setattr(engine, "_oauth_exchange_auth_code", lambda session, oauth_start: "auth-code-1")
    monkeypatch.setattr(
        engine,
        "_oauth_handle_callback",
        lambda oauth_manager, oauth_start, callback_url: {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "id_token": "id-1",
        },
    )

    def fail_if_wait_otp(timeout=120):
        raise AssertionError("about-you 分支不应触发邮箱验证码等待")

    monkeypatch.setattr(engine, "wait_for_verification_email", fail_if_wait_otp)

    token_info = engine._get_oauth_tokens_via_login_flow()

    assert token_info is not None
    assert token_info["access_token"] == "access-1"
    assert engine._oauth_session_token == "session-from-login"


def test_oauth_login_flow_about_you_triggers_recovery_when_code_missing(monkeypatch):
    email_service = FakeEmailService(["123456"])
    engine = RegistrationEngine(email_service)
    engine.email = "tester@example.com"
    engine.password = "pass-1234"

    class DummyOAuthManager:
        def __init__(self, *args, **kwargs):
            pass

        def start_oauth(self):
            return OAuthStart(
                auth_url="https://auth.example.test/flow/1",
                state="state-1",
                code_verifier="verifier-1",
                redirect_uri="http://localhost:1455/auth/callback",
            )

    class DummyHttpClient:
        def __init__(self, proxy_url=None):
            self.session = SimpleNamespace(cookies={"__Secure-next-auth.session-token": "session-after-recovery"})

        def check_sentinel(self, did):
            return "sentinel-token"

    monkeypatch.setattr("src.core.register.OAuthManager", DummyOAuthManager)
    monkeypatch.setattr("src.core.register.OpenAIHTTPClient", DummyHttpClient)

    monkeypatch.setattr(engine, "_oauth_get_device_id", lambda session, auth_url: "did-1")
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_start",
        lambda session, did, sen: SignupFormResult(
            success=True,
            page_type=OPENAI_PAGE_TYPES["LOGIN_PASSWORD"],
            is_existing_account=False,
        ),
    )
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_password",
        lambda session: SignupFormResult(
            success=True,
            page_type="about_you",
            is_existing_account=False,
        ),
    )
    monkeypatch.setattr(engine, "_handle_about_you", lambda source: True)
    monkeypatch.setattr(engine, "_oauth_exchange_auth_code", lambda session, oauth_start: None)

    recovery_calls = {"count": 0}

    def _fake_recovery(session, oauth_start, did, sen_token):
        recovery_calls["count"] += 1
        assert did == "did-1"
        return "auth-code-recovered"

    monkeypatch.setattr(engine, "_oauth_recover_after_about_you_without_otp", _fake_recovery)
    monkeypatch.setattr(
        engine,
        "_oauth_handle_callback",
        lambda oauth_manager, oauth_start, callback_url: {
            "access_token": "access-recovered",
            "refresh_token": "refresh-recovered",
            "id_token": "id-recovered",
        },
    )

    token_info = engine._get_oauth_tokens_via_login_flow()

    assert token_info is not None
    assert token_info["access_token"] == "access-recovered"
    assert recovery_calls["count"] == 1
    assert engine._oauth_session_token == "session-after-recovery"


def test_oauth_rate_limit_sets_global_cooldown_and_short_backoff(monkeypatch):
    email_service = FakeEmailService(["123456"])
    engine = RegistrationEngine(email_service)
    engine.oauth_rate_limit_cooldown_seconds = 300
    engine.oauth_rate_limit_backoff_base_seconds = 7
    engine.oauth_rate_limit_backoff_max_seconds = 60

    register_module._OAUTH_RATE_LIMIT_UNTIL_TS = 0.0
    sleep_calls = []
    monkeypatch.setattr("src.core.register.time.sleep", lambda seconds: sleep_calls.append(seconds))

    engine._oauth_handle_rate_limit(2, stage="单元测试")

    assert sleep_calls == [14]
    assert register_module._OAUTH_RATE_LIMIT_UNTIL_TS > time.time() + 250


def test_oauth_login_flow_rate_limited_stops_immediately(monkeypatch):
    email_service = FakeEmailService(["123456"])
    engine = RegistrationEngine(email_service)
    engine.email = "tester@example.com"
    engine.password = "pass-1234"
    engine.oauth_rate_limit_cooldown_seconds = 300
    engine.oauth_rate_limit_backoff_base_seconds = 5
    engine.oauth_rate_limit_backoff_max_seconds = 60

    class DummyOAuthManager:
        def __init__(self, *args, **kwargs):
            pass

        def start_oauth(self):
            return OAuthStart(
                auth_url="https://auth.example.test/flow/1",
                state="state-1",
                code_verifier="verifier-1",
                redirect_uri="http://localhost:1455/auth/callback",
            )

    class DummyHttpClient:
        def __init__(self, proxy_url=None):
            self.session = SimpleNamespace(cookies={})

        def check_sentinel(self, did):
            return "sentinel-token"

    register_module._OAUTH_RATE_LIMIT_UNTIL_TS = 0.0
    sleep_calls = []
    monkeypatch.setattr("src.core.register.time.sleep", lambda seconds: sleep_calls.append(seconds))
    monkeypatch.setattr("src.core.register.OAuthManager", DummyOAuthManager)
    monkeypatch.setattr("src.core.register.OpenAIHTTPClient", DummyHttpClient)
    monkeypatch.setattr(engine, "_oauth_get_device_id", lambda session, auth_url: "did-1")
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_start",
        lambda session, did, sen: SignupFormResult(
            success=False,
            error_message="HTTP 429: rate limit exceeded",
        ),
    )

    token_info = engine._get_oauth_tokens_via_login_flow()

    assert token_info is None
    assert sleep_calls == [5]


def test_oauth_submit_consent_form_prefers_real_form_submit_and_follows_callback():
    session = QueueSession([
        (
            "POST",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-consent-1&state=state-1"},
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    html_text = """
    <html>
      <form action="/sign-in-with-chatgpt/codex/consent" method="post">
        <input type="hidden" name="csrf_token" value="csrf-1" />
        <button name="decision" value="allow">Continue</button>
      </form>
    </html>
    """

    code = engine._oauth_submit_consent_form(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        html_text=html_text,
        redirect_uri="http://localhost:1455/auth/callback",
    )

    assert code == "code-consent-1"
    assert session.calls[0]["url"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    post_data = session.calls[0]["kwargs"]["data"]
    assert post_data["csrf_token"] == "csrf-1"
    assert "action" not in post_data


def test_oauth_submit_consent_form_falls_back_to_authorize_continue_api():
    session = QueueSession([
        (
            "POST",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                status_code=405,
                text="method not allowed",
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            ),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(
                status_code=200,
                payload={"continue_url": "https://auth.example.test/continue-api"},
                text='{"continue_url":"https://auth.example.test/continue-api"}',
                url=OPENAI_API_ENDPOINTS["signup"],
            ),
        ),
        (
            "GET",
            "https://auth.example.test/continue-api",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-consent-2&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    engine.oauth_enable_workspace_fallback = True
    html_text = """
    <html>
      <form action="/sign-in-with-chatgpt/codex/consent" method="post">
        <input type="hidden" name="workspace_id" value="ws-consent-2" />
        <input type="hidden" name="csrf_token" value="csrf-2" />
        <button name="decision" value="allow">Continue</button>
      </form>
    </html>
    """

    code = engine._oauth_submit_consent_form(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        html_text=html_text,
        redirect_uri="http://localhost:1455/auth/callback",
    )

    assert code == "code-consent-2"
    # 第 1 次是真实 consent 表单提交，第 2 次才是 authorize/continue API 兜底
    assert session.calls[0]["url"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    assert session.calls[1]["url"] == OPENAI_API_ENDPOINTS["signup"]
    api_data = json.loads(session.calls[1]["kwargs"]["data"])
    assert api_data == {}


def test_oauth_submit_consent_form_405_uses_continue_api_without_workspace_fallback():
    session = QueueSession([
        (
            "POST",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                status_code=405,
                text="method not allowed",
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            ),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(
                status_code=200,
                payload={"continue_url": "https://auth.example.test/continue-405-no-ws"},
                text='{"continue_url":"https://auth.example.test/continue-405-no-ws"}',
                url=OPENAI_API_ENDPOINTS["signup"],
            ),
        ),
        (
            "GET",
            "https://auth.example.test/continue-405-no-ws",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-consent-405&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    # 默认关闭 workspace 旁路
    engine.oauth_enable_workspace_fallback = False
    html_text = """
    <html>
      <form action="/sign-in-with-chatgpt/codex/consent" method="post">
        <input type="hidden" name="csrf_token" value="csrf-405" />
        <button name="decision" value="allow">Continue</button>
      </form>
    </html>
    """

    code = engine._oauth_submit_consent_form(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        html_text=html_text,
        redirect_uri="http://localhost:1455/auth/callback",
    )

    assert code == "code-consent-405"
    assert session.calls[0]["url"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    assert session.calls[1]["url"] == OPENAI_API_ENDPOINTS["signup"]


def test_oauth_submit_consent_form_sets_default_action_for_authorize_continue_form():
    session = QueueSession([
        (
            "POST",
            "https://auth.openai.com/api/accounts/authorize/continue",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-consent-3&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    html_text = """
    <html>
      <form action="/api/accounts/authorize/continue" method="post">
        <input type="hidden" name="csrf_token" value="csrf-3" />
        <button type="submit">继续</button>
      </form>
    </html>
    """

    code = engine._oauth_submit_consent_form(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        html_text=html_text,
        redirect_uri="http://localhost:1455/auth/callback",
    )

    assert code == "code-consent-3"
    post_data = session.calls[0]["kwargs"]["data"]
    assert post_data["csrf_token"] == "csrf-3"
    assert post_data["action"] == "default"


def test_oauth_exchange_auth_code_visits_oauth_authorize_entry_first():
    session = QueueSession([
        (
            "GET",
            "https://auth.example.test/flow/1",
            DummyResponse(
                status_code=302,
                headers={"Location": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?flow=abc"},
            ),
        ),
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?flow=abc",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-entry-1&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    oauth_start = OAuthStart(
        auth_url="https://auth.example.test/flow/1",
        state="state-1",
        code_verifier="verifier-1",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    code = engine._oauth_exchange_auth_code(session, oauth_start)

    assert code == "code-entry-1"


def test_oauth_exchange_auth_code_uses_workspace_fallback_when_enabled():
    session = QueueSession([
        (
            "GET",
            "https://auth.example.test/flow/1",
            DummyResponse(
                status_code=302,
                headers={"Location": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?flow=xyz"},
            ),
        ),
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?flow=xyz",
            DummyResponse(
                status_code=200,
                text="""
                <html>
                  <form method="post" action="/sign-in-with-chatgpt/codex/consent">
                    <input type="hidden" name="workspace_id" value="ws-from-consent" />
                    <button type="submit">继续</button>
                  </form>
                </html>
                """,
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent?flow=xyz",
            ),
        ),
        (
            "POST",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                status_code=405,
                text="method not allowed",
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            ),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(
                status_code=200,
                payload={"continue_url": "https://auth.example.test/continue-ws"},
                text='{"continue_url":"https://auth.example.test/continue-ws"}',
            ),
        ),
        (
            "GET",
            "https://auth.example.test/continue-ws",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-ws-1&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    engine.oauth_enable_workspace_fallback = True
    engine._oauth_get_workspace_id = lambda *_args, **_kwargs: "ws-from-consent"
    oauth_start = OAuthStart(
        auth_url="https://auth.example.test/flow/1",
        state="state-1",
        code_verifier="verifier-1",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    code = engine._oauth_exchange_auth_code(session, oauth_start)

    assert code == "code-ws-1"


def test_extract_navigation_url_skips_static_asset_and_prefers_auth_url():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    text = """
    <html>
      <link href="https://cdn.openai.com/common/fonts/openai-sans/v2/OpenAISans-Regular.woff2" />
      <script>
        const a = "https://cdn.openai.com/assets/app.js";
        const b = "https://auth.openai.com/oauth/authorize/resume?flow=1";
      </script>
    </html>
    """
    nav_url = engine._extract_navigation_url_from_html(
        text,
        base_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
    )
    assert nav_url == "https://auth.openai.com/oauth/authorize/resume?flow=1"


def test_extract_redirect_from_html_supports_chrome_error_reload_url():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    html_text = """
    <button id="reload-button" data-url="http://localhost:1455/auth/callback?code=ac_test_1&amp;scope=openid&amp;state=state-1"></button>
    <script>
      var loadTimeDataRaw = {
        "reloadUrl":"http://localhost:1455/auth/callback?code=ac_test_1\\u0026scope=openid\\u0026state=state-1"
      };
    </script>
    """
    callback_url = engine._extract_redirect_from_html(
        html_text,
        "http://localhost:1455/auth/callback",
    )
    assert callback_url is not None
    assert "code=ac_test_1" in callback_url
    assert "state=state-1" in callback_url


def test_oauth_follow_and_extract_code_supports_chrome_error_reload_url():
    session = QueueSession([
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                status_code=200,
                text=(
                    '<button id="reload-button" '
                    'data-url="http://localhost:1455/auth/callback?code=code-html-1&amp;state=state-1"></button>'
                ),
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    code = engine._oauth_follow_and_extract_code(
        session,
        "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
    )
    assert code == "code-html-1"


def test_extract_workspace_id_from_html_supports_value_before_name():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    html_text = """
    <form method="post" action="/sign-in-with-chatgpt/codex/consent">
      <input id="_r_1f_-workspace_id" form="_r_1f_" type="hidden"
             value="ws-order-1" name="workspace_id">
      <button type="submit">继续</button>
    </form>
    """
    workspace_id = engine._extract_workspace_id_from_html(html_text)
    assert workspace_id == "ws-order-1"


def test_extract_workspace_id_from_html_supports_default_workspace_id():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    html_text = """
    <script id="bootstrap-inert-script" type="application/json">
      {"default_workspace_id":"ws-default-1"}
    </script>
    """
    workspace_id = engine._extract_workspace_id_from_html(html_text)
    assert workspace_id == "ws-default-1"


def test_extract_workspace_id_from_html_supports_workspaces_array():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    html_text = """
    <script type="application/json">
      {"workspaces":[{"id":"ws-array-1"},{"id":"ws-array-2"}]}
    </script>
    """
    workspace_id = engine._extract_workspace_id_from_html(html_text)
    assert workspace_id == "ws-array-1"


def test_extract_workspace_id_from_html_supports_escaped_bootstrap_payload():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    ws_id = "5cddda31-082a-45fc-8ca2-7f4b96d14a0a"
    html_text = rf"""
    <script id="bootstrap-inert-script" type="application/json">
      {{"payload":"{{\\\"account\\\":{{\\\"id\\\":\\\"{ws_id}\\\"}}}}"}}
    </script>
    """
    workspace_id = engine._extract_workspace_id_from_html(html_text)
    assert workspace_id == ws_id


def test_oauth_submit_consent_form_uses_workspace_from_cookie_when_405_and_fallback_enabled():
    session = QueueSession([
        (
            "POST",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                status_code=405,
                text="method not allowed",
                url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            ),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(
                status_code=200,
                payload={"continue_url": "https://auth.example.test/continue-cookie-ws"},
                text='{"continue_url":"https://auth.example.test/continue-cookie-ws"}',
            ),
        ),
        (
            "GET",
            "https://auth.example.test/continue-cookie-ws",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-cookie-ws-1&state=state-1"},
            ),
        ),
    ])
    session.cookies["oai-client-auth-session"] = _workspace_cookie("ws-cookie-1")
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    engine.oauth_enable_workspace_fallback = True
    html_text = """
    <form action="/sign-in-with-chatgpt/codex/consent" method="post">
      <button type="submit">继续</button>
    </form>
    """

    code = engine._oauth_submit_consent_form(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        html_text=html_text,
        redirect_uri="http://localhost:1455/auth/callback",
    )

    assert code == "code-cookie-ws-1"


def test_extract_workspace_id_from_cookie_supports_plain_json():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    raw_cookie = '{"default_workspace_id":"ws-json-1","workspaces":[{"id":"ws-json-2"}]}'
    workspace_id = engine._extract_workspace_id_from_cookie(raw_cookie)
    assert workspace_id == "ws-json-1"


def test_extract_workspace_id_from_cookie_supports_account_id_plain_json():
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    ws_id = "5cddda31-082a-45fc-8ca2-7f4b96d14a0a"
    raw_cookie = f'{{"account_id":"{ws_id}"}}'
    workspace_id = engine._extract_workspace_id_from_cookie(raw_cookie)
    assert workspace_id == ws_id


def test_oauth_get_workspace_id_falls_back_to_authorize_url_page():
    oauth_auth_url = (
        "https://auth.openai.com/oauth/authorize?"
        "client_id=app_xxx&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"
    )
    session = QueueSession([
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(
                status_code=401,
                text='{"error":"unauthorized"}',
                url="https://chatgpt.com/api/auth/session",
            ),
        ),
        (
            "GET",
            "https://auth.openai.com/api/auth/session",
            DummyResponse(
                status_code=401,
                text='{"error":"unauthorized"}',
                url="https://auth.openai.com/api/auth/session",
            ),
        ),
        (
            "GET",
            oauth_auth_url,
            DummyResponse(
                status_code=200,
                text='<script type="application/json">{"default_workspace_id":"ws-auth-1"}</script>',
                url=oauth_auth_url,
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    workspace_id = engine._oauth_get_workspace_id(
        session=session,
        consent_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        authorize_url=oauth_auth_url,
    )

    assert workspace_id == "ws-auth-1"


def test_oauth_get_workspace_id_scans_all_cookie_names():
    session = QueueSession([])
    session.cookies["unified_session_manifest"] = '{"default_workspace_id":"ws-manifest-1"}'
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    workspace_id = engine._oauth_get_workspace_id(
        session=session,
        probe_pages=False,
    )

    assert workspace_id == "ws-manifest-1"


def test_oauth_get_workspace_id_falls_back_to_chatgpt_session_account_id():
    ws_id = "5cddda31-082a-45fc-8ca2-7f4b96d14a0a"
    session = QueueSession([
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(
                status_code=200,
                payload={"account": {"id": ws_id}},
                text=f'{{"account":{{"id":"{ws_id}"}}}}',
                url="https://chatgpt.com/api/auth/session",
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    workspace_id = engine._oauth_get_workspace_id(
        session=session,
        probe_pages=False,
    )

    assert workspace_id == ws_id


def test_oauth_get_workspace_id_falls_back_to_auth_session_account_id():
    ws_id = "5cddda31-082a-45fc-8ca2-7f4b96d14a0a"
    session = QueueSession([
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(
                status_code=401,
                text='{"error":"unauthorized"}',
                url="https://chatgpt.com/api/auth/session",
            ),
        ),
        (
            "GET",
            "https://auth.openai.com/api/auth/session",
            DummyResponse(
                status_code=200,
                payload={"account": {"id": ws_id}},
                text=f'{{"account":{{"id":"{ws_id}"}}}}',
                url="https://auth.openai.com/api/auth/session",
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    workspace_id = engine._oauth_get_workspace_id(
        session=session,
        probe_pages=False,
    )

    assert workspace_id == ws_id


def test_oauth_select_workspace_accepts_redirect_location():
    session = QueueSession([
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-ws-redirect-1&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    continue_url = engine._oauth_select_workspace(session, "ws-redirect-1")

    assert continue_url == "http://localhost:1455/auth/callback?code=code-ws-redirect-1&state=state-1"


def test_register_retries_on_transient_502_and_succeeds(monkeypatch):
    session = QueueSession([
        (
            "POST",
            OPENAI_API_ENDPOINTS["register"],
            DummyResponse(status_code=502, text="<html>bad gateway</html>"),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["register"],
            DummyResponse(status_code=200, payload={}),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))
    engine.session = session
    engine.device_id = "device-1"
    engine.ua = "ua-test"
    engine.sec_ch_ua = '"Chromium";v="136"'
    engine.impersonate = "chrome136"

    monkeypatch.setattr("src.core.register.time.sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("src.core.register.build_sentinel_token", lambda *args, **kwargs: "sentinel-refreshed")

    status, data = engine.register(
        email="tester@example.com",
        password="pass-1234",
        sentinel_token="sentinel-initial",
    )

    assert status == 200
    assert data == {}
    first_headers = session.calls[0]["kwargs"]["headers"]
    second_headers = session.calls[1]["kwargs"]["headers"]
    assert first_headers.get("openai-sentinel-token") == "sentinel-initial"
    assert second_headers.get("openai-sentinel-token") == "sentinel-refreshed"


def test_oauth_submit_authorize_continue_api_extracts_workspace_from_payload():
    session = QueueSession([
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(
                status_code=200,
                payload={"data": {"workspaces": [{"id": "ws-from-api"}]}},
                text='{"data":{"workspaces":[{"id":"ws-from-api"}]}}',
                url=OPENAI_API_ENDPOINTS["signup"],
            ),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(
                status_code=200,
                payload={"continue_url": "https://auth.example.test/continue-api-ws"},
                text='{"continue_url":"https://auth.example.test/continue-api-ws"}',
            ),
        ),
        (
            "GET",
            "https://auth.example.test/continue-api-ws",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-api-ws-1&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    code = engine._oauth_submit_authorize_continue_api(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    assert code == "code-api-ws-1"


def test_oauth_submit_authorize_continue_api_refollows_authorize_when_body_empty():
    authorize_url = (
        "https://auth.openai.com/oauth/authorize?"
        "client_id=app_xxx&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"
    )
    session = QueueSession([
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(
                status_code=200,
                payload={},
                text="{}",
                url=OPENAI_API_ENDPOINTS["signup"],
            ),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(
                status_code=401,
                text='{"error":"unauthorized"}',
                url="https://chatgpt.com/api/auth/session",
            ),
        ),
        (
            "GET",
            "https://auth.openai.com/api/auth/session",
            DummyResponse(
                status_code=401,
                text='{"error":"unauthorized"}',
                url="https://auth.openai.com/api/auth/session",
            ),
        ),
        (
            "GET",
            authorize_url,
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-api-empty-1&state=state-1"},
            ),
        ),
    ])
    engine = RegistrationEngine(FakeEmailService(["123456"]))

    code = engine._oauth_submit_authorize_continue_api(
        session=session,
        page_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        redirect_uri="http://localhost:1455/auth/callback",
        authorize_url=authorize_url,
    )

    assert code == "code-api-empty-1"


def test_oauth_login_flow_retries_otp_once_when_first_validate_fails(monkeypatch):
    email_service = FakeEmailService(["123456", "654321"])
    engine = RegistrationEngine(email_service)
    engine.email = "tester@example.com"
    engine.password = "pass-1234"

    class DummyOAuthManager:
        def __init__(self, *args, **kwargs):
            pass

        def start_oauth(self):
            return OAuthStart(
                auth_url="https://auth.example.test/flow/1",
                state="state-1",
                code_verifier="verifier-1",
                redirect_uri="http://localhost:1455/auth/callback",
            )

        def handle_callback(self, callback_url, expected_state, code_verifier):
            return {
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "id_token": "id-1",
            }

    class DummyHttpClient:
        def __init__(self, proxy_url=None):
            self.session = SimpleNamespace(cookies={"__Secure-next-auth.session-token": "session-otp-retry"})

        def check_sentinel(self, did):
            return "sentinel-token"

    monkeypatch.setattr("src.core.register.OAuthManager", DummyOAuthManager)
    monkeypatch.setattr("src.core.register.OpenAIHTTPClient", DummyHttpClient)
    monkeypatch.setattr(engine, "_oauth_get_device_id", lambda session, auth_url: "did-1")
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_start",
        lambda session, did, sen: SignupFormResult(
            success=True,
            page_type=OPENAI_PAGE_TYPES["LOGIN_PASSWORD"],
            is_existing_account=False,
        ),
    )
    monkeypatch.setattr(
        engine,
        "_oauth_submit_login_password",
        lambda session: SignupFormResult(
            success=True,
            page_type=OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"],
            is_existing_account=True,
        ),
    )

    validate_calls = {"count": 0}

    def validate_once_fail_then_pass(session, code):
        validate_calls["count"] += 1
        return validate_calls["count"] >= 2

    monkeypatch.setattr(engine, "_oauth_validate_verification_code", validate_once_fail_then_pass)
    monkeypatch.setattr(engine, "_oauth_exchange_auth_code", lambda session, oauth_start: "auth-code-otp-retry")

    token_info = engine._get_oauth_tokens_via_login_flow()

    assert token_info is not None
    assert token_info["access_token"] == "access-1"
    assert validate_calls["count"] == 2
