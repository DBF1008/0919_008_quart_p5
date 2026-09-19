from __future__ import annotations

from http.cookies import SimpleCookie

from hypercorn.typing import HTTPScope
from werkzeug.datastructures import Headers

from quart.app import Quart
from quart.sessions import SecureCookieSession
from quart.sessions import SecureCookieSessionInterface
from quart.testing import no_op_push
from quart.wrappers import Request
from quart.wrappers import Response


async def test_secure_cookie_session_interface_open_session(
    http_scope: HTTPScope,
) -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    response = Response("")
    await interface.save_session(app, session, response)
    request = Request(
        "GET",
        "http",
        "/",
        b"",
        Headers(),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    request.headers["Cookie"] = response.headers["Set-Cookie"]
    new_session = await interface.open_session(app, request)
    assert new_session == session


async def test_secure_cookie_session_interface_save_session() -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    response = Response("")
    await interface.save_session(app, session, response)
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["Set-Cookie"])
    cookie = cookies[app.config["SESSION_COOKIE_NAME"]]
    assert cookie["path"] == interface.get_cookie_path(app)
    assert cookie["httponly"] == "" if not interface.get_cookie_httponly(app) else True
    assert cookie["secure"] == "" if not interface.get_cookie_secure(app) else True
    assert cookie["samesite"] == (interface.get_cookie_samesite(app) or "")
    assert cookie["domain"] == (interface.get_cookie_domain(app) or "")
    assert cookie["expires"] == (interface.get_expiration_time(app, session) or "")
    assert response.headers["Vary"] == "Cookie"


async def _save_session(session: SecureCookieSession) -> Response:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    response = Response("")
    await interface.save_session(app, session, response)
    return response


async def test_secure_cookie_session_interface_save_session_no_modification() -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    session.modified = False
    response = await _save_session(session)
    assert response.headers.get("Set-Cookie") is None


async def test_secure_cookie_session_interface_save_session_no_access() -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    session.accessed = False
    session.modified = False
    response = await _save_session(session)
    assert response.headers.get("Set-Cookie") is None
    assert response.headers.get("Vary") is None


def _request_with_cookie(cookie: str, http_scope: HTTPScope) -> Request:
    request = Request(
        "GET",
        "http",
        "/",
        b"",
        Headers(),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    request.headers["Cookie"] = cookie
    return request


async def _session_cookie(session: SecureCookieSession) -> str:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    session.modified = True
    response = Response("")
    await interface.save_session(app, session, response)
    return response.headers["Set-Cookie"]


async def test_get_cookie_path_empty_values_normalised() -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    assert interface.get_cookie_path(app) == "/"
    app.config["APPLICATION_ROOT"] = ""
    assert interface.get_cookie_path(app) == "/"
    app.config["SESSION_COOKIE_PATH"] = ""
    assert interface.get_cookie_path(app) == "/"
    app.config["SESSION_COOKIE_PATH"] = "/api"
    assert interface.get_cookie_path(app) == "/api"


async def test_get_cookie_domain_empty_values_normalised() -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    assert interface.get_cookie_domain(app) is None
    app.config["SESSION_COOKIE_DOMAIN"] = ""
    assert interface.get_cookie_domain(app) is None
    app.config["SESSION_COOKIE_DOMAIN"] = "example.com"
    assert interface.get_cookie_domain(app) == "example.com"


async def _open_two_sessions(
    interface: SecureCookieSessionInterface,
    app: Quart,
    cookie: str,
    http_scope: HTTPScope,
) -> tuple[SecureCookieSession, SecureCookieSession]:
    session_a = await interface.open_session(
        app, _request_with_cookie(cookie, http_scope)
    )
    session_b = await interface.open_session(
        app, _request_with_cookie(cookie, http_scope)
    )
    return session_a, session_b


async def test_concurrent_session_changes_are_merged(
    http_scope: HTTPScope,
) -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"

    cookie = await _session_cookie(SecureCookieSession({"count": 1}))

    # Two concurrent requests open the same session cookie.
    session_a, session_b = await _open_two_sessions(interface, app, cookie, http_scope)

    # The faster request saves first.
    session_a["fast"] = "a"
    await interface.save_session(app, session_a, Response(""))

    # The slower request must not lose the faster request's changes.
    session_b["slow"] = "b"
    response_b = Response("")
    await interface.save_session(app, session_b, response_b)

    final = await interface.open_session(
        app, _request_with_cookie(response_b.headers["Set-Cookie"], http_scope)
    )
    assert final["count"] == 1
    assert final["fast"] == "a"
    assert final["slow"] == "b"


async def test_concurrent_session_deletion_is_merged(
    http_scope: HTTPScope,
) -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"

    cookie = await _session_cookie(SecureCookieSession({"a": 1, "b": 2}))

    session_a, session_b = await _open_two_sessions(interface, app, cookie, http_scope)

    session_a["c"] = 3
    await interface.save_session(app, session_a, Response(""))

    del session_b["a"]
    response_b = Response("")
    await interface.save_session(app, session_b, response_b)

    final = await interface.open_session(
        app, _request_with_cookie(response_b.headers["Set-Cookie"], http_scope)
    )
    assert "a" not in final
    assert final["b"] == 2
    assert final["c"] == 3


async def test_concurrent_session_conflicting_key_last_save_wins(
    http_scope: HTTPScope,
) -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"

    cookie = await _session_cookie(SecureCookieSession({"shared": 0, "other": 1}))

    session_a, session_b = await _open_two_sessions(interface, app, cookie, http_scope)

    session_a["shared"] = "a"
    await interface.save_session(app, session_a, Response(""))

    session_b["shared"] = "b"
    response_b = Response("")
    await interface.save_session(app, session_b, response_b)

    final = await interface.open_session(
        app, _request_with_cookie(response_b.headers["Set-Cookie"], http_scope)
    )
    assert final["shared"] == "b"
    assert final["other"] == 1


async def test_session_version_increments_on_save(
    http_scope: HTTPScope,
) -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"

    cookie = await _session_cookie(SecureCookieSession({"count": 1}))

    session = await interface.open_session(
        app, _request_with_cookie(cookie, http_scope)
    )
    identity = session._quart_identity
    assert session._quart_version == 0

    await interface.save_session(app, session, Response(""))
    assert interface._tracked_versions()[identity] == 1

    reopened = await interface.open_session(
        app, _request_with_cookie(cookie, http_scope)
    )
    assert reopened._quart_version == 1
