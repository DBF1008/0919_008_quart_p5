from __future__ import annotations

import asyncio
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


async def test_get_cookie_path_empty_values_default_to_slash() -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    assert interface.get_cookie_path(app) == "/"
    app.config["APPLICATION_ROOT"] = ""
    assert interface.get_cookie_path(app) == "/"
    app.config["SESSION_COOKIE_PATH"] = ""
    assert interface.get_cookie_path(app) == "/"
    app.config["SESSION_COOKIE_PATH"] = "/api"
    assert interface.get_cookie_path(app) == "/api"


async def test_get_cookie_domain_empty_string_is_none() -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    assert interface.get_cookie_domain(app) is None
    app.config["SESSION_COOKIE_DOMAIN"] = ""
    assert interface.get_cookie_domain(app) is None
    app.config["SESSION_COOKIE_DOMAIN"] = "example.com"
    assert interface.get_cookie_domain(app) == "example.com"


def _cookie_request(cookie: str, http_scope: HTTPScope) -> Request:
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


async def _seed_cookie(app: Quart, data: dict) -> str:
    interface = SecureCookieSessionInterface()
    session = SecureCookieSession()
    session.update(data)
    response = Response("")
    await interface.save_session(app, session, response)
    return response.headers["Set-Cookie"]


async def test_concurrent_saves_do_not_lose_changes(http_scope: HTTPScope) -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    cookie = await _seed_cookie(app, {"count": 1})

    # Two concurrent requests share the same session cookie.
    session_a = await interface.open_session(app, _cookie_request(cookie, http_scope))
    session_b = await interface.open_session(app, _cookie_request(cookie, http_scope))
    session_a["a"] = 1
    session_b["b"] = 2

    response_a = Response("")
    response_b = Response("")
    await asyncio.gather(
        interface.save_session(app, session_a, response_a),
        interface.save_session(app, session_b, response_b),
    )

    # The save that completes last must contain both requests'
    # changes, rather than overwriting the first save.
    merged = None
    for response in (response_a, response_b):
        session = await interface.open_session(
            app, _cookie_request(response.headers["Set-Cookie"], http_scope)
        )
        if "a" in session and "b" in session:
            merged = session
    assert merged is not None
    assert merged["a"] == 1
    assert merged["b"] == 2
    assert merged["count"] == 1


async def test_concurrent_saves_merge_deletions(http_scope: HTTPScope) -> None:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    cookie = await _seed_cookie(app, {"count": 1, "other": 2})

    session_a = await interface.open_session(app, _cookie_request(cookie, http_scope))
    session_b = await interface.open_session(app, _cookie_request(cookie, http_scope))
    del session_a["count"]
    session_b["b"] = 2

    response_a = Response("")
    response_b = Response("")
    await interface.save_session(app, session_a, response_a)
    await interface.save_session(app, session_b, response_b)

    final = await interface.open_session(
        app, _cookie_request(response_b.headers["Set-Cookie"], http_scope)
    )
    assert "count" not in final
    assert final["other"] == 2
    assert final["b"] == 2
