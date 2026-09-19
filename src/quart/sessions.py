from __future__ import annotations

import asyncio
import copy
import hashlib
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Hashable
from typing import TYPE_CHECKING

from flask.sessions import NullSession as NullSession  # noqa: F401
from flask.sessions import SecureCookieSession as SecureCookieSession  # noqa: F401
from flask.sessions import (  # noqa: F401
    session_json_serializer as session_json_serializer,
)
from flask.sessions import SessionMixin as SessionMixin  # noqa: F401
from itsdangerous import BadSignature
from itsdangerous import URLSafeTimedSerializer
from werkzeug.wrappers import Response as WerkzeugResponse

from .wrappers import BaseRequestWebsocket
from .wrappers import Response

if TYPE_CHECKING:
    from .app import Quart  # noqa


class SessionInterface:
    """Base class for session interfaces.

    Attributes:
        null_session_class: Storage class for null (no storage)
            sessions.
        pickle_based: Indicates if pickling is used for the session.
    """

    null_session_class = NullSession
    pickle_based = False

    def __init__(self) -> None:
        # Tracks per-session locks, versions, and snapshots so that
        # concurrent requests sharing a session can be serialized and
        # merged rather than silently losing each other's changes.
        self._locks: dict[Hashable, asyncio.Lock] = {}
        self._versions: dict[Hashable, int] = {}
        self._snapshots: dict[Hashable, dict[str, Any]] = {}

    def _get_lock(self, key: Hashable) -> asyncio.Lock:
        """Return the lock guarding the session identified by key."""
        try:
            return self._locks[key]
        except KeyError:
            lock = self._locks[key] = asyncio.Lock()
            return lock

    def copy_session(self, session: SessionMixin) -> SessionMixin:
        """Return an independent copy of the given session.

        Session interfaces may return the same object from
        ``open_session`` for concurrent requests; copying ensures each
        request context mutates its own session object and therefore
        cannot race with other contexts.
        """
        return copy.copy(session)

    async def make_null_session(self, app: Quart) -> NullSession:
        """Create a Null session object.

        This is used in replacement of an actual session if sessions
        are not configured or active.
        """
        return self.null_session_class()

    def is_null_session(self, instance: object) -> bool:
        """Returns True is the instance is a null session."""
        return isinstance(instance, self.null_session_class)

    def get_cookie_name(self, app: Quart) -> str:
        """Helper method to return the Cookie Name for the App."""
        return app.config["SESSION_COOKIE_NAME"]

    def get_cookie_domain(self, app: Quart) -> str | None:
        """Helper method to return the Cookie Domain for the App.

        An empty string is normalized to None so that the Domain
        attribute is omitted from the cookie, matching the unset
        (None) configuration semantics.
        """
        rv = app.config["SESSION_COOKIE_DOMAIN"]
        return rv if rv else None

    def get_cookie_partitioned(self, app: Quart) -> bool:
        """Helper method to return the Cookie partitioned setting for the App."""
        return app.config["SESSION_COOKIE_PARTITIONED"]

    def get_cookie_path(self, app: Quart) -> str:
        """Helper method to return the Cookie path for the App.

        Falls back to "/" when neither SESSION_COOKIE_PATH nor
        APPLICATION_ROOT provide a non-empty value, ensuring the
        cookie Path is never the empty string.
        """
        return (
            app.config["SESSION_COOKIE_PATH"] or app.config["APPLICATION_ROOT"] or "/"
        )

    def get_cookie_httponly(self, app: Quart) -> bool:
        """Helper method to return if the Cookie should be HTTPOnly for the App."""
        return app.config["SESSION_COOKIE_HTTPONLY"]

    def get_cookie_secure(self, app: Quart) -> bool:
        """Helper method to return if the Cookie should be Secure for the App."""
        return app.config["SESSION_COOKIE_SECURE"]

    def get_cookie_samesite(self, app: Quart) -> str:
        """Helper method to return the Cookie Samesite configuration for the App."""
        return app.config["SESSION_COOKIE_SAMESITE"]

    def get_expiration_time(self, app: Quart, session: SessionMixin) -> datetime | None:
        """Helper method to return the Session expiration time.

        If the session is not 'permanent' it will expire as and when
        the browser stops accessing the app.
        """
        if session.permanent:
            return datetime.now(timezone.utc) + app.permanent_session_lifetime
        else:
            return None

    def should_set_cookie(self, app: Quart, session: SessionMixin) -> bool:
        """Helper method to return if the Set Cookie header should be present.

        This triggers if the session is marked as modified or the app
        is configured to always refresh the cookie.
        """
        if session.modified:
            return True
        save_each = app.config["SESSION_REFRESH_EACH_REQUEST"]
        return save_each and session.permanent

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> SessionMixin | None:
        """Open an existing session from the request or create one.

        Returns:
            The Session object or None if no session can be created,
            in which case the :attr:`null_session_class` is expected
            to be used.
        """
        raise NotImplementedError()

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        """Save the session argument to the response.

        Arguments:
            response: Can be None if the session is being saved after
                a websocket connection closes.

        Returns:
            The modified response, with the session stored.

        """
        raise NotImplementedError()


class SecureCookieSessionInterface(SessionInterface):
    """A Session interface that uses cookies as storage.

    This will store the data on the cookie in plain text, but with a
    signature to prevent modification.
    """

    digest_method = staticmethod(hashlib.sha1)
    key_derivation = "hmac"
    salt = "cookie-session"
    serializer = session_json_serializer
    session_class = SecureCookieSession

    def get_signing_serializer(self, app: Quart) -> URLSafeTimedSerializer | None:
        """Return a serializer for the session that also signs data.

        This will return None if the app is not configured for secrets.
        """
        if not app.secret_key:
            return None

        keys: list[str | bytes] = []

        if fallbacks := app.config["SECRET_KEY_FALLBACKS"]:
            keys.extend(fallbacks)

        keys.append(app.secret_key)  # itsdangerous expects current key at top
        options = {
            "key_derivation": self.key_derivation,
            "digest_method": self.digest_method,
        }
        return URLSafeTimedSerializer(
            keys,  # type: ignore[arg-type]
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs=options,
        )

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> SecureCookieSession | None:
        """Open a secure cookie based session.

        This will return None if a signing serializer is not available,
        usually if the config SECRET_KEY is not set.
        """
        signer = self.get_signing_serializer(app)
        if signer is None:
            return None

        cookie = request.cookies.get(self.get_cookie_name(app))
        if cookie is None:
            return self.session_class()
        max_age = int(app.permanent_session_lifetime.total_seconds())
        try:
            data = signer.loads(cookie, max_age=max_age)
            session = self.session_class(data)
        except BadSignature:
            return self.session_class()

        # Track the session so that concurrent requests sharing this
        # cookie can be serialized and merged when saved.
        key = hashlib.sha256(cookie.encode()).hexdigest()
        session._session_key = key
        session._session_version = self._versions.get(key, 0)
        session._session_base = dict(session)
        return session

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        """Saves the session to the response in a secure cookie."""
        key = getattr(session, "_session_key", None)
        if response is None or key is None:
            await self._save_session(app, session, response)
            return

        # Serialize concurrent saves of the same session and merge
        # any changes saved by other requests since this session was
        # opened, preventing lost updates.
        async with self._get_lock(key):
            version = getattr(session, "_session_version", 0)
            if session.modified and self._versions.get(key, 0) != version:
                self._merge_session(session, key)
            await self._save_session(app, session, response)
            self._versions[key] = version + 1
            self._snapshots[key] = dict(session)

    def _merge_session(self, session: SessionMixin, key: Hashable) -> None:
        """Merge changes saved by other requests into the session.

        Applies this session's changes (relative to the data it was
        opened with) on top of the latest saved snapshot, so that
        concurrent modifications to distinct keys are not lost.
        """
        base: dict[str, Any] = getattr(session, "_session_base", {})
        merged = dict(self._snapshots.get(key, {}))
        current = dict(session)
        for name in base:
            if name not in current:
                merged.pop(name, None)
        for name, value in current.items():
            if name not in base or base[name] != value:
                merged[name] = value
        session.clear()
        session.update(merged)

    async def _save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        if response is None:
            if session.modified:
                app.logger.exception(
                    "Secure Cookie Session modified during websocket handling. "
                    "These modifications will be lost as a cookie cannot be set."
                )
            return

        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        partitioned = self.get_cookie_partitioned(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        # Add a "Vary: Cookie" header if the session was accessed at all.
        if session.accessed:
            response.vary.add("Cookie")

        # If the session is modified to be empty, remove the cookie.
        # If the session is empty, return without setting the cookie.
        if not session:
            if session.modified:
                response.delete_cookie(
                    name,
                    domain=domain,
                    partitioned=partitioned,
                    path=path,
                    secure=secure,
                    samesite=samesite,
                    httponly=httponly,
                )
                response.vary.add("Cookie")

            return

        if not self.should_set_cookie(app, session):
            return

        expires = self.get_expiration_time(app, session)
        val = self.get_signing_serializer(app).dumps(dict(session))
        response.set_cookie(
            name,
            val,
            expires=expires,
            httponly=httponly,
            domain=domain,
            partitioned=partitioned,
            path=path,
            secure=secure,
            samesite=samesite,
        )
        response.vary.add("Cookie")
