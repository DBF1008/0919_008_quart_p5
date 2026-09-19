from __future__ import annotations

import hashlib
from collections import OrderedDict
from datetime import datetime
from datetime import timezone
from typing import Any
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


def _session_identity(cookie: str) -> str:
    """Return a stable identity for the session stored in the cookie."""
    return hashlib.sha256(cookie.encode("utf-8")).hexdigest()


class SessionInterface:
    """Base class for session interfaces.

    Attributes:
        null_session_class: Storage class for null (no storage)
            sessions.
        pickle_based: Indicates if pickling is used for the session.
        max_tracked_sessions: Maximum number of session identities for
            which version information is retained to detect and merge
            conflicting concurrent modifications.
    """

    null_session_class = NullSession
    pickle_based = False
    max_tracked_sessions = 512

    def __init__(self) -> None:
        self._session_versions: OrderedDict[str, int] = OrderedDict()
        self._session_data: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def _tracked_versions(self) -> OrderedDict[str, int]:
        # Lazily initialised so subclasses that do not call
        # super().__init__() are still protected.
        if not hasattr(self, "_session_versions"):
            self._session_versions = OrderedDict()
        return self._session_versions

    def _tracked_data(self) -> OrderedDict[str, dict[str, Any]]:
        if not hasattr(self, "_session_data"):
            self._session_data = OrderedDict()
        return self._session_data

    def _track_session_open(self, session: SessionMixin, identity: str) -> None:
        """Record the version the session was opened at.

        This stamps the session with the identity, the current version
        and a snapshot of the data as opened, so that a later
        :meth:`_merge_session_changes` call can detect and resolve
        conflicts caused by concurrent requests.
        """
        session._quart_identity = identity
        session._quart_version = self._tracked_versions().get(identity, 0)
        session._quart_snapshot = dict(session)

    def _merge_session_changes(self, session: SessionMixin) -> None:
        """Merge concurrent changes and bump the session version.

        If another request sharing the same session identity saved
        after this session was opened, the session is stale. Rather
        than overwriting the other request's changes (lost update),
        the changes made by this session - computed by diffing against
        the snapshot taken when it was opened - are applied on top of
        the most recently saved data.
        """
        identity = getattr(session, "_quart_identity", None)
        if identity is None:
            return

        versions = self._tracked_versions()
        stored_data = self._tracked_data()
        current_version = versions.get(identity, 0)
        opened_version = getattr(session, "_quart_version", current_version)

        if opened_version < current_version:
            latest = stored_data.get(identity, {})
            snapshot = getattr(session, "_quart_snapshot", {})
            merged = dict(latest)
            for key in snapshot.keys() - session.keys():
                merged.pop(key, None)
            for key, value in session.items():
                if key not in snapshot or snapshot[key] != value:
                    merged[key] = value
            if merged != dict(session):
                session.clear()
                session.update(merged)

        versions[identity] = current_version + 1
        versions.move_to_end(identity)
        stored_data[identity] = dict(session)
        stored_data.move_to_end(identity)
        while len(versions) > self.max_tracked_sessions:
            versions.popitem(last=False)
        while len(stored_data) > self.max_tracked_sessions:
            stored_data.popitem(last=False)

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

        Empty values (None or "") are normalised to None so that the
        Domain attribute is omitted from the cookie, rather than set
        to an empty string which browsers treat differently.
        """
        rv = app.config["SESSION_COOKIE_DOMAIN"]
        return rv if rv else None

    def get_cookie_partitioned(self, app: Quart) -> bool:
        """Helper method to return the Cookie partitioned setting for the App."""
        return app.config["SESSION_COOKIE_PARTITIONED"]

    def get_cookie_path(self, app: Quart) -> str:
        """Helper method to return the Cookie path for the App.

        Empty values are normalised to "/" so that the cookie path is
        never an empty string (which browsers treat inconsistently).
        """
        path = app.config["SESSION_COOKIE_PATH"] or app.config["APPLICATION_ROOT"]
        return path or "/"

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

        The returned session is stamped with a version and snapshot so
        that concurrent requests sharing the same cookie can be
        detected and merged on save (preventing lost updates).
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
            session = self.session_class()
        self._track_session_open(session, _session_identity(cookie))
        return session

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        """Saves the session to the response in a secure cookie."""
        if response is None:
            if session.modified:
                app.logger.exception(
                    "Secure Cookie Session modified during websocket handling. "
                    "These modifications will be lost as a cookie cannot be set."
                )
            return

        # Detect and merge conflicting concurrent modifications before
        # anything is written, so a slower request cannot overwrite
        # changes made by a faster one sharing the same session.
        self._merge_session_changes(session)

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
