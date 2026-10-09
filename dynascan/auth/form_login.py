from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..http_client import ScanClient
from .base import AuthHandler, AuthError


class FormLoginAuth(AuthHandler):
    """Classic HTML form login that yields a session cookie.

    Hidden fields (e.g. CSRF tokens) found on the login page are submitted automatically.
    """

    def __init__(self, login_url: str, username: str, password: str,
                 username_field: str = "username", password_field: str = "password",
                 extra_fields: dict[str, str] | None = None,
                 success_indicator: str = "", failure_indicator: str = "",
                 logged_in_url: str = "") -> None:
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        self.success_indicator = success_indicator
        self.failure_indicator = failure_indicator
        self.logged_in_url = logged_in_url
        self.description = f"form login as '{username}'"

    async def apply(self, client: ScanClient, base_url: str) -> None:
        login_url = urljoin(base_url, self.login_url)
        page = await client.get(login_url)
        hidden: dict[str, str] = {}
        action = login_url
        if page is not None and "html" in page.headers.get("content-type", ""):
            soup = BeautifulSoup(page.text, "html.parser")
            form = None
            for f in soup.find_all("form"):
                if f.find("input", {"type": "password"}) or f.find("input", {"name": self.password_field}):
                    form = f
                    break
            if form is not None:
                if form.get("action"):
                    action = urljoin(login_url, form["action"])
                for inp in form.find_all("input", {"type": "hidden"}):
                    if inp.get("name"):
                        hidden[inp["name"]] = inp.get("value", "")
        data = {**hidden, **self.extra_fields,
                self.username_field: self.username, self.password_field: self.password}
        resp = await client.post(action, data=data, follow_redirects=True)
        if resp is None:
            raise AuthError("login request failed (network error)")
        text = resp.text or ""
        if self.failure_indicator and self.failure_indicator in text:
            raise AuthError("login failed: failure indicator present in response")
        if self.success_indicator and self.success_indicator not in text:
            raise AuthError("login failed: success indicator not found in response")
        if resp.status_code in (401, 403):
            raise AuthError(f"login rejected with HTTP {resp.status_code}")
        if not len(client.cookies) and not self.success_indicator:
            raise AuthError("login produced no session cookie; set success_indicator to verify")

    async def verify(self, client: ScanClient, base_url: str) -> bool:
        if not self.logged_in_url:
            return True
        r = await client.get(urljoin(base_url, self.logged_in_url))
        return r is not None and r.status_code == 200
