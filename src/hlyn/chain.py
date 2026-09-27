"""Chaining through the user's own proxy (DESIGN-host-allowlisting.md 5.5).

Behind a corporate proxy, hlyn's proxy forwards through it. Apart from
`proxy.py` so `hlyn run` can read and check the user's proxy settings
without importing the proxy's asyncio server.
"""

from __future__ import annotations

import contextlib
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass

from .error import Invalid

__all__ = ["Upstream", "upstream"]


@dataclass(frozen=True, slots=True)
class Upstream:
    """A proxy to chain through: `host:port`, optional Basic credentials,
    and the `NO_PROXY` entries that bypass it."""

    host: str
    port: int
    auth: str | None = None
    skip: tuple[str, ...] = ()

    def bypass(self, host: str) -> bool:
        """True if `NO_PROXY` says `host` goes direct (curl's rules: a name
        matches itself and its subdomains, compared label by label)."""
        name = host.lower().rstrip(".")
        for entry in self.skip:
            if entry == "*":
                return True
            want = entry.lower().lstrip(".").rstrip(".")
            if not want:
                continue
            if "/" in want:
                with contextlib.suppress(ValueError):
                    if ipaddress.ip_address(name) in ipaddress.ip_network(want, strict=False):
                        return True
                continue
            labels, wanted = name.split("."), want.split(".")
            if len(labels) >= len(wanted) and labels[len(labels) - len(wanted) :] == wanted:
                return True
        return False


def upstream(env: Mapping[str, str]) -> Upstream | None:
    """The proxy the user's own environment names, before hlyn cleans it.

    `HTTPS_PROXY`, then `HTTP_PROXY`, then `ALL_PROXY` (either case), and
    `NO_PROXY`. Only `http://` proxies are chained; anything else raises
    `Invalid` naming the variable, rather than being silently ignored and
    connecting direct where the user's network expects a proxy.
    """
    url = next(
        (env[key] for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
                              "all_proxy") if env.get(key)),
        None,
    )
    if not url:
        return None
    from urllib.parse import unquote, urlsplit

    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme.lower() != "http":
        raise Invalid(
            f"the proxy in your environment ({parts.scheme}://...) can't be chained: hlyn chains "
            f"only http:// proxies. Unset HTTPS_PROXY/HTTP_PROXY/ALL_PROXY, or point them at an "
            f"http:// proxy."
        )
    if not parts.hostname:
        raise Invalid(f"the proxy in your environment has no host ({url!r}). Fix HTTPS_PROXY.")
    try:
        port = parts.port or 8080
    except ValueError:
        raise Invalid(f"the proxy in your environment has a bad port ({url!r}). Fix HTTPS_PROXY.") from None
    auth = None
    if parts.username is not None:
        import base64

        pair = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
        auth = base64.b64encode(pair.encode()).decode("ascii")
    skip = tuple(
        item.strip()
        for item in (env.get("NO_PROXY") or env.get("no_proxy") or "").split(",")
        if item.strip()
    )
    return Upstream(parts.hostname, port, auth, skip)
