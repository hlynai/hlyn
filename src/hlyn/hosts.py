# SPDX-License-Identifier: Apache-2.0
"""Host entries for `net`: grammar, normalisation, matching, and reports.

This is the pure half of design phase 1 (DESIGN-host-allowlisting.md 4.1-4.3,
6.7, appendix B): standard library only, nothing that touches the kernel or a
socket. `Policy` and the proxy call into this module; it never calls back into
them, so it can be tested -- and read -- on its own.

Public API
----------

`parse(entry, field="net") -> Rule`
    Turn one `net` list entry into a `Rule`, or raise `hlyn.error.Invalid` with
    a message that names the fix (4.2). Accepts a host (`api.openai.com`), a
    host with a port (`api.openai.com:8443`), a single leftmost wildcard
    (`*.example.com`), `localhost:PORT`, an IPv4 or IPv6 literal
    (`10.0.0.5:5432`, `[2001:db8::10]:8443`), or a CIDR range
    (`10.20.0.0/16:8080`, `[fd00::/8]:443`). The port defaults to 443.

`Rule`
    One normalised entry: `kind` (`"host"`, `"wildcard"`, `"localhost"`,
    `"address"` or `"range"`), `port`, `host` (the normalised name, for the
    name-based kinds) and `network` (an `ipaddress` network, for the
    address-based kinds). `str(rule)` is its canonical form
    (`"api.openai.com:443"`); `rule.flag()` is the `--net` flag that would
    allow it (`"--net api.openai.com"`, port omitted when it is the default).

`normalize(name, field="net") -> str`
    The rule-1 normalisation (lowercase, strip one trailing dot, refuse
    non-ASCII and bad grammar) that both `parse` and `match` apply, so a name
    is always checked the same way on both sides of the comparison.

`match(rules, *, port, name=None, address=None) -> Rule | None`
    The first rule in `rules` that allows `port` for `name` and/or `address`,
    or `None`. Implements matching rules 1-3: normalises `name` the same way
    `parse` did, compares it to a wildcard label by label (never `endswith`,
    a regex or a glob), and parses `address` with `ipaddress`, unwrapping
    IPv4-mapped, NAT64, 6to4 and Teredo forms first. A malformed `name` or
    `address` matches nothing -- the same fail-closed answer as one that
    matches no rule -- rather than raising.

`unwrap(address) -> IPv4Address | IPv6Address`
    `address` with IPv4-mapped, NAT64, 6to4 and Teredo wrapping removed, so
    the address actually being reached is what gets compared and classified.

`classify(address, mine=()) -> str | None`
    Appendix B / matching rule 4: `None` if `address` may be reached by name;
    otherwise which class it is (`"loopback"`, `"private"`, `"cgnat"`,
    `"link-local"`, `"multicast"`, `"broadcast"`, `"reserved"`,
    `"unspecified"`, `"cloud-metadata"` or `"own-interface"`), for building
    report text such as "resolves to a private address". Checks both
    `ipaddress`'s own properties and the explicit appendix-B table -- Python's
    `is_private`/`is_global` alone had CVE-2024-4032. `mine` is this machine's
    own interface addresses; gathering that set is a later phase, so it is
    just a parameter here.

`warn(rule) -> str | None`
    Design 6.7: the warning text for a rule that names a local service port
    that would give an agent full onward network reach (Docker's API,
    Kubernetes, a kubelet, Tor, a local HTTP/SOCKS proxy), or `None` if the
    rule's port isn't one of those.

Nothing here changes `Policy` or wires into the CLI; that is a later step.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
from collections.abc import Iterable
from dataclasses import dataclass

from .error import Invalid

__all__ = ["Reach", "Rule", "classify", "match", "normalize", "parse", "unwrap", "warn"]


class Reach(UserWarning):
    """A `net` entry names a local service that gives onward reach (design 6.7).

    A warning, not a refusal: the user may mean it. Filter it like any other
    (`warnings.simplefilter("ignore", hlyn.Reach)`), or make it an error.
    """

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_PORT = 443


# ---------------------------------------------------------------------------
# the parsed entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rule:
    """One normalised `net` entry.

    `kind` is `"host"`, `"wildcard"`, `"localhost"`, `"address"` or `"range"`.
    `host` is the normalised name for the three name-based kinds (for
    `"wildcard"` it is the suffix *without* the leading `"*."`, e.g.
    `"example.com"` for `*.example.com`) and `None` otherwise. `network` is
    the address or CIDR range for the two address-based kinds (a single
    address is stored as a /32 or /128) and `None` otherwise.

    Construct these with `parse`, not directly -- `parse` is what enforces the
    grammar in 4.2.
    """

    kind: str
    port: int
    host: str | None = None
    network: IPNetwork | None = None

    def _body(self) -> str:
        if self.kind == "host":
            return self.host or ""
        if self.kind == "wildcard":
            return f"*.{self.host}"
        if self.kind == "localhost":
            return "localhost"
        if self.network is None:
            raise ValueError(f"a {self.kind} rule without an address")
        if self.network.num_addresses == 1:
            addr = self.network.network_address
            return f"[{addr}]" if addr.version == 6 else str(addr)
        return f"[{self.network}]" if self.network.version == 6 else str(self.network)

    def __repr__(self) -> str:
        return f"Rule({str(self)!r})"

    def __str__(self) -> str:
        """The canonical form of this rule, e.g. `"api.openai.com:443"`."""
        return f"{self._body()}:{self.port}"

    def flag(self) -> str:
        """The `--net` flag that would allow this rule, port omitted when it is the default."""
        body = self._body()
        if self.port == DEFAULT_PORT:
            return f"--net {body}"
        return f"--net {body}:{self.port}"


# ---------------------------------------------------------------------------
# normalisation (matching rule 1)
# ---------------------------------------------------------------------------

_LABEL_OK = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def _check_label(label: str, entry: str, field: str) -> None:
    if not label:
        raise Invalid(
            f"{field}: {entry!r} has an empty label (two dots in a row, or a leading dot). "
            f"Remove the extra dot."
        )
    if len(label) > 63:
        raise Invalid(
            f"{field}: {entry!r} has a label over 63 characters ({label!r}). Shorten it."
        )
    if label[0] == "-" or label[-1] == "-":
        raise Invalid(
            f"{field}: {entry!r} has a label starting or ending with '-' ({label!r}). Trim the '-'."
        )
    bad = sorted(set(label) - _LABEL_OK)
    if bad:
        raise Invalid(
            f"{field}: {entry!r} has a character not allowed in a host name: {bad!r} "
            f"(in label {label!r}). Host names are letters, digits and '-' only."
        )


def normalize(name: str, field: str = "net") -> str:
    """Lowercase `name`, strip one trailing dot, and check its grammar.

    This is matching rule 1, applied on the way in by `parse` and again by
    `match` to whatever a client sends, so the two sides are always compared
    on the same footing. Raises `Invalid`, naming the fix, on anything
    malformed: non-ASCII (write it in `xn--` form instead), an empty label, a
    label starting or ending with '-', a label over 63 characters, a name
    over 253, or a character outside `a-z0-9-`.
    """
    if not isinstance(name, str) or not name:
        raise Invalid(f"{field}: expected a non-empty host name, got {name!r}.")
    if not name.isascii():
        suggestion = None
        with contextlib.suppress(UnicodeError):
            suggestion = name.encode("idna").decode("ascii")
        hint = f" Try {suggestion!r}." if suggestion else ""
        raise Invalid(
            f"{field}: {name!r} has non-ASCII characters. Write it in its `xn--` form.{hint}"
        )
    lowered = name.lower()
    if lowered.endswith(".") and lowered != ".":
        lowered = lowered[:-1]
    if len(lowered) > 253:
        raise Invalid(f"{field}: {name!r} is over 253 characters.")
    for label in lowered.split("."):
        _check_label(label, name, field)
    return lowered


def _wildcard_matches(name: str, suffix: str) -> bool:
    """True if `name` is a strict, non-empty descendant of `suffix`.

    Matching rule 2: compared label by label, never `endswith`, a regex, or a
    glob. `*.example.com` matches `a.example.com` and `a.b.example.com`. It
    does not match `example.com` itself, `evilexample.com` (a different,
    single label), or `example.com.evil.net` (the labels are the same but in
    the wrong position).
    """
    name_labels = name.split(".")
    suffix_labels = suffix.split(".")
    if len(name_labels) <= len(suffix_labels):
        return False
    return name_labels[len(name_labels) - len(suffix_labels) :] == suffix_labels


# ---------------------------------------------------------------------------
# IPv4-in-disguise detection: refused, not silently corrected
# ---------------------------------------------------------------------------

# A number, or a dotted group of up to four of them, each in decimal, octal
# (leading zero) or hex (0x) -- the classic BSD `inet_aton` grammar. Strict
# dotted-decimal input never reaches this: `parse` only calls it after
# `ipaddress.ip_address` has already refused the text.
_LOOSE_IPV4 = re.compile(
    r"(0[xX][0-9a-fA-F]+|0[0-7]+|0|[1-9][0-9]*)"
    r"(\.(0[xX][0-9a-fA-F]+|0[0-7]+|0|[1-9][0-9]*)){0,3}"
)


def _loose_ipv4(text: str) -> str | None:
    """`text` reinterpreted as strict dotted decimal, if it looks like an old,
    sloppy IPv4 form (octal, hex, or fewer than four decimal parts) -- the
    form CERT and every SSRF audit in the research warns about. `None` if
    `text` doesn't look like an IPv4 attempt at all.
    """
    if not _LOOSE_IPV4.fullmatch(text):
        return None
    try:
        return socket.inet_ntoa(socket.inet_aton(text))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# parse() -- one `net` entry (4.2)
# ---------------------------------------------------------------------------


# IPv6 prefixes that carry an IPv4 address inside (matching rule 3). A single
# address in one is stored as the IPv4 address it reaches; a range that
# touches one is refused, because what it covers depends on the embedding.
_WRAPPED: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
    ipaddress.ip_network("2002::/16"),  # 6to4
    ipaddress.ip_network("2001::/32"),  # Teredo
)


def _shown(network: IPNetwork) -> str:
    """How an address or range is written in a `net` entry: IPv6 in brackets."""
    text = str(network.network_address) if network.num_addresses == 1 else str(network)
    return f"[{text}]" if network.version == 6 else text


def _network_of(text: str, entry: str, field: str) -> IPNetwork:
    """`text` as a single address or a CIDR range, in canonical form.

    Host bits set are refused rather than silently masked -- the same "never
    quietly substitute a different value" rule `hlyn.policy.ports` follows
    for a fractional port. A single address wrapped in IPv6 (mapped, NAT64,
    6to4, Teredo) is stored as the IPv4 address it reaches, so it matches
    that address in any spelling.
    """
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as exc:
            try:
                loose = ipaddress.ip_network(text, strict=False)
            except ValueError:
                raise Invalid(f"{field}: {entry!r} is not a valid address range: {exc}.") from None
            raise Invalid(
                f"{field}: {entry!r} has host bits set. Use the network address: "
                f"--net {_shown(loose)}:PORT."
            ) from None
        if network.version == 6 and any(network.overlaps(w) for w in _WRAPPED):
            raise Invalid(
                f"{field}: {entry!r} is a range inside an IPv6 prefix that wraps IPv4 addresses "
                f"(mapped, NAT64, 6to4 or Teredo). Write the IPv4 range instead, e.g. --net 10.0.0.0/8:PORT."
            )
        if network.num_addresses > 1:
            return network
    else:
        try:
            network = ipaddress.ip_network(ipaddress.ip_address(text))
        except ValueError as exc:
            raise Invalid(f"{field}: {entry!r} is not a valid address: {exc}.") from None
    return ipaddress.ip_network(unwrap(network.network_address))


def _address_rule(network: IPNetwork, port: int) -> Rule:
    return Rule(kind="address" if network.num_addresses == 1 else "range", port=port, network=network)


def parse(entry: str, field: str = "net") -> Rule:
    """Parse one `net` list entry into a `Rule`.

    See the module docstring for what is accepted. Raises `Invalid`, naming
    the fix, for everything 4.2 says to refuse: a URL, a name with a path, a
    user or a query string, a named port or a port range, a malformed
    wildcard, a non-ASCII name, forbidden characters, a loose IPv4 form, or
    an unbracketed IPv6 address.
    """
    if not isinstance(entry, str):
        raise Invalid(f"{field}: expected a string host entry, got {type(entry).__name__} ({entry!r}).")
    if not entry:
        raise Invalid(f"{field}: empty host entry. Remove it, or give a host name.")

    for ch, name in (("\x00", "a NUL byte"), ("\r", "a carriage return"), ("\n", "a line feed")):
        if ch in entry:
            raise Invalid(f"{field}: {entry!r} contains {name}. Remove it.")

    if "://" in entry:
        _, _, rest = entry.partition("://")
        guess = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[-1]
        guess = guess or "example.com"
        raise Invalid(f"{field}: {entry!r} is a URL. Give the host name: --net {guess}")
    if "@" in entry:
        raise Invalid(
            f"{field}: {entry!r} has a user name in it. Give just the host name: "
            f"--net {entry.rsplit('@', 1)[1]}"
        )
    if "?" in entry or "#" in entry:
        raise Invalid(
            f"{field}: {entry!r} has a query string. Give just the host name and, optionally, "
            f"a port: api.openai.com or api.openai.com:8443."
        )
    if "%" in entry:
        raise Invalid(
            f"{field}: {entry!r} has a '%' (an IPv6 zone id). Zone ids aren't portable across "
            f"machines; remove it."
        )

    # -- [ADDRESS-OR-RANGE]:PORT ----------------------------------------------
    if entry.startswith("["):
        end = entry.find("]")
        if end == -1:
            raise Invalid(f"{field}: {entry!r} has an unmatched '['. Close it: [...]:PORT.")
        rest = entry[end + 1 :]
        if rest and not rest.startswith(":"):
            raise Invalid(
                f"{field}: {entry!r} has text after the closing ']' that isn't a port. Use [...]:PORT."
            )
        network = _network_of(entry[1:end], entry, field)
        return _address_rule(network, _parse_port(rest[1:] if rest else None, entry, field))

    if entry.count(":") >= 2:
        raise Invalid(
            f"{field}: {entry!r} looks like an IPv6 address without brackets. Wrap it in "
            f"brackets and add the port after them: --net [{entry}]:443"
        )
    host_part, colon, port_text = entry.partition(":")
    if not host_part:
        raise Invalid(f"{field}: {entry!r} has no host name before the ':'.")
    if colon and not port_text:
        raise Invalid(f"{field}: {entry!r} ends in ':' with no port. "
                      f"Drop the ':' (443 is the default) or add one.")

    # -- ADDRESS/PREFIX, or a name with a path ---------------------------------
    if "/" in host_part:
        before = host_part.split("/", 1)[0]
        try:
            ipaddress.ip_address(before)
        except ValueError:
            raise Invalid(
                f"{field}: {entry!r} has a path. Give just the host name: --net {before}"
                if before else f"{field}: {entry!r} is not a host name or address range."
            ) from None
        port = _parse_port(port_text or None, entry, field)
        return _address_rule(_network_of(host_part, entry, field), port)

    try:
        ipaddress.ip_address(host_part)
    except ValueError:
        pass
    else:
        port = _parse_port(port_text or None, entry, field)
        return _address_rule(_network_of(host_part, entry, field), port)
    loose = _loose_ipv4(host_part)
    if loose is not None:
        raise Invalid(
            f"{field}: {entry!r} is not a strict IPv4 address (four decimal numbers 0-255, "
            f"no leading zeros, no 0x). Did you mean {loose!r}? Use --net {loose}"
            + (f":{port_text}" if port_text else "") + "."
        )

    # -- a host name, a wildcard, or `localhost` ------------------------------
    lowered = host_part.lower()
    if lowered.endswith(".") and lowered != ".":
        lowered = lowered[:-1]

    if lowered == "*":
        raise Invalid(f"{field}: {entry!r} is a lone '*'. Name the suffix: *.example.com.")
    if "*" in lowered:
        if lowered.count("*") > 1:
            raise Invalid(
                f"{field}: {entry!r} has more than one '*'. Only one wildcard is allowed."
            )
        if not lowered.startswith("*."):
            raise Invalid(
                f"{field}: {entry!r} has '*' that isn't the whole first label. A wildcard must "
                f"be leftmost: *.example.com, not {entry!r}."
            )
        suffix = lowered[2:]
        if "." not in suffix:
            raise Invalid(
                f"{field}: {entry!r} has a single-label suffix. *.{suffix} would match every "
                f"name ending in .{suffix}; name a real domain: *.example.{suffix}."
            )
        normalized = normalize(suffix, field)
        port = _parse_port(port_text, entry, field)
        return Rule(kind="wildcard", port=port, host=normalized)

    normalized = normalize(lowered, field)
    port = _parse_port(port_text, entry, field)
    if normalized == "localhost":
        return Rule(kind="localhost", port=port)
    return Rule(kind="host", port=port, host=normalized)


def _parse_port(text: str | None, entry: str, field: str) -> int:
    if text is None or text == "":
        return DEFAULT_PORT
    if "-" in text and text.replace("-", "").isdigit():
        raise Invalid(
            f"{field}: {entry!r} names a port range. One port per entry; repeat the entry "
            f"for the others."
        )
    if not text.isdigit():
        raise Invalid(
            f"{field}: {entry!r} has a named port ({text!r}). Use the port number instead, "
            f"e.g. {entry.rsplit(':', 1)[0]}:443."
        )
    port = int(text)
    if not 0 < port < 65536:
        raise Invalid(f"{field}: {entry!r} has port {port}, which is not 1-65535.")
    return port


# ---------------------------------------------------------------------------
# matching (rules 1-3)
# ---------------------------------------------------------------------------

_LOOPBACK: tuple[IPAddress, ...] = (ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv6Address("::1"))

_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def unwrap(address: IPAddress) -> IPAddress:
    """`address` with IPv4-mapped, NAT64, 6to4 and Teredo wrapping removed.

    Matching rule 3. An IPv4-mapped IPv6 address (`::ffff:7f00:1` in any
    spelling) becomes its IPv4 form. NAT64 (`64:ff9b::/96`), 6to4
    (`2002::/16`) and Teredo (`2001::/32`) addresses become the IPv4 address
    they embed -- for Teredo, the client address, which is the one actually
    reached. Anything else, including a plain IPv4 address, is returned
    unchanged.
    """
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped
        if address in _NAT64:
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        six = address.sixtofour
        if six is not None:
            return six
        teredo = address.teredo
        if teredo is not None:
            return teredo[1]
    return address


def _as_address(value: IPAddress | str) -> IPAddress | None:
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def match(
    rules: Iterable[Rule],
    *,
    port: int,
    name: str | None = None,
    address: IPAddress | str | None = None,
) -> Rule | None:
    """The first rule in `rules` that allows `port` for `name` and/or `address`.

    `name` is compared to `"host"` and `"wildcard"` rules (and to
    `"localhost"`, whose name is always `"localhost"`), normalised the same
    way `parse` normalises an entry (matching rule 1) and compared label by
    label (rule 2). `address` is compared to `"address"` and `"range"` rules
    (and to `"localhost"`, which matches 127.0.0.1 and ::1), parsed with
    `ipaddress` and unwrapped first (rule 3).

    A malformed `name` or `address` simply matches nothing -- fail closed,
    the same as one that matches no rule -- rather than raising.
    """
    candidate: str | None = None
    if name is not None:
        try:
            candidate = normalize(name)
        except Invalid:
            candidate = None

    ip: IPAddress | None = None
    if address is not None:
        parsed = _as_address(address)
        ip = unwrap(parsed) if parsed is not None else None

    for rule in rules:
        if rule.port == port and _allows(rule, candidate, ip):
            return rule
    return None


def _allows(rule: Rule, name: str | None, ip: IPAddress | None) -> bool:
    """Whether `rule` covers an already-normalised name or unwrapped address."""
    if rule.kind == "host":
        return name is not None and name == rule.host
    if rule.kind == "wildcard":
        return name is not None and rule.host is not None and _wildcard_matches(name, rule.host)
    if rule.kind == "localhost":
        return name == "localhost" or (ip is not None and ip in _LOOPBACK)
    return ip is not None and rule.network is not None and ip in rule.network


# ---------------------------------------------------------------------------
# address classification (matching rule 4 / appendix B)
# ---------------------------------------------------------------------------

# Ordered most specific first: the cloud-metadata addresses below sit inside
# the broader private/link-local ranges further down, and must be recognised
# by their more useful name before the broad range claims them.
_TABLE: tuple[tuple[IPNetwork, str], ...] = (
    (ipaddress.ip_network("168.63.129.16/32"), "cloud-metadata"),  # Azure
    (ipaddress.ip_network("fd00:ec2::/32"), "cloud-metadata"),  # AWS
    (ipaddress.ip_network("fd20:ce::254/128"), "cloud-metadata"),  # GCP
    (ipaddress.ip_network("fd00:c1::a9fe:a9fe/128"), "cloud-metadata"),  # Alibaba
    (ipaddress.ip_network("fd00:42::42/128"), "cloud-metadata"),  # DigitalOcean
    (ipaddress.ip_network("0.0.0.0/8"), "unspecified"),
    (ipaddress.ip_network("::/128"), "unspecified"),
    (ipaddress.ip_network("127.0.0.0/8"), "loopback"),
    (ipaddress.ip_network("::1/128"), "loopback"),
    (ipaddress.ip_network("10.0.0.0/8"), "private"),
    (ipaddress.ip_network("172.16.0.0/12"), "private"),
    (ipaddress.ip_network("192.168.0.0/16"), "private"),
    (ipaddress.ip_network("fc00::/7"), "private"),
    (ipaddress.ip_network("100.64.0.0/10"), "cgnat"),  # includes 100.100.100.200, Alibaba metadata
    (ipaddress.ip_network("169.254.0.0/16"), "link-local"),  # includes 169.254.169.254
    (ipaddress.ip_network("fe80::/10"), "link-local"),
    (ipaddress.ip_network("224.0.0.0/4"), "multicast"),
    (ipaddress.ip_network("ff00::/8"), "multicast"),
    (ipaddress.ip_network("255.255.255.255/32"), "broadcast"),
    (ipaddress.ip_network("240.0.0.0/4"), "reserved"),
    (ipaddress.ip_network("198.18.0.0/15"), "reserved"),  # benchmarking
    # IETF protocol assignments, incl. 192.0.0.192 (Oracle's metadata service)
    (ipaddress.ip_network("192.0.0.0/24"), "reserved"),
)


def classify(address: IPAddress | str, mine: Iterable[IPAddress | str] = ()) -> str | None:
    """`None` if `address` may be reached by name; otherwise which class it is.

    Appendix B / matching rule 4. `address` is unwrapped first (`unwrap`), so
    an IPv4-mapped, NAT64, 6to4 or Teredo spelling of a blocked address is
    still caught. Checks the explicit appendix-B table first (for a specific,
    reportable reason such as `"cloud-metadata"`), then `mine` -- this
    machine's own interface addresses, supplied by the caller, since
    gathering that set is a later phase -- then falls back to `ipaddress`'s
    own `is_private`/`is_loopback`/etc. properties as a second, independent
    check. Both are consulted, deliberately: `is_private`/`is_global` alone
    had CVE-2024-4032, so this never trusts them by themselves.

    Reasons: `"unspecified"`, `"loopback"`, `"private"`, `"cgnat"`,
    `"link-local"`, `"multicast"`, `"broadcast"`, `"reserved"`,
    `"cloud-metadata"`, `"own-interface"`.
    """
    parsed = _as_address(address)
    if parsed is None:
        raise Invalid(f"not an IP address: {address!r}.")
    ip = unwrap(parsed)

    for network, reason in _TABLE:
        if ip in network:
            return reason

    for own in mine:
        parsed_own = _as_address(own)
        if parsed_own is not None and unwrap(parsed_own) == ip:
            return "own-interface"

    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    return None


# ---------------------------------------------------------------------------
# local-service port warnings (6.7)
# ---------------------------------------------------------------------------

# port -> (what it is, what an agent that reaches it can do)
_LOCAL_SERVICE: dict[int, tuple[str, str]] = {
    2375: ("Docker's API port", "controls this machine"),
    2376: ("Docker's API port", "controls this machine"),
    6443: ("the Kubernetes API port", "can control the cluster"),
    10250: ("the kubelet port", "can run code on this node"),
    9050: ("Tor's SOCKS port", "gets full onward network reach through Tor, bypassing this allowlist"),
    1080: ("a SOCKS proxy port", "gets full onward network reach through it, bypassing this allowlist"),
    3128: ("a common HTTP proxy port", "gets full onward network reach through it, bypassing this allowlist"),
}
# 8080 is left out on purpose: it is far more often a development server than
# a proxy, and a warning on every such entry teaches people to ignore it.


def warn(rule: Rule) -> str | None:
    """Design 6.7: the warning for a rule that names a local service port
    that would give an agent full onward network reach, or `None`.

    Only for `localhost`, address and range entries. Docker's API (2375,
    2376), the Kubernetes API (6443), a kubelet (10250), Tor's SOCKS port
    (9050), and common proxy ports (1080, 3128). Naming one of these in `net` makes that service part of the
    boundary (6.7): "Other processes on the machine" residual.
    """
    if rule.kind not in ("localhost", "address", "range"):
        # A named host's port is that host's business; these warnings are
        # about services on this machine or its network, reached by address.
        return None
    found = _LOCAL_SERVICE.get(rule.port)
    if found is None:
        return None
    label, consequence = found
    return (
        f"hlyn: {rule} is {label}. An agent that reaches it {consequence}. "
        f"Remove {rule.flag()} unless you mean it."
    )
