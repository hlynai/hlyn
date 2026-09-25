"""A policy written down, rather than passed as keyword arguments.

Keywords and command-line flags are fine for the engineer who wrote them and
useless to the person who has to approve them. A file can be reviewed, diffed,
commented, checked in, and pointed at in an audit, which is most of what makes
a control real rather than intended.

    hlyn.load("agent-policy.toml")          -> Policy

Three formats are read. TOML is the one to prefer and the one the examples use:
it takes comments, and a reviewer's questions belong next to the line that
raises them. JSON is read because `hlyn show --intent` writes it and the
standard library can always parse it. YAML is read only if PyYAML is already
installed -- this package depends on nothing, and a containment layer is the
last place to start pulling in parsers.

Two decisions in here are worth knowing about, because both are the kind of
thing that quietly widens a boundary if it goes the other way.

**A key this module does not recognise is an error.** A policy file is
security configuration, and the failure mode of ignoring `reed = ["/src"]` is
a boundary that is tighter than the file says while everyone believes it is
looser -- or, with `net`, the reverse. Refusing costs a five-second fix;
ignoring costs an incident nobody can explain.

**Relative paths resolve against the file, not the working directory.** A
policy checked in beside the agent it confines should mean the same thing
whatever directory it is invoked from. `read = ["src"]` next to
`/srv/app/policy.toml` grants `/srv/app/src`, from anywhere.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from .error import Invalid
from .policy import Policy

__all__ = ["build", "dumps", "load", "loads", "raw", "shape"]


# Every field a policy file may set, which is every field `Policy` has. Kept as
# an explicit tuple rather than read off the dataclass so that adding a field to
# `Policy` is a deliberate decision to expose it in a file, not an automatic
# one.
FIELDS: tuple[str, ...] = ("read", "write", "exec", "net", "env", "tmp", "log")

# Paths in these fields resolve against the file's own directory. `net` and
# `env` hold ports and variable names, and `tmp` and `log` are locations the
# runtime writes to rather than grants -- those stay as written.
ROOTED: tuple[str, ...] = ("read", "write", "exec")


def shape(policy: Policy) -> dict[str, Any]:
    """A policy as a plain dictionary, in the form a file holds it.

    Intent, not the resolved grant list. The interpreter's own files are
    deliberately absent: they are computed from whichever interpreter is
    running, so writing them into a file would freeze one machine's answer into
    a document meant to outlive it. `hlyn show` prints the resolved view when
    that is the question.
    """
    out: dict[str, Any] = {}
    for field in FIELDS:
        value = getattr(policy, field)
        out[field] = list(value) if isinstance(value, tuple) else value
    return out


def dumps(policy: Policy) -> str:
    """A policy as JSON, ready to be written to a file and reviewed."""
    return json.dumps(shape(policy), indent=2) + "\n"


def _rooted(value: object, root: str, field: str) -> object:
    """Resolve relative paths in one field against `root`."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise Invalid(
            f"{field}: expected a list of paths, or true/false, got {type(value).__name__}."
        )
    out = []
    for item in value:
        if not isinstance(item, str):
            raise Invalid(f"{field}: expected a path, got {item!r}.")
        out.append(item if os.path.isabs(os.path.expanduser(item)) else os.path.join(root, item))
    return out


def build(data: Mapping[str, Any], root: str | None = None) -> Policy:
    """Turn a parsed policy document into a `Policy`.

    `root` is the directory relative paths are resolved against. Callers that
    have no file to anchor to may leave it out, and then relative paths mean
    what they would anywhere else in Python: relative to the working directory.
    """
    if not isinstance(data, Mapping):
        raise Invalid(
            f"a policy document must be a mapping of field names to values, "
            f"got {type(data).__name__}."
        )

    strange = [key for key in data if key not in FIELDS]
    if strange:
        known = ", ".join(FIELDS)
        raise Invalid(
            f"unknown field(s) in policy: {', '.join(sorted(strange))}. "
            f"A policy file is refused rather than partly applied, because a field "
            f"nobody reads is a grant nobody notices. Known fields: {known}."
        )

    edits: dict[str, Any] = {}
    for field, value in data.items():
        edits[field] = _rooted(value, root, field) if root and field in ROOTED else value

    # Policy's own __post_init__ does the real validation -- ports, path shapes,
    # host names -- so a file and a keyword argument are checked by exactly the
    # same code and cannot drift apart.
    return Policy(**edits)


def _find(*names: str) -> Any:
    """The first of `names` that is installed, or None.

    Imported by name rather than with an `import` statement because these are
    genuinely optional: this package depends on nothing, and a static import of
    a module that may not exist is a type error on every interpreter where it
    does not.
    """
    import importlib

    for name in names:
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    return None


def _toml(text: str) -> Any:
    """Parse TOML with whatever the interpreter has, or say what is missing."""
    parser = _find("tomllib", "tomli")  # stdlib on 3.11+, a package before that
    if parser is None:
        raise Invalid(
            "reading TOML needs Python 3.11 or newer, where it is in the standard "
            "library, or the `tomli` package on 3.10. Install tomli, upgrade, or "
            "write the policy as JSON -- hlyn depends on nothing and will not pull "
            "a parser in on its own."
        )
    try:
        return parser.loads(text)
    except Exception as exc:  # noqa: BLE001 - any parse failure, reported as one
        raise Invalid(f"this is not valid TOML: {exc}") from None


def _yaml(text: str) -> Any:
    """Parse YAML if PyYAML is installed, and say so plainly if it is not."""
    parser = _find("yaml")
    if parser is None:
        raise Invalid(
            "reading YAML needs the `pyyaml` package, which hlyn does not depend on. "
            "Install it, or write the policy as TOML or JSON."
        )
    try:
        # safe_load, not load: a policy file is exactly the kind of document an
        # attacker would like to see handed to a constructor-calling parser.
        return parser.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - any parse failure, reported as one
        raise Invalid(f"this is not valid YAML: {exc}") from None


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise Invalid(f"this is not valid JSON: {exc}") from None


KINDS: dict[str, Any] = {
    "toml": _toml,
    "json": _json,
    "yaml": _yaml,
    "yml": _yaml,
}


def loads(text: str, kind: str = "toml", root: str | None = None) -> Policy:
    """Parse a policy document held in a string."""
    parse = KINDS.get(kind.lower().lstrip("."))
    if parse is None:
        raise Invalid(f"unknown policy format {kind!r}. Known formats: toml, json, yaml.")
    got = parse(text)
    # An empty document is almost certainly a truncated file or the wrong
    # format for the extension, and it would otherwise read as the strictest
    # policy there is -- which fails safe, but leaves someone debugging an
    # agent that cannot open anything with no hint as to why. An empty policy
    # that is meant sets a field explicitly. (TOML yields `{}` where JSON and
    # YAML yield `None`, so both shapes are checked.)
    if got is None or (isinstance(got, Mapping) and not got):
        raise Invalid(
            "this policy document is empty. If nothing but the runtime should be "
            "granted, say so explicitly, e.g. `read = []`."
        )
    return build(got, root)


def raw(path: str | os.PathLike[str]) -> dict[str, Any]:
    """The document as written, before it becomes a `Policy`.

    Needed by the audit, which has findings about the difference between the
    two: a path named in the file and then swallowed by a broader one in the
    same field is gone by the time a `Policy` exists, and it is exactly the
    kind of thing a reviewer should be told about.
    """
    where = os.path.abspath(os.fspath(path))
    kind = os.path.splitext(where)[1].lstrip(".").lower()
    parse = KINDS.get(kind)
    if parse is None:
        return {}
    try:
        with open(where, encoding="utf-8") as fh:
            got = parse(fh.read())
    except (OSError, Invalid):
        return {}
    return dict(got) if isinstance(got, Mapping) else {}


def load(path: str | os.PathLike[str]) -> Policy:
    """Read a policy from a file, choosing the format by extension."""
    where = os.path.abspath(os.fspath(path))
    kind = os.path.splitext(where)[1].lstrip(".").lower()
    if not kind:
        raise Invalid(
            f"{where}: a policy file needs an extension saying what it is "
            f"(.toml, .json, or .yaml)."
        )
    if kind not in KINDS:
        raise Invalid(
            f"{where}: {kind!r} is not a policy format hlyn reads. Use .toml, .json, or .yaml."
        )
    try:
        with open(where, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise Invalid(f"{where}: {exc.strerror or 'could not be read'}.") from None
    return loads(text, kind, root=os.path.dirname(where))
