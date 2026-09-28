# SPDX-License-Identifier: Apache-2.0
"""Host entries for `net`: grammar, normalisation, matching and address classes.

DESIGN-host-allowlisting.md 4.2 (what an entry can be), 4.3 (matching rules),
6.7 (local-service warnings), appendix B (addresses never reached by name), and
matrix rows 8-11 of section 9 at the unit level. Every test prints what it
observed, so the log shows the parsed rule or the exact refusal.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hlyn import hosts
from hlyn.error import Invalid


def accepted(entry: str) -> hosts.Rule:
    rule = hosts.parse(entry)
    print(f"{entry!r} -> {rule} (kind={rule.kind}, flag={rule.flag()})")
    return rule


def refused(entry: str) -> str:
    with pytest.raises(Invalid) as caught:
        hosts.parse(entry)
    text = str(caught.value)
    print(f"{entry!r} refused: {text}")
    return text


# ---------------------------------------------------------------------------
# 4.2: what an entry can be
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("entry", "canonical", "kind", "flag"), [
    ("api.openai.com", "api.openai.com:443", "host", "--net api.openai.com"),
    ("api.openai.com:8443", "api.openai.com:8443", "host", "--net api.openai.com:8443"),
    ("*.example.com", "*.example.com:443", "wildcard", "--net *.example.com"),
    ("localhost:5432", "localhost:5432", "localhost", "--net localhost:5432"),
    ("10.0.0.5:5432", "10.0.0.5:5432", "address", "--net 10.0.0.5:5432"),
    ("[2001:db8::10]:8443", "[2001:db8::10]:8443", "address", "--net [2001:db8::10]:8443"),
    ("10.20.0.0/16:8080", "10.20.0.0/16:8080", "range", "--net 10.20.0.0/16:8080"),
    ("[fd00::/8]:443", "[fd00::/8]:443", "range", "--net [fd00::/8]"),
])
def test_every_accepted_form(entry, canonical, kind, flag):
    rule = accepted(entry)
    assert str(rule) == canonical
    assert rule.kind == kind
    assert rule.flag() == flag


def test_a_bare_host_means_port_443():
    assert accepted("api.openai.com").port == 443


def test_the_canonical_form_parses_back_to_the_same_rule():
    for entry in ("API.OpenAI.com.", "*.Example.COM", "localhost:5432", "[2001:DB8::10]:8443",
                  "10.20.0.0/16:8080", "[::ffff:127.0.0.1]:80"):
        rule = accepted(entry)
        assert hosts.parse(str(rule)) == rule


@pytest.mark.parametrize(("entry", "fix"), [
    # Each refusal names what to write instead (4.2, and the CLAUDE.md rule
    # that every message says what to do next).
    ("https://api.openai.com/v1", "--net api.openai.com"),
    ("example.com/v1", "--net example.com"),
    ("user@example.com", "--net example.com"),
    ("example.com?x=1", "api.openai.com:8443"),
    ("host.example:https", "host.example:443"),
    ("host.example:80-90", "repeat the entry"),
    ("*", "*.example.com"),
    ("api.*.com", "*.example.com"),
    ("*.*.example.com", "Only one wildcard"),
    ("*.com", "*.example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("a\x00b.com", "Remove it"),
    ("a\r\nb.com", "Remove it"),
    ("[fe80::1%en0]:80", "remove it"),
    ("a_b.com", "letters, digits and '-'"),
    ("-a.com", "Trim the '-'"),
    ("a-.com", "Trim the '-'"),
    ("a..com", "Remove the extra dot"),
    ("a" * 64 + ".com", "Shorten it"),
    ("0177.0.0.1", "--net 127.0.0.1"),
    ("0x7f.1", "--net 127.0.0.1"),
    ("2130706433", "--net 127.0.0.1"),
    ("127.1", "--net 127.0.0.1"),
    # A trailing dot makes a name absolute, not a different address: "1." is
    # the address 0.0.0.1 to every resolver, so it is refused like "1".
    ("0.", "--net 0.0.0.0"),
    ("1.:443", "--net 0.0.0.1:443"),
    ("127.1.", "--net 127.0.0.1"),
    ("10.0.0.1.", "--net 10.0.0.1"),
    ("2001:db8::1", "--net [2001:db8::1]:443"),
    ("10.0.0.1/8:80", "--net 10.0.0.0/8:PORT"),
    ("[::ffff:0:0/100]:80", "Write the IPv4 range"),
    ("example.com:", "Drop the ':'"),
    ("example.com:0", "1-65535"),
    ("example.com:65536", "1-65535"),
])
def test_every_refused_form_names_the_fix(entry, fix):
    assert fix in refused(entry)


def test_a_name_over_253_characters_is_refused():
    name = ".".join(["a" * 63] * 4)  # 255 characters
    assert "over 253" in refused(name)


def test_a_name_of_exactly_253_characters_is_accepted():
    name = ".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 61])
    assert len(name) == 253
    assert accepted(name).host == name


def test_non_ascii_is_refused_even_when_it_has_no_xn_form():
    # A soft hyphen: invisible, and the confusable class 4.3.1 refuses outright.
    assert "xn--" in refused("exa­mple.com")


# ---------------------------------------------------------------------------
# 4.3 rule 1-3 and matrix row 8: names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", ["API.OPENAI.COM", "api.openai.com.", "Api.OpenAI.Com."])
def test_case_and_one_trailing_dot_match_the_same_rule(spelling):
    rules = [hosts.parse("api.openai.com")]
    found = hosts.match(rules, port=443, name=spelling)
    print(f"{spelling!r} -> {found}")
    assert found == rules[0]


@pytest.mark.parametrize("sent", [
    "api.openai.com..", "api­openai.com", "api.openai.com\x00.evil.net", "api.openai.com\r\n",
    "api_openai.com", "аpi.openai.com",  # noqa: RUF001 - the first letter is Cyrillic, on purpose
    "", "a" * 254,
])
def test_a_malformed_name_from_a_client_matches_nothing(sent):
    rules = [hosts.parse("api.openai.com"), hosts.parse("*.openai.com")]
    found = hosts.match(rules, port=443, name=sent)
    print(f"{sent!r} -> {found}")
    assert found is None


def test_the_port_must_match_too():
    rules = [hosts.parse("api.openai.com")]
    print(hosts.match(rules, port=8443, name="api.openai.com"))
    assert hosts.match(rules, port=8443, name="api.openai.com") is None


# ---------------------------------------------------------------------------
# matrix row 10: wildcards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "allowed"), [
    ("a.example.com", True),
    ("a.b.example.com", True),
    ("example.com", False),
    ("evilexample.com", False),
    ("example.com.evil.net", False),
    ("a.example.com.evil.net", False),
    ("a.example.co", False),
])
def test_a_wildcard_matches_subdomains_only(name, allowed):
    rules = [hosts.parse("*.example.com")]
    found = hosts.match(rules, port=443, name=name)
    print(f"*.example.com vs {name!r} -> {found}")
    assert (found is not None) is allowed


# ---------------------------------------------------------------------------
# matrix row 9: addresses in every spelling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", [
    "127.0.0.1", "::ffff:7f00:1", "::ffff:127.0.0.1", "0:0:0:0:0:ffff:7f00:1",
])
def test_a_listed_address_matches_in_any_ipv6_spelling(spelling):
    rules = [hosts.parse("localhost:5432")]
    found = hosts.match(rules, port=5432, address=spelling)
    print(f"{spelling!r} -> {found}")
    assert found == rules[0]


@pytest.mark.parametrize("spelling", ["0177.0.0.1", "0x7f.1", "2130706433", "127.1", "not-an-ip"])
def test_a_loose_ipv4_spelling_from_a_client_matches_nothing(spelling):
    rules = [hosts.parse("localhost:5432"), hosts.parse("127.0.0.1:5432")]
    found = hosts.match(rules, port=5432, address=spelling)
    print(f"{spelling!r} -> {found}")
    assert found is None


@pytest.mark.parametrize(("entry", "reached"), [
    ("[::ffff:10.0.0.5]:5432", "10.0.0.5"),
    ("[64:ff9b::a00:5]:5432", "10.0.0.5"),  # NAT64
    ("[2002:a00:5::]:5432", "10.0.0.5"),  # 6to4
])
def test_a_wrapped_address_in_a_rule_is_stored_as_the_ipv4_it_reaches(entry, reached):
    rule = accepted(entry)
    assert str(rule) == f"{reached}:5432"
    assert hosts.match([rule], port=5432, address=reached) == rule


def test_a_range_matches_addresses_inside_it_only():
    rules = [hosts.parse("10.20.0.0/16:8080")]
    for address, inside in (("10.20.1.2", True), ("::ffff:10.20.255.255", True), ("10.21.0.0", False)):
        found = hosts.match(rules, port=8080, address=address)
        print(f"{address} -> {found}")
        assert (found is not None) is inside


# ---------------------------------------------------------------------------
# matrix row 11 and appendix B: addresses never reached by name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("address", "reason"), [
    ("127.0.0.1", "loopback"),
    ("10.1.2.3", "private"),
    ("172.16.0.1", "private"),
    ("192.168.1.1", "private"),
    ("169.254.169.254", "link-local"),
    ("fd00:ec2::254", "cloud-metadata"),
    ("168.63.129.16", "cloud-metadata"),
    ("100.100.100.200", "cgnat"),
    ("192.0.0.192", "reserved"),
    ("0.0.0.0", "unspecified"),  # noqa: S104 - classified, not bound
    ("::", "unspecified"),
    ("::1", "loopback"),
    ("fe80::1", "link-local"),
    ("fc00::1", "private"),
    ("224.0.0.1", "multicast"),
    ("ff02::1", "multicast"),
    ("255.255.255.255", "broadcast"),
    ("240.0.0.1", "reserved"),
    ("198.18.0.1", "reserved"),
    # The same addresses wrapped in IPv6 (rule 3).
    ("::ffff:169.254.169.254", "link-local"),
    ("64:ff9b::a9fe:a9fe", "link-local"),
    ("2002:7f00:1::", "loopback"),
    ("::ffff:10.0.0.5", "private"),
])
def test_special_addresses_are_never_reached_by_name(address, reason):
    found = hosts.classify(address)
    print(f"{address} -> {found}")
    assert found == reason


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_may_be_reached_by_name(address):
    found = hosts.classify(address)
    print(f"{address} -> {found}")
    assert found is None


def test_this_machines_own_addresses_are_never_reached_by_name():
    mine = ["203.0.113.7", ipaddress.ip_address("2001:4860::7")]
    for address in ("203.0.113.7", "::ffff:203.0.113.7", "2001:4860::7"):
        found = hosts.classify(address, mine=mine)
        print(f"{address} with mine={mine} -> {found}")
        assert found == "own-interface"


def test_classify_refuses_what_is_not_an_address():
    with pytest.raises(Invalid) as caught:
        hosts.classify("example.com")
    print(caught.value)


# ---------------------------------------------------------------------------
# 6.7: local services that give onward reach
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("entry", "said"), [
    ("localhost:2375", "Docker's API"),
    ("localhost:2376", "Docker's API"),
    ("10.0.0.5:6443", "Kubernetes"),
    ("10.0.0.0/8:10250", "kubelet"),
    ("localhost:9050", "Tor"),
    ("localhost:1080", "SOCKS"),
    ("localhost:3128", "proxy"),
])
def test_a_local_service_port_warns_and_names_the_flag(entry, said):
    text = hosts.warn(hosts.parse(entry))
    print(f"{entry} -> {text}")
    assert text is not None and said in text
    assert f"Remove {hosts.parse(entry).flag()}" in text


@pytest.mark.parametrize("entry", ["localhost:5432", "api.example.com:2375", "api.example.com:8080"])
def test_other_entries_do_not_warn(entry):
    text = hosts.warn(hosts.parse(entry))
    print(f"{entry} -> {text}")
    assert text is None


# ---------------------------------------------------------------------------
# properties
# ---------------------------------------------------------------------------

label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=20).filter(
    lambda s: s[0] != "-" and s[-1] != "-"
)
name = st.lists(label, min_size=2, max_size=5).map(".".join).filter(
    lambda s: len(s) <= 253 and not s.replace(".", "").isdigit()
)


@settings(max_examples=300, deadline=None)
@given(name, st.sampled_from(["", "."]), st.booleans())
def test_normalising_is_idempotent_and_ignores_case_and_one_trailing_dot(host, dot, upper):
    spelled = (host.upper() if upper else host) + dot
    once = hosts.normalize(spelled)
    assert once == host
    assert hosts.normalize(once) == once


@settings(max_examples=300, deadline=None)
@given(name, label)
def test_a_wildcard_never_matches_its_bare_domain_or_a_mere_suffix(suffix, prefix):
    rules = [hosts.parse(f"*.{suffix}")]
    assert hosts.match(rules, port=443, name=suffix) is None
    # Glued on without a dot: ends with the suffix, is not under it.
    glued = prefix + suffix
    if len(glued) <= 253:
        assert hosts.match(rules, port=443, name=glued) is None
    after = f"{suffix}.{prefix}"
    if not after.endswith(f".{suffix}"):  # "a.a" + ".a" really is under "a.a"
        assert hosts.match(rules, port=443, name=after) is None
    child = f"{prefix}.{suffix}"
    if len(child) <= 253:
        assert hosts.match(rules, port=443, name=child) is not None


SPECIAL = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
           "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "198.18.0.0/15", "192.0.0.0/24",
           "0.0.0.0/8"]


@settings(max_examples=500, deadline=None)
@given(st.sampled_from(SPECIAL), st.integers(min_value=0, max_value=2**32 - 1),
       st.sampled_from(["plain", "mapped", "nat64", "6to4"]))
def test_every_special_ipv4_address_is_refused_by_name_in_every_spelling(block, noise, form):
    network = ipaddress.ip_network(block)
    host = int(network.network_address) + noise % network.num_addresses
    v4 = ipaddress.IPv4Address(host)
    spelled = {
        "plain": v4,
        "mapped": ipaddress.IPv6Address(f"::ffff:{v4}"),
        "nat64": ipaddress.IPv6Address((0x64FF9B << 96) | host),
        "6to4": ipaddress.IPv6Address((0x2002 << 112) | (host << 80)),
    }[form]
    assert hosts.classify(spelled) is not None, f"{spelled} ({form} of {v4}) was reachable by name"


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=40))
def test_parse_either_returns_a_rule_or_refuses_cleanly(text):
    # Anything a user types: a Rule, or Invalid with a message. Never another
    # exception, which would surface as a traceback instead of advice.
    try:
        rule = hosts.parse(text)
    except Invalid as exc:
        assert str(exc)
    else:
        assert hosts.parse(str(rule)) == rule
