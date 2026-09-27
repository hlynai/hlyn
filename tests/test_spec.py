# SPDX-License-Identifier: Apache-2.0
"""Policy files.

The dangerous failure here is not a crash, it is a file that parses into a
policy nobody meant: a typo'd field silently dropped, a relative path resolved
against the wrong directory, a host name accepted because a file took a
different route into `Policy` than a keyword argument does.
"""

from __future__ import annotations

import json
import os

import pytest

from hlyn import spec
from hlyn.error import Invalid
from hlyn.policy import Policy


def write(tmp_path, name: str, text: str) -> str:
    where = tmp_path / name
    where.write_text(text)
    return str(where)


# -- what a file means ------------------------------------------------------


def test_a_toml_policy_becomes_a_policy(tmp_path):
    path = write(tmp_path, "p.toml", 'read = ["/srv"]\nnet = [443]\nexec = false\n')
    plan = spec.load(path)
    assert plan.read == ("/srv",)
    assert plan.net == (443,)
    assert plan.exec is False


def test_json_and_toml_agree(tmp_path):
    body = {"read": ["/srv"], "net": [443], "env": ["OPENAI_API_KEY"]}
    as_json = write(tmp_path, "p.json", json.dumps(body))
    as_toml = write(
        tmp_path,
        "p.toml",
        'read = ["/srv"]\nnet = [443]\nenv = ["OPENAI_API_KEY"]\n',
    )
    assert spec.load(as_json) == spec.load(as_toml)


def test_a_policy_survives_a_round_trip(tmp_path):
    first = Policy(read=["/srv"], write=["/out"], net=[443], env=["X"], exec=False)
    path = write(tmp_path, "p.json", spec.dumps(first))
    assert spec.load(path) == first


def test_relative_paths_resolve_against_the_file_not_the_caller(tmp_path, monkeypatch):
    """A checked-in policy must mean the same thing from any directory."""
    (tmp_path / "src").mkdir()
    path = write(tmp_path, "p.toml", 'read = ["src"]\n')
    monkeypatch.chdir(os.path.dirname(os.path.abspath(__file__)))
    assert spec.load(path).read == (str(tmp_path / "src"),)


def test_absolute_paths_are_left_alone(tmp_path):
    path = write(tmp_path, "p.toml", 'read = ["/etc/hostname"]\n')
    assert spec.load(path).read == ("/etc/hostname",)


def test_ports_and_names_are_not_treated_as_paths(tmp_path):
    """`net` and `env` hold numbers and names, so anchoring them would be wrong."""
    path = write(tmp_path, "p.toml", 'net = [443]\nenv = ["HOME"]\n')
    plan = spec.load(path)
    assert plan.net == (443,)
    assert plan.env == ("HOME",)


# -- what a file may not do -------------------------------------------------


def test_an_unknown_field_is_refused_not_ignored(tmp_path):
    """The whole point: a grant nobody reads is a grant nobody notices."""
    path = write(tmp_path, "p.toml", 'reed = ["/srv"]\n')
    with pytest.raises(Invalid) as caught:
        spec.load(path)
    assert "reed" in str(caught.value)


def test_a_file_is_checked_by_the_same_rules_as_a_keyword(tmp_path):
    """A host entry means the same, and is refused the same, however it arrives."""
    path = write(tmp_path, "p.toml", 'net = ["API.openai.com.", "localhost:5432"]\n')
    loaded = spec.load(path)
    print(loaded.net)
    assert loaded == Policy(net=["api.openai.com", "localhost:5432"])
    bad = write(tmp_path, "q.toml", 'net = ["https://api.openai.com/v1"]\n')
    with pytest.raises(Invalid) as caught:
        spec.load(bad)
    print(caught.value)
    assert "--net api.openai.com" in str(caught.value)


def test_hosts_round_trip_through_json_and_toml(tmp_path):
    p = Policy(net=["*.githubusercontent.com", "[::ffff:10.0.0.5]:5432", "10.20.0.0/16:8080"])
    text = spec.dumps(p)
    print(text)
    assert json.loads(text)["net"] == ["*.githubusercontent.com:443", "10.0.0.5:5432", "10.20.0.0/16:8080"]
    assert spec.loads(text, "json") == p


def test_an_empty_file_is_refused(tmp_path):
    """Reading it as deny-everything would be a confusing way to find a typo."""
    path = write(tmp_path, "p.toml", "\n")
    with pytest.raises(Invalid):
        spec.load(path)


def test_a_missing_file_says_so(tmp_path):
    with pytest.raises(Invalid) as caught:
        spec.load(str(tmp_path / "absent.toml"))
    assert "absent.toml" in str(caught.value)


def test_an_unknown_extension_is_refused(tmp_path):
    path = write(tmp_path, "p.ini", "read = /srv\n")
    with pytest.raises(Invalid) as caught:
        spec.load(path)
    assert "ini" in str(caught.value)


def test_a_document_that_is_not_a_mapping_is_refused(tmp_path):
    path = write(tmp_path, "p.json", '["/srv"]')
    with pytest.raises(Invalid) as caught:
        spec.load(path)
    assert "mapping" in str(caught.value)


def test_malformed_syntax_is_reported_as_such(tmp_path):
    path = write(tmp_path, "p.json", "{not json")
    with pytest.raises(Invalid) as caught:
        spec.load(path)
    assert "JSON" in str(caught.value)


# -- how a file reaches the rest of the package -----------------------------


def test_a_file_can_be_passed_anywhere_a_policy_can(tmp_path):
    from hlyn import jail

    path = write(tmp_path, "p.toml", 'read = ["/srv"]\n')
    assert jail._plan(path, {}).read == ("/srv",)


def test_a_preset_name_wins_over_a_file_of_the_same_name(tmp_path, monkeypatch):
    """Presets are a closed set; a bare word is a preset, not a guess at a file."""
    from hlyn import jail

    monkeypatch.chdir(tmp_path)
    (tmp_path / "coder").write_text("read = []\n")
    assert jail._plan("coder", {}).exec is True  # the preset, not the file


def test_keywords_still_edit_a_policy_that_came_from_a_file(tmp_path):
    from hlyn import jail

    path = write(tmp_path, "p.toml", 'read = ["/srv"]\n')
    assert jail._plan(path, {"net": [443]}).net == (443,)


def test_the_intent_form_excludes_the_interpreters_own_files():
    """A file must not freeze one machine's interpreter layout into a document."""
    body = spec.shape(Policy(read=["/srv"]))
    assert body["read"] == ["/srv"]
