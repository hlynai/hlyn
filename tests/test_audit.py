"""Reading a policy for grants nobody meant to make.

The findings that matter are the ones about two fields combining, because
those are the ones review misses: each half looks reasonable on its own. So
most of what is asserted here is that a *pair* is caught, and -- equally --
that a safe policy produces silence, since a checker that always finds
something gets switched off within a week.
"""

from __future__ import annotations

import datetime as dt

import pytest

from hlyn import accept, audit
from hlyn.error import Invalid
from hlyn.policy import Policy


def ids(found) -> set[str]:
    return {item.rule for item in found}


def only(found, rule):
    return [item for item in found if item.rule == rule]


# -- the pairs --------------------------------------------------------------


def test_writing_and_running_the_same_tree_is_critical():
    """Write a program, then run it: every other grant becomes a starting point."""
    found = only(audit.check(Policy(write=["/srv/app"], exec=["/srv/app/tool"])), "write-exec")
    assert found and found[0].severity == "critical"


def test_writing_anywhere_with_any_exec_is_critical():
    found = only(audit.check(Policy(write=True, exec=True)), "write-exec")
    assert found and found[0].severity == "critical"


def test_separate_write_and_exec_trees_are_not_flagged():
    assert not only(audit.check(Policy(write=["/out"], exec=["/usr/bin/git"])), "write-exec")


def test_reading_credentials_and_reaching_the_network_is_exfiltration():
    found = only(audit.check(Policy(read=["/root"], net=[443])), "exfiltration")
    assert found and found[0].severity == "critical"


def test_credentials_without_a_network_is_not_exfiltration():
    assert not only(audit.check(Policy(read=["/root"])), "exfiltration")


def test_a_network_without_credentials_is_not_exfiltration():
    assert not only(audit.check(Policy(read=["/srv/data"], net=[443])), "exfiltration")


# -- credentials ------------------------------------------------------------


def test_a_home_directory_reaches_credentials_without_naming_any():
    """`read = ["/root"]` mentions no secret, and reaches every dotfile there is."""
    assert only(audit.check(Policy(read=["/root"])), "credential-reach")


def test_a_named_credential_directory_is_caught():
    assert only(audit.check(Policy(read=["/home/app/.aws"])), "credential-reach")


def test_a_users_home_on_macos_shape_is_caught():
    assert only(audit.check(Policy(read=["~"])), "credential-reach")


def test_reading_everything_is_reported_as_reaching_credentials():
    assert only(audit.check(Policy(read=True)), "credential-reach")


def test_an_ordinary_data_directory_is_not_flagged():
    """A checker that fires on everything is a checker nobody keeps."""
    assert not only(audit.check(Policy(read=["/srv/data"])), "credential-reach")


def test_etc_reaches_the_password_file():
    assert only(audit.check(Policy(read=["/etc"])), "credential-reach")


# -- the subtle ones --------------------------------------------------------


def test_an_interpreter_on_the_exec_list_defeats_the_allowlist():
    """The list governs which file runs; an interpreter runs whatever it is given."""
    found = only(audit.check(Policy(exec=["/usr/bin/python3"])), "interpreter-exec")
    assert found and found[0].severity == "high"


def test_a_versioned_interpreter_is_still_an_interpreter():
    assert only(audit.check(Policy(exec=["/usr/local/bin/python3.13"])), "interpreter-exec")


def test_an_ordinary_program_on_the_exec_list_is_fine():
    assert not only(audit.check(Policy(exec=["/usr/bin/convert"])), "interpreter-exec")


def test_a_writable_log_stops_being_evidence():
    found = only(audit.check(Policy(write=["/srv/app"], log="/srv/app/hlyn.log")), "evidence")
    assert found and found[0].severity == "high"


def test_a_log_outside_every_writable_path_is_fine():
    assert not only(audit.check(Policy(write=["/srv/app"], log="/var/log/hlyn.log")), "evidence")


def test_writing_where_programs_are_found_is_a_hijack():
    assert only(audit.check(Policy(write=["/usr/local/bin"])), "hijack")


def test_proc_hands_back_the_environment_that_was_scrubbed():
    assert only(audit.check(Policy(write=["/proc"])), "proc-write")


def test_naming_tcp_ports_reports_that_udp_stays_open():
    assert only(audit.check(Policy(net=[443])), "udp-open")


def test_closing_the_network_says_nothing_about_udp():
    assert not only(audit.check(Policy(net=False)), "udp-open")


def test_the_debug_preset_is_reported_as_no_boundary():
    from hlyn.policy import preset

    found = only(audit.check(preset("debug")), "no-boundary")
    assert found and found[0].severity == "critical"


def test_a_path_swallowed_by_a_broader_one_is_reported():
    """What the reviewer reads names a path the kernel never sees."""
    asked = {"read": ["/srv/app", "/srv/app/config"]}
    found = only(audit.check(Policy(read=asked["read"]), asked), "widened")
    assert found and found[0].subject == "/srv/app/config"


def test_without_the_document_there_is_nothing_to_compare():
    assert not only(audit.check(Policy(read=["/srv/app", "/srv/app/config"])), "widened")


# -- the shape of a report --------------------------------------------------


def test_a_tight_policy_produces_nothing():
    """Silence on a good policy is what earns attention on a bad one."""
    assert audit.check(Policy(read=["/srv/data"], write=["/srv/out"])) == []


def test_findings_come_back_worst_first():
    found = audit.check(Policy(read=["/root"], net=[443], exec=["/usr/bin/python3"]))
    ranks = [audit.RANK[item.severity] for item in found]
    assert ranks == sorted(ranks)


def test_every_finding_says_what_why_and_how_to_fix_it():
    """A finding without a fix gets waived rather than addressed."""
    for item in audit.check(Policy(read=["/root"], net=[443], write=["/usr/bin"])):
        assert item.says and item.why and item.fix
        assert item.id.startswith(item.rule + ":")


# -- accepting a risk -------------------------------------------------------


TODAY = dt.date(2026, 7, 30)


def seat(finding: str, until: str = "2026-12-31") -> accept.Accepted:
    return accept.Accepted(finding, "a reason", "someone@example.com", dt.date.fromisoformat(until))


def test_an_accepted_finding_stops_being_outstanding():
    found = audit.check(Policy(net=[443]))
    verdict = accept.apply(found, [seat("udp-open:443")], TODAY)
    assert verdict.clean
    assert len(verdict.waived) == 1


def test_an_accepted_finding_is_still_reported():
    """A report that hides accepted risk cannot be used to review the decision."""
    found = audit.check(Policy(net=[443]))
    verdict = accept.apply(found, [seat("udp-open:443")], TODAY)
    assert verdict.waived[0][0].rule == "udp-open"


def test_an_expired_acceptance_stops_waiving():
    found = audit.check(Policy(net=[443]))
    verdict = accept.apply(found, [seat("udp-open:443", "2025-01-01")], TODAY)
    assert not verdict.clean
    assert len(verdict.expired) == 1


def test_an_acceptance_that_matches_nothing_is_stale():
    verdict = accept.apply([], [seat("udp-open:443")], TODAY)
    assert verdict.stale and verdict.clean


def test_a_whole_rule_can_be_accepted_at_once():
    """Waiving by rule rather than by id, for a finding that recurs per path."""
    found = audit.check(Policy(read=["/root"]))
    verdict = accept.apply(found, [seat("credential-reach")], TODAY)
    assert verdict.clean


def test_waiving_one_subject_does_not_waive_another():
    found = audit.check(Policy(read=["/root", "/home/app/.ssh"]))
    verdict = accept.apply(found, [seat("credential-reach:/root")], TODAY)
    assert verdict.live


# -- the register file ------------------------------------------------------


def test_a_register_needs_a_reason_an_owner_and_an_expiry():
    for missing in ("reason", "by", "until"):
        body = {
            "accepted": [
                {
                    "finding": "udp-open:443",
                    "reason": "r",
                    "by": "b",
                    "until": "2026-12-31",
                }
            ]
        }
        del body["accepted"][0][missing]
        with pytest.raises(Invalid) as caught:
            accept.build(body)
        assert missing in str(caught.value)


def test_an_empty_reason_is_not_a_decision():
    body = {"accepted": [{"finding": "x", "reason": "  ", "by": "b", "until": "2026-12-31"}]}
    with pytest.raises(Invalid):
        accept.build(body)


def test_an_unknown_field_in_the_register_is_refused():
    body = {"accepted": [{"finding": "x", "reason": "r", "by": "b", "until": "2026-12-31", "wat": 1}]}
    with pytest.raises(Invalid) as caught:
        accept.build(body)
    assert "wat" in str(caught.value)


def test_a_bad_date_says_what_a_date_looks_like():
    body = {"accepted": [{"finding": "x", "reason": "r", "by": "b", "until": "soon"}]}
    with pytest.raises(Invalid) as caught:
        accept.build(body)
    assert "2026-12-31" in str(caught.value)


def test_a_register_reads_from_toml(tmp_path):
    path = tmp_path / "risks.toml"
    path.write_text(
        "[[accepted]]\n"
        'finding = "udp-open:443"\n'
        'reason  = "egress is restricted upstream"\n'
        'by      = "karan@hlyn.dev"\n'
        "until   = 2026-12-31\n"
    )
    got = accept.load(str(path))
    assert got[0].finding == "udp-open:443"
    assert got[0].until == dt.date(2026, 12, 31)
