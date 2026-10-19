# SPDX-License-Identifier: Apache-2.0
"""What SECURITY.md promises, and the tests that check each promise.

`test_promises.py` reads SECURITY.md and fails when a promise has no entry
here, when an entry names a test that does not exist, or when an entry has no
check and no stated reason. Add the entry in the same change as the promise.

Each entry:
  says       the start of the bullet in SECURITY.md (whitespace as one space).
  tests      "file::function" for tests that try to break the promise.
  control    tests of the allowed twin: the same kind of action, permitted, shown
             to work. A refusal test without one can pass because the probe is
             blind, not because the boundary held.
  no_control why there is none (when `control` is empty).
  gap        what is known not to be covered, with its REMAINING number.
"""

from __future__ import annotations

# One shared allowed twin per area, so an entry points at the same proof.
TUNNEL = "test_proxy.py::test_a_listed_host_is_tunnelled_and_bytes_flow_both_ways"
HOSTS = "test_hostmode.py::test_every_entry_point_reaches_a_listed_host_and_only_it"

# Bullets that are not promises of their own, with why.
EXEMPT: dict[str, str] = {
    'anything in the "It stops" list': 'points at the "It stops" list, which is mapped item by item below',
}

PROMISES: list[dict[str, object]] = [
    # --- What counts as a vulnerability ---
    {
        "says": "reading, writing, or executing a path the policy did not grant",
        "tests": ["test_landlock.py::test_a_path_outside_the_grant_is_refused",
                  "test_landlock.py::test_writing_outside_the_grant_is_refused",
                  "test_landlock.py::test_running_a_program_outside_the_grant_is_refused",
                  "test_landlock.py::test_a_symlink_cannot_leave_the_grant",
                  "test_landlock.py::test_dotdot_cannot_leave_the_grant"],
        "control": ["test_landlock.py::test_a_granted_path_is_readable",
                    "test_landlock.py::test_a_granted_path_is_writable"],
    },
    {
        "says": "reaching a TCP port the policy did not name",
        "tests": ["test_landlock.py::test_an_ungranted_port_is_refused",
                  "test_landlock.py::test_an_adjacent_port_is_refused",
                  "test_landlock.py::test_ipv6_gets_the_same_port_enforcement_as_ipv4"],
        "control": ["test_landlock.py::test_a_granted_port_is_reachable"],
    },
    {
        "says": "reaching a host `net` does not list",
        "tests": ["test_hostmode.py::test_row_15_clients_that_ignore_the_proxy_fail_closed",
                  "test_hostmode.py::test_row_16_the_agent_cannot_touch_the_helpers_or_another_runs_proxy",
                  "test_hostmode.py::test_row_17_a_helper_killed_mid_run_closes_the_network_and_opens_nothing"],
        "control": [HOSTS],
    },
    {
        "says": "reaching another agent's process, memory, signals, or descriptors",
        "tests": ["test_landlock.py::test_signalling_outside_the_domain_is_refused",
                  "test_landlock.py::test_abstract_unix_socket_outside_the_domain_is_refused",
                  "test_seccomp.py::test_ptrace_is_shut",
                  "test_seccomp.py::test_process_vm_readv_is_shut",
                  "test_seccomp.py::test_stealing_a_descriptor_from_another_process_is_shut"],
        "control": ["test_signals.py::test_an_agent_signals_what_it_started_and_nothing_else"],
    },
    {
        "says": "removing, weakening, or escaping the confinement after it has been applied",
        "tests": ["test_escape.py::test_a_child_cannot_shed_the_boundary",
                  "test_seccomp.py::test_unshare_is_shut",
                  "test_seccomp.py::test_setns_is_shut",
                  "test_seccomp.py::test_mount_is_shut",
                  "test_seccomp.py::test_new_user_namespace_via_clone_is_shut",
                  "test_escape.py::test_a_refused_syscall_through_a_foreign_abi_never_runs"],
        "control": ["test_seccomp.py::test_python_survives_the_filter"],
    },
    {
        "says": "`seal` returning success when the kernel applied less than the whole policy",
        "tests": ["test_landlock.py::test_partial_enforcement_raises_instead_of_returning",
                  "test_landlock.py::test_no_enforcement_at_all_raises",
                  "test_landlock.py::test_every_shim_failure_raises_and_says_which",
                  "test_openat2_refused.py::test_a_refused_openat2_makes_the_seal_fail_and_name_why"],
        "control": ["test_landlock.py::test_full_enforcement_is_the_only_case_that_returns",
                    "test_openat2_refused.py::test_the_same_seal_works_without_the_refusal"],
    },
    # --- It stops ---
    {
        "says": "Opening a TCP connection to any host and port not on the list",
        "tests": ["test_escape.py::test_tcp_is_still_refused_when_the_network_is_closed",
                  "test_hostfilter.py::test_a_tcp_connect_the_kernel_runs_is_refused_by_landlock_whatever_its_port",
                  "test_proxy.py::test_row_13_an_unlisted_port_on_a_listed_host_is_403",
                  "test_guard.py::test_row_1_and_2_any_other_address_is_refused_and_nothing_reaches_it",
                  "test_guard.py::test_row_3_racing_the_address_never_connects_tcp_anywhere_but_the_proxy"],
        "control": [TUNNEL],
    },
    {
        "says": "Reaching private, loopback, link-local or cloud-metadata addresses through a public name",
        "tests": ["test_proxy.py::test_row_11_a_name_resolving_privately_is_refused",
                  "test_proxy.py::test_row_11_private_answers_are_dropped_and_only_public_ones_dialled",
                  "test_proxy.py::test_row_11_each_connection_resolves_once_and_uses_the_address_it_checked",
                  "test_hosts.py::test_every_special_ipv4_address_is_refused_by_name_in_every_spelling"],
        "control": ["test_proxy.py::test_localhost_is_never_looked_up_and_reaches_loopback", TUNNEL],
    },
    {
        "says": "UDP of any kind (DNS, QUIC, anything tunnelled over it), raw IP, SCTP",
        "tests": ["test_landlock.py::test_closing_the_network_closes_udp_too",
                  "test_seccomp.py::test_every_family_net_does_not_describe_is_refused",
                  "test_seccomp.py::test_a_domain_outside_the_network_policy_is_shut",
                  "test_hostfilter.py::test_ip_sockets_must_be_tcp_and_other_families_are_refused",
                  "test_escape.py::test_a_socket_family_with_high_bits_set_cannot_open_the_network"],
        "control": ["test_seccomp.py::test_the_allowed_families_still_work",
                    "test_seccomp.py::test_network_is_available_when_open"],
    },
    {
        "says": "DNS lookups, whether over UDP, over TCP, through the resolver daemons or D-Bus",
        "tests": ["test_proxy.py::test_tcp_53_is_refused_as_dns",
                  "test_proxy.py::test_gate_mode_direct_to_port_53_is_reported_as_dns",
                  "test_network.py::test_the_resolver_configuration_stays_closed_when_the_network_is",
                  "test_mac.py::test_dnssd_cannot_look_up_names_with_the_network_off"],
        "control": [TUNNEL],
        "gap": "no test starts a real resolver daemon or D-Bus service and asks it to resolve; the "
               "socket paths and families that reach them are refused, which is what is tested",
    },
    {
        "says": "Unix datagram sockets, which can name any socket file in `sendmsg`",
        "tests": ["test_datagram.py::test_only_stream_and_seqpacket_unix_sockets_are_made",
                  "test_datagram.py::test_hlyn_on_refuses_to_seal_while_a_datagram_socket_is_open",
                  "test_guard.py::test_row_23_a_unix_datagram_goes_by_connect_never_by_a_path_in_sendto"],
        "control": ["test_datagram.py::test_an_open_network_leaves_datagram_sockets_alone"],
        "gap": "REMAINING #58: the Linux 7.1+ path check has not run on a 7.1 kernel",
    },
    {
        "says": "Reaching a container runtime's socket",
        "tests": ["test_guard.py::test_row_22_unix_sockets_need_a_write_grant_"
                  "and_the_refused_list_always_wins",
                  "test_hostmode.py::test_the_gates_refusals_reach_the_log_from_every_entry_point",
                  "test_guard.py::test_a_hard_link_to_a_refused_socket_is_refused_by_what_it_is"],
        "control": ["test_seccomp.py::test_unix_sockets_survive_a_closed_network"],
        "gap": "REMAINING #60: one file each; a socket inside a write-granted folder on Linux 7.1+ is "
               "warned about, not blocked",
    },
    {
        "says": "Connections opened before the seal: the sealed child closes them",
        "tests": ["test_escape.py::test_sealing_with_a_network_socket_already_open_is_refused",
                  "test_jail.py::test_spawn_closes_an_inherited_connection_under_ports",
                  "test_fds.py::test_run_closes_a_connected_unix_socket",
                  "test_fds.py::test_run_closes_a_descriptor_the_launcher_left_open"],
        "control": ["test_escape.py::test_a_socket_open_is_fine_when_the_network_is_not_closed",
                    "test_fds.py::test_run_keep_fd_passes_the_descriptor_on_purpose"],
    },
    {
        "says": "Tricks with how names and addresses are written",
        "tests": ["test_hosts.py::test_case_and_one_trailing_dot_match_the_same_rule",
                  "test_hosts.py::test_a_loose_ipv4_spelling_from_a_client_matches_nothing",
                  "test_hosts.py::test_a_listed_address_matches_in_any_ipv6_spelling",
                  "test_proxy.py::test_row_9_a_loose_ipv4_spelling_is_refused",
                  "test_proxy.py::test_row_9_a_wrapped_address_not_listed_is_refused",
                  "test_proxy.py::test_row_9_zone_ids_are_refused"],
        "control": [TUNNEL,
                    "test_proxy.py::test_row_9_a_wrapped_address_is_treated_as_the_address_it_embeds"],
    },
    {
        "says": "A mismatch between the CONNECT target and the TLS SNI",
        "tests": ["test_proxy.py::test_row_12_a_different_or_missing_tls_name_closes_the_tunnel",
                  "test_proxy.py::test_row_12_an_address_target_with_a_tls_name_is_refused_and_without_one_passes"],
        "control": ["test_proxy.py::test_row_12_the_same_name_in_tls_passes_through_untouched"],
    },
    {
        "says": "Using another environment's proxy, killing or tracing hlyn's own helpers",
        "tests": ["test_hostmode.py::test_row_16_the_agent_cannot_touch_the_helpers_or_another_runs_proxy",
                  "test_hostmode.py::test_row_19_the_agent_holds_no_notification_descriptor",
                  "test_seccomp.py::test_ptrace_is_shut"],
        "control": [HOSTS],
    },
    {
        "says": "changing the mode, owner, times or extended attributes of a file outside the write grants",
        "tests": ["test_metadata.py::test_changes_outside_the_grants_are_refused_and_change_nothing",
                  "test_metadata.py::test_a_link_inside_a_grant_does_not_reach_a_file_outside_it",
                  "test_metadata.py::test_a_descriptor_to_a_file_that_was_removed_is_refused",
                  "test_metadata.py::test_the_report_names_the_folder_to_grant",
                  "test_metadata.py::test_file_attribute_ioctls_follow_the_same_rule_as_chmod",
                  "test_metadata.py::test_ioctls_that_change_a_file_for_good_are_refused_while_writes_are_limited",
                  "test_metadata.py::test_a_grant_replaced_after_it_was_checked_is_not_honoured_by_the_gate"],
        "control": ["test_metadata.py::test_the_same_changes_inside_a_grant_work_and_take_effect",
                    "test_metadata.py::test_an_attribute_inside_a_grant_is_set_and_removed",
                    "test_metadata.py::test_with_writes_open_nothing_is_trapped_and_the_call_just_runs"],
        "gap": "REMAINING #66: not checked where no gate can start (inside another seccomp listener, "
               "libseccomp before 2.5); a file reached by a hard link inside a grant is changed through it",
    },
    {
        "says": "On macOS, system services that resolve names or fetch URLs",
        "tests": ["test_mac_hosts.py::test_row_25_trustd_and_dnssd_are_refused_and_libinfo_works",
                  "test_mac.py::test_dnssd_cannot_look_up_names_with_the_network_off",
                  "test_mac_hosts.py::test_row_7_no_name_resolves_but_localhost_and_udp_is_refused"],
        "control": ["test_mac_hosts.py::test_port_mode_allows_the_measured_services_"
                    "and_the_two_that_reach_the_network"],
    },
]
