"""Périmètre réseau (offense.netns) — tests unitaires.

Aucun de ces tests ne lance `ip`, `nft` ou `sudo` : fonctions pures, ou `run`
/ `write` injectés. La preuve par le noyau est dans test_netns_integration.py.
"""
import ipaddress

import pytest

from scope import Scope
from offense import netns


# --------------------------------------------------------------------------- #
# Task 1 : génération pure
# --------------------------------------------------------------------------- #
def test_scope_v4_collapses_and_drops_v6():
    s = Scope.from_lines(["10.0.0.0/25", "10.0.0.128/25", "10.10.10.5", "fd00::/8"])
    assert [str(n) for n in netns.scope_v4(s)] == ["10.0.0.0/24", "10.10.10.5/32"]


def test_ruleset_is_atomic_and_scoped():
    r = netns.nft_ruleset([ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("10.10.10.5/32")])
    assert r.startswith("table inet piratecrew {}\ndelete table inet piratecrew\n")
    assert "elements = { 10.0.0.0/24, 10.10.10.5 }" in r
    assert 'iifname "pc-host" ip daddr @scope4 accept' in r
    assert 'iifname "pc-host" counter drop' in r
    assert r.index("@scope4 accept") < r.index('iifname "pc-host" counter drop')
    assert "hook input" in r and "hook forward" in r and "masquerade" in r


def test_ruleset_refuses_empty_and_overlap():
    with pytest.raises(netns.NetnsError):
        netns.nft_ruleset([])
    with pytest.raises(netns.NetnsError):
        netns.nft_ruleset([ipaddress.ip_network("10.200.0.0/16")])   # chevauche LINK_NET


def test_setup_orders_and_disables_v6():
    cmds = netns.setup_commands()
    assert cmds[0] == ["ip", "netns", "add", "pc-offense"]
    assert ["ip", "netns", "exec", "pc-offense", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"] in cmds
    assert ["ip", "netns", "exec", "pc-offense", "ip", "route", "add", "default", "via", "10.200.77.1"] in cmds
    assert cmds[-1] == ["sysctl", "-w", "net.ipv4.ip_forward=1"]


def test_teardown():
    assert netns.teardown_commands() == [["ip", "netns", "del", "pc-offense"],
                                         ["nft", "delete", "table", "inet", "piratecrew"]]
