"""Replay, through the namespace, of the bypasses confirmed in round 3.

The adversarial review of 2026-11-18 (commit e97cec9) confirmed several ways to
get an OUT-of-scope host past the text check
(`offense/guardrails.py`, frozen since). This module replays each of those
commands with the real tool and measures two protocol-independent things:

- no packet ARRIVES at the out-of-scope target;
- the host filter did DROP at least one packet — the tool therefore really
  tried to reach that host: the replay is not green "because the tool
  refused the command".

What holds here no longer depends on what the text check sees or misses.

Run (Linux, root):
    sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_netns_round3_replay.py -v
"""
import os
import shlex
import shutil
import tempfile

import pytest

from offense import executor, netns

from netns_bench import IN_SCOPE, MARKS, OUT_OF_SCOPE, host_drops, target_packets
from netns_bench import _active_scope, bench  # noqa: F401 — test bench fixtures

pytestmark = MARKS

_SSH = "-o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no"

# (identifier, template). {H} = out-of-scope IP; {REPORT}/{CORP} = names that resolve
# to it; {IN} = in-scope target; {WL} = small word list.
REPLAYS = [
    # 1. Scheme whitelist (B3) + abnormal slashes: schemes curl can
    #    compose but that the text check does not normalize.
    ("schemes/imap-one-slash", "curl -s -m 3 imap:/{H}/x"),
    ("schemes/smtp-three-slashes", "curl -s -m 3 smtp:///{H}/"),
    ("schemes/tftp-three-slashes", "curl -s -m 3 tftp:///{H}/x"),
    ("schemes/pop3-one-slash", "curl -s -m 3 pop3:/{H}/"),
    ("schemes/tftp-second-url", "curl -s -m 3 http://{IN}:8000/ tftp:/{H}/exfil"),
    ("schemes/cloud-metadata", "curl -s -m 3 smtp:///169.254.169.254/"),
    # 2. Identity flags skipped on the "@" form (e97cec9): the host behind
    #    -u/-p is taken for an identifier.
    #    (-noninteractive: without a terminal, ffuf hangs before emitting anything.)
    ("at-sign/ffuf-url-userinfo",
     "ffuf -u http://x@{H}:8000/FUZZ -w {WL} -maxtime 3 -timeout 2 -noninteractive"),
    ("at-sign/wfuzz-url-userinfo",
     "wfuzz -u http://a@{H}:8000/FUZZ -w {WL} --conn-delay 2 --req-delay 2"),
    ("at-sign/sqlmap-url-userinfo",
     "sqlmap -u http://admin@{H}:8000/p.php?id=1 --batch --timeout 2 --retries 0"),
    ("at-sign/scp", f"scp {_SSH} -p root@{{H}}:/loot /tmp/pc-it-loot"),
    ("at-sign/rsync", f"rsync -p -e 'ssh {_SSH}' root@{{H}}:/s /tmp/pc-it-s"),
    # 3. Attached flag value: --flag=http://IP/ is not seen as a URL.
    ("attached/sqlmap-url", "sqlmap --url=http://{H}:8000/ --batch --timeout 2 --retries 0"),
    ("attached/curl-proxy", "curl -s -m 3 --proxy=http://{H}:8080 http://{IN}:8000/"),
    # 4. `.report` classified as a file extension although it is a real TLD.
    #    (--system-dns: nmap >= 7.96 resolves names itself, without reading /etc/hosts;
    #    DNS being closed in the namespace, the name would not even resolve otherwise.)
    ("tld/report", "nmap -sT -Pn -p 8000 --max-retries 0 --host-timeout 5s --system-dns {REPORT}"),
    # 5. Operator path: a placeholder other than {target} rendered in host position
    #    (here the command as rendered, {domain} -> out-of-scope name).
    ("placeholder/smbclient", "smbclient -L //{CORP} -N"),
    ("placeholder/curl", "curl -s -m 3 http://{CORP}:8000/"),
    ("placeholder/ssh", f"ssh {_SSH} admin@{{CORP}} true"),
]


@pytest.fixture(scope="module")
def wordlist():
    path = tempfile.mkdtemp(prefix="pc-it-wl-", dir="/tmp")
    os.chmod(path, 0o755)
    words = os.path.join(path, "words.txt")
    with open(words, "w", encoding="utf-8") as fh:
        fh.write("admin\nlogin\n")
    os.chmod(words, 0o644)
    try:
        yield words
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _render(template: str, wordlist: str) -> str:
    return template.format(H=OUT_OF_SCOPE, IN=IN_SCOPE, WL=wordlist,
                           REPORT="pc-it-oos.report", CORP="pc-it-oos.corp")


_PARAMS = [pytest.param(template, id=name) for name, template in REPLAYS]


@pytest.mark.parametrize("template", _PARAMS)
def test_kernel_drops_what_the_text_layer_missed(template, wordlist):
    # No text check here: the command enters the namespace as-is.
    argv = shlex.split(_render(template, wordlist))
    received, dropped = target_packets(OUT_OF_SCOPE), host_drops()
    out = netns.run_isolated(argv, timeout=12)
    assert target_packets(OUT_OF_SCOPE) == received, "a packet reached the out-of-scope target"
    assert host_drops() > dropped, (
        f"the tool emitted nothing toward the out-of-scope host: worthless replay — output: {out[-400:]!r}")


@pytest.mark.parametrize("template", _PARAMS)
def test_product_path_never_reaches_out_of_scope(template, wordlist, request):
    # The product's real path (text guardrails THEN namespace). Whether the text
    # blocks or lets it through, the out-of-scope target receives nothing.
    rendered = _render(template, wordlist)
    received = target_packets(OUT_OF_SCOPE)
    status, _out = executor.execute_command(rendered, timeout=12)
    print(f"REPLAY_STATUS {request.node.callspec.id} {status}")
    assert status != "blocked_no_netns", "namespace missing: the replay proves nothing"
    assert target_packets(OUT_OF_SCOPE) == received, "a packet reached the out-of-scope target"


def test_probe_counts_what_reaches_the_target():
    # Control for the probe itself: an allowed packet is indeed counted on
    # arrival. Without it, "0 packets received" would prove nothing.
    received = target_packets(IN_SCOPE)
    netns.run_isolated(["curl", "-s", "-m", "3", f"http://{IN_SCOPE}:8000/"])
    assert target_packets(IN_SCOPE) > received
