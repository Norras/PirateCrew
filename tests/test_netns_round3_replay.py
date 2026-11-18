"""Rejeu, à travers le namespace, des contournements confirmés au round 3.

La revue adverse du 18/11/2026 (commit e97cec9) a confirmé plusieurs façons de
faire passer un hôte HORS périmètre à travers le contrôle texte
(`offense/guardrails.py`, gelé depuis). Ce module rejoue chacune de ces
commandes avec le vrai outil et mesure deux choses, indépendantes du protocole :

- aucun paquet n'ARRIVE à la cible hors périmètre ;
- le filtre de l'hôte a bien JETÉ au moins un paquet — l'outil a donc
  réellement tenté de joindre cet hôte : le rejeu n'est pas vert « parce que
  l'outil a refusé la commande ».

Ce qui tient ici ne dépend plus de ce que le contrôle texte voit ou rate.

Lancement (Linux, root) :
    sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_netns_round3_replay.py -v
"""
import os
import shlex
import shutil
import tempfile

import pytest

from offense import executor, netns

from netns_bench import IN_SCOPE, MARKS, OUT_OF_SCOPE, host_drops, target_packets
from netns_bench import _active_scope, bench  # noqa: F401 — fixtures du banc d'essai

pytestmark = MARKS

_SSH = "-o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no"

# (identifiant, gabarit). {H} = IP hors périmètre ; {REPORT}/{CORP} = noms qui s'y
# résolvent ; {IN} = cible in-scope ; {WL} = petite liste de mots.
REPLAYS = [
    # 1. Liste blanche de schémas (B3) + slashs anormaux : schémas que curl sait
    #    composer mais que le contrôle texte ne normalise pas.
    ("schemas/imap-un-slash", "curl -s -m 3 imap:/{H}/x"),
    ("schemas/smtp-trois-slashs", "curl -s -m 3 smtp:///{H}/"),
    ("schemas/tftp-trois-slashs", "curl -s -m 3 tftp:///{H}/x"),
    ("schemas/pop3-un-slash", "curl -s -m 3 pop3:/{H}/"),
    ("schemas/tftp-seconde-url", "curl -s -m 3 http://{IN}:8000/ tftp:/{H}/exfil"),
    ("schemas/metadonnees-cloud", "curl -s -m 3 smtp:///169.254.169.254/"),
    # 2. Saut des flags d'identité sur la forme « @ » (e97cec9) : l'hôte derrière
    #    -u/-p est pris pour un identifiant.
    #    (-noninteractive : sans terminal, ffuf se bloque avant d'émettre quoi que ce soit.)
    ("arobase/ffuf-url-userinfo",
     "ffuf -u http://x@{H}:8000/FUZZ -w {WL} -maxtime 3 -timeout 2 -noninteractive"),
    ("arobase/wfuzz-url-userinfo",
     "wfuzz -u http://a@{H}:8000/FUZZ -w {WL} --conn-delay 2 --req-delay 2"),
    ("arobase/sqlmap-url-userinfo",
     "sqlmap -u http://admin@{H}:8000/p.php?id=1 --batch --timeout 2 --retries 0"),
    ("arobase/scp", f"scp {_SSH} -p root@{{H}}:/loot /tmp/pc-it-loot"),
    ("arobase/rsync", f"rsync -p -e 'ssh {_SSH}' root@{{H}}:/s /tmp/pc-it-s"),
    # 3. Valeur de flag attachée : --flag=http://IP/ n'est pas vu comme une URL.
    ("attache/sqlmap-url", "sqlmap --url=http://{H}:8000/ --batch --timeout 2 --retries 0"),
    ("attache/curl-proxy", "curl -s -m 3 --proxy=http://{H}:8080 http://{IN}:8000/"),
    # 4. `.report` classé extension de fichier alors que c'est un vrai TLD.
    #    (--system-dns : nmap ≥ 7.96 résout lui-même les noms, sans lire /etc/hosts ;
    #    DNS étant fermé dans le namespace, le nom ne se résoudrait même pas sinon.)
    ("tld/report", "nmap -sT -Pn -p 8000 --max-retries 0 --host-timeout 5s --system-dns {REPORT}"),
    # 5. Chemin operator : placeholder autre que {target} rendu en position d'hôte
    #    (ici la commande telle que rendue, {domain} -> nom hors périmètre).
    ("placeholder/smbclient", "smbclient -L //{CORP} -N"),
    ("placeholder/curl", "curl -s -m 3 http://{CORP}:8000/"),
    ("placeholder/ssh", f"ssh {_SSH} admin@{{CORP}} true"),
]


@pytest.fixture(scope="module")
def wordlist():
    path = tempfile.mkdtemp(prefix="pc-it-wl-", dir="/tmp")
    os.chmod(path, 0o755)
    words = os.path.join(path, "mots.txt")
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
    # Aucun contrôle texte ici : la commande entre telle quelle dans le namespace.
    argv = shlex.split(_render(template, wordlist))
    received, dropped = target_packets(OUT_OF_SCOPE), host_drops()
    out = netns.run_isolated(argv, timeout=12)
    assert target_packets(OUT_OF_SCOPE) == received, "un paquet a atteint la cible hors périmètre"
    assert host_drops() > dropped, (
        f"l'outil n'a rien émis vers l'hôte hors périmètre : rejeu sans valeur — sortie : {out[-400:]!r}")


@pytest.mark.parametrize("template", _PARAMS)
def test_product_path_never_reaches_out_of_scope(template, wordlist, request):
    # Le chemin réel du produit (garde-fous texte PUIS namespace). Que le texte
    # bloque ou laisse passer, la cible hors périmètre ne reçoit rien.
    rendered = _render(template, wordlist)
    received = target_packets(OUT_OF_SCOPE)
    status, _out = executor.execute_command(rendered, timeout=12)
    print(f"REPLAY_STATUS {request.node.callspec.id} {status}")
    assert status != "blocked_no_netns", "namespace absent : le rejeu ne prouve rien"
    assert target_packets(OUT_OF_SCOPE) == received, "un paquet a atteint la cible hors périmètre"


def test_probe_counts_what_reaches_the_target():
    # Témoin de la sonde elle-même : un paquet autorisé est bien compté à
    # l'arrivée. Sans cela, « 0 paquet reçu » ne prouverait rien.
    received = target_packets(IN_SCOPE)
    netns.run_isolated(["curl", "-s", "-m", "3", f"http://{IN_SCOPE}:8000/"])
    assert target_packets(IN_SCOPE) > received
