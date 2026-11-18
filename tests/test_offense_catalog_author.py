import json

import pytest

import offense.catalog_author as author

_GOOD = json.dumps({"id":"llm.smb.cme","name":"CME","domain":"ad","service":"smb",
    "requires":["credential"],"tool":"crackmapexec",
    "command_template":"crackmapexec smb {target} -u {user} -H {hash}",
    "success_signal":"Pwn3d","opens_session":True})
_BAD = json.dumps({"id":"llm.bad","service":"smb","tool":"sh",
    "command_template":"rm -rf / ; curl {target}"})

def test_author_returns_tagged_technique():
    t = author.author_technique("smb", "contexte", llm_invoke=lambda p: _GOOD)
    assert t is not None and t.provided_by == "llm" and t.service == "smb"
    assert t.opens_session is True and "credential" in t.requires

def test_author_rejects_destructive_or_shell_template():
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: _BAD) is None

def test_author_rejects_unparseable_output():
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: "désolé je ne peux pas") is None

def test_persist_roundtrips_through_loader(tmp_path):
    from state import mission_io
    from catalog.loader import load_catalog
    import pathlib
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: _GOOD)
    p = author.persist_llm_technique(t, "m1", root=tmp_path)
    assert pathlib.Path(p).exists()
    cat = load_catalog(builtin_dir=str(tmp_path / "m1"), operator_dir="catalog/__none__")
    assert any(x.id == "llm.smb.cme" and x.provided_by == "llm" for x in cat)


def test_parse_technique_non_str_returns_none():
    assert author.parse_technique(None) is None


def test_author_forces_provided_by_and_service():
    raw = json.dumps({"id": "llm.x", "service": "ftp", "provided_by": "builtin",
                      "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target}"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    assert t is not None and t.provided_by == "llm" and t.service == "smb"


def test_build_author_prompt_encadre_le_contexte_et_consigne_les_echecs():
    p = author.build_author_prompt("smb", "ÉTAT-RÉEL-XYZ")
    assert "ÉTAT-RÉEL-XYZ" in p            # le contexte réel est injecté
    assert "déjà" in p.lower()              # consigne : ne pas reproposer ce qui a été tenté
    assert "UN objet JSON" in p             # format de sortie conservé


def test_build_author_prompt_annonce_tous_les_champs_remplissables():
    # Le rendu sait remplir {port} et {password} : l'auteur doit le savoir, sinon il
    # met un mot de passe dans {hash} et ne peut pas viser un port non standard.
    p = author.build_author_prompt("smb", "ctx")
    for field in ("{target}", "{port}", "{user}", "{password}", "{hash}", "{domain}", "{share}"):
        assert field in p, field


class _FakeStore:
    def __init__(self):
        self.calls = []
    def add_texts(self, texts, metadatas=None, ids=None):
        self.calls.append((list(texts), metadatas, ids))


def test_promote_techniques_to_rag_add_texts_et_ids_stables():
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: _GOOD)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "mission-1", store=s) == 1
    texts, metas, ids = s.calls[0]
    assert "crackmapexec smb {target}" in texts[0]        # gabarit décrit, placeholders intacts
    assert metas[0]["source"] == "llm_authored" and metas[0]["service"] == "smb"
    assert metas[0]["technique_id"] == "llm.smb.cme"
    # idempotence inter-missions : même contenu -> même id (upsert, pas de doublon)
    author.promote_techniques_to_rag([t], "mission-2", store=s)
    assert s.calls[1][2] == ids


_BASE = {"id": "llm.probe", "name": "n", "domain": "web", "requires": [], "tool": "echo",
         "command_template": "echo {target}", "success_signal": "ok", "opens_session": False}


def test_author_accepts_the_well_typed_baseline():
    assert author.author_technique("http", "ctx", llm_invoke=lambda p: json.dumps(_BASE)) is not None


@pytest.mark.parametrize("bad", [
    {"command_template": ["echo", "{target}"]},   # liste : faisait lever author_technique
    {"id": {"a": 1}},                              # non hachable : empoisonnait le catalogue de mission
    {"id": ["a"]},
    {"id": ""},
    {"id": "../../ailleurs"},
    {"tool": ["echo"]},
    {"name": {"x": 1}},
    {"success_signal": ["ok"]},
    {"requires": [1, 2]},
    {"requires": {"session": True}},
    {"opens_session": "oui"},
])
def test_author_rejects_ill_typed_fields(bad):
    # Une proposition mal typée est REJETÉE (None) — jamais d'exception qui
    # interromprait la mission, jamais d'entrée inutilisable dans le catalogue.
    raw = json.dumps({**_BASE, **bad})
    assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None


def test_author_survives_a_failing_llm_call():
    def down(_prompt):
        raise ConnectionError("API indisponible")
    assert author.author_technique("http", "ctx", llm_invoke=down) is None


def _tech(**over):
    from catalog.loader import Technique
    base = dict(id="llm.t", name="x", domain="recon", service="smb", requires=set(), tool="nmap",
                command_template="nmap -sV -p 445 {target}", success_signal="ok", provided_by="llm")
    return Technique(**{**base, **over})


def test_promote_isolates_a_malformed_technique():
    # Une technique illisible est écartée seule : elle ne fait plus lever, ni
    # perdre tout le lot.
    s = _FakeStore()
    assert author.promote_techniques_to_rag([_tech(command_template=None), _tech()], "m", store=s) == 1
    assert len(s.calls[0][0]) == 1


def test_promote_dedupes_identical_templates_in_one_batch():
    s = _FakeStore()
    assert author.promote_techniques_to_rag([_tech(id="llm.a"), _tech(id="llm.b")], "m", store=s) == 1
    assert s.calls[0][2] == list(dict.fromkeys(s.calls[0][2])) and len(s.calls[0][2]) == 1


def test_rag_candidates_expose_exactly_what_would_be_stored():
    cands = author.rag_candidates([_tech(), _tech(command_template="nmap -p 445 192.0.2.10")])
    assert len(cands) == 1                                   # l'IP littérale écarte la seconde
    assert cands[0]["text"].startswith("Technique « x » pour le service smb")
    assert cands[0]["id"].startswith("llm:") and cands[0]["metadata"]["tool"] == "nmap"
    s = _FakeStore()
    assert author.store_candidates(cands, store=s) == 1 and s.calls[0][0] == [cands[0]["text"]]


def test_promote_techniques_to_rag_vide_est_noop():
    class Boom:
        def add_texts(self, *a, **k):
            raise AssertionError("ne doit pas écrire pour une liste vide")
    assert author.promote_techniques_to_rag([], "m", store=Boom()) == 0


def test_promote_skips_template_with_ip_literal():
    # IP littérale dans le gabarit = spécifique à la mission -> jamais dans le RAG partagé.
    # Technique construite directement : author_technique la rejetterait désormais en amont.
    from catalog.loader import Technique
    t = Technique(id="llm.smb.x", name="x", domain="ad", service="smb", requires=set(),
                  tool="crackmapexec", command_template="crackmapexec smb 10.0.0.5 -u admin",
                  success_signal="Pwn3d", provided_by="llm")
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_skips_template_with_known_secret():
    raw = json.dumps({"id": "llm.smb.y", "name": "y", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target} -u admin -p Summer2024!",
                      "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", forbidden=["Summer2024!"], store=s) == 0
    assert s.calls == []


def test_promote_metadata_omits_target_mission_id():
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: _GOOD)
    s = _FakeStore()
    author.promote_techniques_to_rag([t], "10.0.0.5-20261116-120000", store=s)
    meta = s.calls[0][1][0]
    assert "mission_id" not in meta            # champ retiré
    assert "10.0.0.5" not in str(meta)         # aucune IP cible en metadata


def test_promote_skips_unknown_nt_hash_literal():
    # hash NT inconnu (non reconcilié) inliné par le LLM -> rejeté (entropie + flag)
    raw = json.dumps({"id": "llm.smb.h", "name": "pth", "service": "smb", "tool": "impacket-wmiexec",
                      "command_template": "impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 {user}@{target}",
                      "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0   # forbidden vide
    assert s.calls == []


def test_promote_skips_literal_credential_flag_value():
    # secret inconnu, basse entropie, en position de flag credential -> contrôle structurel
    raw = json.dumps({"id": "llm.smb.p", "name": "brute", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target} -u {user} -p hunter2", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_scans_all_persisted_fields_not_subset():
    # IP dans `tool` (champ persisté hors des 4 scannés initialement) -> rejeté
    raw = json.dumps({"id": "llm.smb.t", "name": "x", "service": "smb", "tool": "scanner-10.0.0.5",
                      "command_template": "run {target}", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_skips_compressed_ipv6_literal():
    # IPv6 littérale dans le gabarit -> jamais promue (construite directement : rejetée à l'authoring).
    from catalog.loader import Technique
    t = Technique(id="llm.x.6", name="x", domain="ad", service="smb", requires=set(),
                  tool="nmap", command_template="nmap -6 fe80::1", success_signal="ok",
                  provided_by="llm")
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_allows_timestamp_in_success_signal():
    # régression du faux positif IPv6-ish : HH:MM:SS ne doit PAS bloquer la promotion
    raw = json.dumps({"id": "llm.ok.ts", "name": "x", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb {target} -u {user}", "success_signal": "session at 10:30:00"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 1


def test_promote_allows_literal_numeric_port():
    # un port littéral après -p n'est PAS un credential -> promu (fin du faux positif)
    raw = json.dumps({"id": "llm.np", "name": "scan", "service": "smb", "tool": "nmap",
                      "command_template": "nmap -p 445 {target}", "success_signal": "open"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 1


def test_promote_allows_header_flag():
    # -H = en-tête HTTP (curl), pas un hash -> promu ; un vrai hash reste capté par l'entropie
    raw = json.dumps({"id": "llm.hd", "name": "get", "service": "http", "tool": "curl",
                      "command_template": 'curl -H "Content-Type: application/json" {target}', "success_signal": "200"})
    t = author.author_technique("http", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 1


def test_promote_skips_short_base64_key_in_noncommand_field():
    # clé base64 ~22 car. dans success_signal (hors flag/commande) -> captée par entropie (seuil 20)
    raw = json.dumps({"id": "llm.k", "name": "x", "service": "smb", "tool": "run",
                      "command_template": "run {target}", "success_signal": "key ABCDEFGHIJKLMNOPQRSTUV"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0
    assert s.calls == []


def test_promote_skips_short_H_hash_via_entropy():
    # garde : -H retiré du contrôle structurel, mais un vrai hash reste rejeté par l'entropie
    raw = json.dumps({"id": "llm.hh", "name": "pth", "service": "smb", "tool": "cme",
                      "command_template": "cme smb {target} -H 31d6cfe0d16ae931b73c59d7e0c089c0", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    assert author.promote_techniques_to_rag([t], "m1", store=s) == 0


# --- Authoring : le gabarit DOIT cibler {target} et ne porter aucun hôte/IP littéral --- #
def test_author_rejects_template_without_target():
    # Pas de {target} -> la cible n'est pas garantie in-scope -> rejet.
    raw = json.dumps({"id": "llm.x", "service": "smb", "tool": "nmap",
                      "command_template": "nmap -sV -p 445"})
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is None


def test_author_rejects_literal_ip():
    raw = json.dumps({"id": "llm.x", "service": "smb", "tool": "cme",
                      "command_template": "cme smb 10.0.0.5 -u {user}"})
    assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is None


def test_author_rejects_literal_host_even_with_target():
    # {target} présent mais un SECOND hôte littéral (proxy) -> rejet (évasion de périmètre).
    raw = json.dumps({"id": "llm.x", "service": "http", "tool": "curl",
                      "command_template": "curl http://{target}/ -x http://evil.example.com:8080"})
    assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None


def test_author_accepts_templated_target():
    raw = json.dumps({"id": "llm.ok", "service": "smb", "tool": "cme",
                      "command_template": "cme smb {target} -u {user}", "success_signal": "Pwn3d"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    assert t is not None and "{target}" in t.command_template


def test_author_accepts_rate_flag():
    # un grand entier (débit) n'est pas un hôte littéral -> scan rapide autorisé (fin du FP débit).
    raw = json.dumps({"id": "llm.ms", "service": "smb", "tool": "masscan",
                      "command_template": "masscan {target} --rate 100000 -p445", "success_signal": "open"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    assert t is not None


def test_author_rejects_placeholder_glued_to_literal_host():
    # Évasion de périmètre (re-review 17/11) : {target} collé à un domaine attaquant.
    # host_literals() seul ne le voit pas (les accolades cassent la classification), mais
    # au rendu l'hôte '10.0.0.5.evil.com' NAÎT et échappe aux deux couches. Rejet par
    # substitution sentinelle du gabarit à l'authoring (chemin LLM non fiable).
    for tpl in ["curl http://{target}.evil.com/",
                "nmap -sV {target}.evil.example.com",
                "curl http://{target}@localhost/"]:
        raw = json.dumps({"id": "llm.x", "service": "http", "tool": "curl",
                          "command_template": tpl})
        assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None, tpl


def test_author_accepts_legit_placeholder_templates():
    # Non-régression : les gabarits normaux (placeholder en position d'hôte, port, chemin,
    # fichier de sortie) ne déclenchent PAS la détection de collage.
    for tpl in ["crackmapexec smb {target} -u {user} -H {hash}",
                "curl http://{target}:{port}/{path}",
                "smbclient //{target}/{share} -U {user}",
                "nmap -p {port} -oN {output}.txt {target}"]:
        raw = json.dumps({"id": "llm.ok", "service": "smb", "tool": "x",
                          "command_template": tpl, "success_signal": "ok"})
        assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is not None, tpl


def test_author_rejects_non_target_placeholder_in_host_position():
    # Round 2 : seul {target} est sanctionné in-scope. Un AUTRE placeholder en position
    # d'hôte (ou {target} collé à un autre) se matérialise hors périmètre au rendu
    # (corp.local via creds) -> rejet à l'authoring LLM (invariant {target} par position).
    for tpl in ["curl http://{domain}/ {target}",
                "curl -x http://{domain}:{port} {target}",
                "ssh {user}@{domain} {target}",
                "smbclient //{share}/x {target}",
                "curl http://{target}.{domain}/"]:
        raw = json.dumps({"id": "llm.x", "service": "http", "tool": "curl",
                          "command_template": tpl})
        assert author.author_technique("http", "ctx", llm_invoke=lambda p: raw) is None, tpl


def test_author_accepts_capture_and_identity_templates():
    # Régression B2 corrigée : gabarits légitimes de capture/sortie et identités AD
    # (UPN/NetBIOS, domaine en argument -d) ne doivent PLUS être rejetés.
    for tpl in ["tcpdump -w {output}.pcap host {target}",
                "tshark -w {capture}.cap host {target}",
                "nmap {target} -oA {output}.report",
                "nmap {target} -oN {output}.scan",
                "crackmapexec smb {target} -u {user} -d {domain}",
                "crackmapexec smb {target} -u {user}@{domain} -p {password}"]:
        raw = json.dumps({"id": "llm.ok", "service": "smb", "tool": "x",
                          "command_template": tpl, "success_signal": "ok"})
        assert author.author_technique("smb", "ctx", llm_invoke=lambda p: raw) is not None, tpl
