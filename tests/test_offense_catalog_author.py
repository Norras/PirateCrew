import json
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


def test_promote_techniques_to_rag_vide_est_noop():
    class Boom:
        def add_texts(self, *a, **k):
            raise AssertionError("ne doit pas écrire pour une liste vide")
    assert author.promote_techniques_to_rag([], "m", store=Boom()) == 0


def test_promote_skips_template_with_ip_literal():
    raw = json.dumps({"id": "llm.smb.x", "name": "x", "service": "smb", "tool": "crackmapexec",
                      "command_template": "crackmapexec smb 10.0.0.5 -u admin", "success_signal": "Pwn3d"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
    s = _FakeStore()
    # gabarit à IP littérale = spécifique à la mission -> jamais dans le RAG partagé
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
    raw = json.dumps({"id": "llm.x.6", "name": "x", "service": "smb", "tool": "nmap",
                      "command_template": "nmap -6 fe80::1", "success_signal": "ok"})
    t = author.author_technique("smb", "ctx", llm_invoke=lambda p: raw)
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
