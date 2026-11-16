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
