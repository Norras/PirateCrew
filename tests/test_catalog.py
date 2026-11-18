from catalog import Technique, load_catalog, techniques_for
from catalog.loader import _technique_from_dict


def test_star_service_applies_to_every_service():
    # "*" = cross-cutting technique (see catalog/operator.example.yaml): it must
    # be offered for every service, in addition to the service's own techniques.
    star = _technique_from_dict({"id": "op.any", "name": "x", "service": "*",
                                 "command_template": "tool {target}", "provided_by": "operator"})
    ftp = _technique_from_dict({"id": "op.ftp", "name": "y", "service": "ftp",
                                "command_template": "tool {target}", "provided_by": "operator"})
    assert [t.id for t in techniques_for([star, ftp], "ftp")] == ["op.any", "op.ftp"]
    assert [t.id for t in techniques_for([star, ftp], "smb")] == ["op.any"]


def test_recon_builtin_is_not_planned_per_service():
    # nmap.quick / tcp.check are done by the recon phase: making them "*" would
    # re-run them on every discovered service.
    assert not [t for t in techniques_for(load_catalog(), "http") if t.domain == "recon"
                and t.id in ("nmap.quick", "tcp.check")]


def test_builtin_loads_as_techniques():
    cat = load_catalog()  # the project's default directories
    assert cat and all(isinstance(t, Technique) for t in cat)
    smb = techniques_for(cat, "smb")
    assert any(t.id == "smb.enum_shares" and t.provided_by == "builtin" for t in smb)


def test_requires_parsed_as_set():
    cat = load_catalog()
    t = next(t for t in cat if t.id == "smb.enum_shares")
    assert isinstance(t.requires, set)


def test_missing_operator_dir_is_ok(tmp_path):
    cat = load_catalog(builtin_dir="catalog/builtin", operator_dir=str(tmp_path / "absent"))
    assert cat  # builtin only, no crash


def test_technique_reads_opens_session_flag():
    from catalog.loader import _technique_from_dict
    t = _technique_from_dict({"id": "x", "service": "smb", "opens_session": True})
    assert t.opens_session is True
    assert _technique_from_dict({"id": "y", "service": "smb"}).opens_session is False
