from catalog import Technique, load_catalog, techniques_for


def test_builtin_loads_as_techniques():
    cat = load_catalog()  # dossiers par défaut du projet
    assert cat and all(isinstance(t, Technique) for t in cat)
    smb = techniques_for(cat, "smb")
    assert any(t.id == "smb.enum_shares" and t.provided_by == "builtin" for t in smb)


def test_requires_parsed_as_set():
    cat = load_catalog()
    t = next(t for t in cat if t.id == "smb.enum_shares")
    assert isinstance(t.requires, set)


def test_missing_operator_dir_is_ok(tmp_path):
    cat = load_catalog(builtin_dir="catalog/builtin", operator_dir=str(tmp_path / "absent"))
    assert cat  # builtin seuls, pas de crash
