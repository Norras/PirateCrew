from scope import Scope, set_active_scope
import offense.guardrails as g

def test_shell_metachar_detected():
    assert g.shell_metachar("evil-winrm -i 127.0.0.1 | nc x 4444")  # '|'
    assert g.shell_metachar("a; b") and g.shell_metachar("$(x)") and g.shell_metachar("a > b")
    assert g.shell_metachar("evil-winrm -i 127.0.0.1 -u admin") is None

def test_destructive_denylist():
    for bad in ["rm -rf /", "mkfs.ext4 /dev/sda", "dd of=/dev/sda", "shutdown now",
                "reboot", "format c:", "del /s x", "DROP TABLE users", "TRUNCATE t"]:
        assert g.destructive_match(bad), bad
    assert g.destructive_match("crackmapexec smb 127.0.0.1 -u a -p b") is None

def test_scope_violations_flags_out_of_scope_ipv4():
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.scope_violations("evil-winrm -i 127.0.0.1") == []
    assert g.scope_violations("x 127.0.0.1 10.0.0.9") == ["10.0.0.9"]

def test_tokenize_rejects_shell_meta_and_splits_clean():
    import pytest
    assert g.tokenize_argv("evil-winrm -i 127.0.0.1 -u admin") == ["evil-winrm","-i","127.0.0.1","-u","admin"]
    with pytest.raises(g.GuardrailError):
        g.tokenize_argv("a | b")

def test_evaluate_order_and_pass():
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.evaluate("crackmapexec smb 127.0.0.1 -u a -H h") is None
    assert g.evaluate("a | b")[0] == "blocked_shell_meta"
    assert g.evaluate("rm -rf /")[0] == "blocked_destructive"
    assert g.evaluate("nmap 10.0.0.9")[0] == "blocked_out_of_scope"

def test_destructive_reordered_flags():
    for bad in ["rm --no-preserve-root -rf /", "rm -rf /", "rm -fr /", "rm -r /tmp/x",
                "format /q c:", "format /fs:ntfs c:", "format c:",
                "del /f /s /q C:\\", "del /s x"]:
        assert g.destructive_match(bad), bad
    for ok in ["crackmapexec smb 127.0.0.1 -u a -p b",
               "evil-winrm -i 127.0.0.1 -u admin -H h", "rm file", "confirm -r x"]:
        assert g.destructive_match(ok) is None, ok

def test_scope_violations_malformed_ip_no_dns(monkeypatch):
    import scope
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    def boom(*a, **k):
        raise AssertionError("DNS appelé")
    monkeypatch.setattr(scope.socket, "gethostbyname", boom)
    assert g.scope_violations("nmap 256.0.0.1") == ["256.0.0.1"]

def test_evaluate_precedence_combined():
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.evaluate("rm -rf / | x")[0] == "blocked_shell_meta"
    assert g.evaluate("rm -rf 10.0.0.9")[0] == "blocked_destructive"

def test_tokenize_unbalanced_quote():
    import pytest
    with pytest.raises(g.GuardrailError):
        g.tokenize_argv('foo "bar')


_BLOCK_DEV = ["cp /dev/zero /dev/sda", "shred -n 3 /dev/sda", "wipefs -a /dev/sda",
              "mkswap /dev/sda", "sgdisk --zap-all /dev/sda", "parted /dev/sda mklabel gpt",
              "badblocks -w /dev/sda"]


def test_block_device_wipes_denied():
    for bad in _BLOCK_DEV:
        assert g.destructive_match(bad), bad
        assert g.evaluate(bad)[0] == "blocked_destructive", bad


def test_dev_null_not_matched_by_device_pattern():
    assert g.destructive_match("cat /dev/null") is None
    assert g.destructive_match("cat /dev/urandom") is None
    assert g.destructive_match("badblocks /dev/null") is None


def test_scope_violations_flags_ipv6_literal():
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.scope_violations("evil-winrm -i dead:beef::1") == ["dead:beef::1"]
    assert g.scope_violations("evil-winrm -i [dead:beef::1]") == ["dead:beef::1"]
    assert g.scope_violations("x 127.0.0.1") == []


def test_destructive_binaries_without_device():
    for bad in ["shred secret.txt", "wipefs x", "mkswap x", "sgdisk x", "parted x", "badblocks -w x"]:
        assert g.destructive_match(bad), bad
    assert g.destructive_match("badblocks x") is None


def _fake_dns(monkeypatch, mapping):
    """Résolveur DNS déterministe et hors-ligne pour les tests de périmètre."""
    import scope
    def fake(name):
        if name in mapping:
            return mapping[name]
        raise OSError("NXDOMAIN")
    monkeypatch.setattr(scope.socket, "gethostbyname", fake)


def test_scope_violations_resolves_out_of_scope_hostname(monkeypatch):
    # Un nom d'hôte hors périmètre est RÉSOLU puis contrôlé (fix du fail-open critique).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.example.com": "203.0.113.9"})
    assert g.scope_violations("nmap -sV evil.example.com") == ["evil.example.com"]


def test_scope_violations_allows_in_scope_hostname(monkeypatch):
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"box.lab": "10.0.0.7"})
    assert g.scope_violations("nmap -sV box.lab") == []


def test_scope_violations_flags_decimal_ip_evasion():
    # 167772169 == 10.0.0.9 (hors périmètre), notation décimale que _IPV4 ne voit pas ; sans DNS.
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.scope_violations("nmap 167772169") == ["167772169"]


def test_scope_violations_allows_numeric_port_not_treated_as_ip():
    # Un port (<= 65535) après -p ne doit PAS être pris pour une IP décimale.
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.scope_violations("nmap -p 445 127.0.0.1") == []


def test_scope_violations_flags_proxy_host_in_url(monkeypatch):
    # {target} rendu in-scope, mais un SECOND hôte littéral (proxy) hors périmètre est capté.
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    _fake_dns(monkeypatch, {"evil.example.com": "203.0.113.9"})
    out = g.scope_violations("curl http://127.0.0.1/ -x http://evil.example.com:8080")
    assert out == ["evil.example.com"]


def test_scope_violations_ignores_output_filename(monkeypatch):
    # Un nom de fichier (extension connue) ressemble à un FQDN mais ne doit PAS être résolu.
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    def boom(name):
        raise AssertionError(f"DNS appelé pour un nom de fichier : {name}")
    import scope
    monkeypatch.setattr(scope.socket, "gethostbyname", boom)
    assert g.scope_violations("nmap -oN scan.txt 127.0.0.1") == []


def test_host_literals_pure_extraction_no_dns(monkeypatch):
    # host_literals est PUR : extraction + classification, jamais de résolution.
    import scope
    def boom(name):
        raise AssertionError("host_literals ne doit jamais résoudre")
    monkeypatch.setattr(scope.socket, "gethostbyname", boom)
    assert g.host_literals("cme smb {target} -u {user}") == []          # placeholders ignorés
    assert g.host_literals("nmap 10.0.0.5") == ["10.0.0.5"]             # IP littérale
    assert g.host_literals("nmap evil.example.com") == ["evil.example.com"]  # hôte littéral
