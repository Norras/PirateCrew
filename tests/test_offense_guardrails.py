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
        raise AssertionError("DNS called")
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
    """Deterministic, offline DNS resolver for scope tests."""
    import scope
    def fake(name):
        if name in mapping:
            return mapping[name]
        raise OSError("NXDOMAIN")
    monkeypatch.setattr(scope.socket, "gethostbyname", fake)


# --- scope_violations: backstop on the RENDERED command, LITERAL IPs only (no DNS, no FP) ---
def test_scope_violations_rendered_ip_only_out_of_scope():
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.scope_violations("nmap 203.0.113.9") == ["203.0.113.9"]  # dotted IP out of scope
    assert g.scope_violations("nmap 10.0.0.5") == []                   # dotted IP in scope


def test_scope_violations_rendered_ignores_hostname_and_rate(monkeypatch):
    # Ruled-out FPs: a rendered domain (identity arg) and a large integer (rate) are NOT
    # taken for IPs -> no over-blocking, and NO DNS on this backstop.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS forbidden on the IP-only backstop: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_violations("cme smb 10.0.0.1 -u admin -d corp.local") == []
    assert g.scope_violations("masscan 10.0.0.1 --rate 100000") == []


def test_scope_violations_rendered_flags_dotted_octal_ip():
    # 0177.0.0.1 == 127.0.0.1 (dotted octal, accepted by nmap/curl via inet_aton), out of scope.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.scope_violations("nmap -sV 10.0.0.5 0177.0.0.1") == ["0177.0.0.1"]


def test_scope_violations_rendered_ignores_filename():
    # A file name (known extension) is not an IP -> never flagged.
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.scope_violations("nmap -oN scan.txt 127.0.0.1") == []


# --- host_literals: PURE (authoring + template check), never resolves ---
def test_host_literals_pure_no_dns(monkeypatch):
    import scope
    monkeypatch.setattr(scope.socket, "gethostbyname",
                        lambda n: (_ for _ in ()).throw(AssertionError("host_literals never resolves")))
    assert g.host_literals("cme smb {target} -u {user} -d {domain}") == []      # placeholders ignored
    assert g.host_literals("nmap 10.0.0.5") == ["10.0.0.5"]                      # dotted IP
    assert g.host_literals("nmap evil.example.com") == ["evil.example.com"]      # FQDN
    assert g.host_literals("nmap -sV {target} 0177.0.0.1") == ["0177.0.0.1"]     # dotted octal
    assert g.host_literals("masscan {target} --rate 100000") == []              # bare integer != host


# --- scope_literal_violations: check on the TEMPLATE (resolves names; "resolve + report" model) ---
def test_scope_literal_violations_resolves_out_of_scope_hostname(monkeypatch):
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.example.com": "203.0.113.9"})
    assert g.scope_literal_violations("nmap -sV {target} evil.example.com") == ["evil.example.com"]


def test_scope_literal_violations_allows_in_scope_hostname(monkeypatch):
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"box.lab": "10.0.0.7"})
    assert g.scope_literal_violations("nmap -sV {target} box.lab") == []


def test_scope_literal_violations_flags_proxy_host_in_url(monkeypatch):
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.example.com": "203.0.113.9"})
    assert g.scope_literal_violations(
        "curl http://{target}/ -x http://evil.example.com:8080") == ["evil.example.com"]


def test_scope_literal_violations_ignores_placeholders_and_rate(monkeypatch):
    # {domain}/{share} are placeholders, a rate is a bare integer: none is a host,
    # so no resolution and no over-blocking (end of the domain/rate FPs).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname",
                        lambda n: (_ for _ in ()).throw(AssertionError(f"unexpected resolution: {n}")))
    assert g.scope_literal_violations("cme smb {target} -u {user} -d {domain} --rate 100000") == []


# --- B1: closing the three host-classification bypasses (exotic notations) ---
# Each notation was ignored by the local classification although the OS (and therefore the real
# tool: nmap/nc/curl) resolves it. The scope check must therefore see it. See adversarial review of 11/17.

def test_scope_literal_violations_flags_trailing_dot_fqdn(monkeypatch):
    # #1: an FQDN with a trailing dot (DNS root, evil.example.com.) IS a host — nc/curl
    # resolve it. It must be resolved and checked like any name.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.example.com.": "203.0.113.9"})
    assert g.scope_literal_violations("nmap -sV {target} evil.example.com.") == ["evil.example.com."]


def test_scope_flags_abbreviated_ipv4_literal(monkeypatch):
    # #2: abbreviated IPv4 — 8.524296 == 8.8.0.8 via inet_aton, accepted as-is by
    # nc/nmap/curl — out of scope. Checked WITHOUT DNS (IP form) on the template AND the
    # rendered backstop.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS forbidden on a literal IP: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("nc 8.524296 4444") == ["8.524296"]
    assert g.scope_violations("nc 8.524296 4444") == ["8.524296"]


def test_scope_flags_integer_host_in_url(monkeypatch):
    # #3: integer encoding an IP in a URL HOST POSITION — http://2130706433/ == 127.0.0.1,
    # out of scope. A structured host position is an unambiguous host → checked
    # even as a bare integer, and WITHOUT DNS (IP form).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS forbidden on a literal IP: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("curl http://2130706433/") == ["2130706433"]
    assert g.scope_violations("curl http://2130706433/") == ["2130706433"]


def test_bare_integer_argument_still_not_a_host(monkeypatch):
    # FP non-regression: a BARE integer OUTSIDE a host position (rate, count, port) is NOT
    # an IP, even though inet_aton would accept it (100000 == 0.1.134.160). No over-blocking,
    # and never DNS. This is the exact counter-example of #3: only the POSITION differs.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS forbidden: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("masscan 10.0.0.5 --rate 100000") == []
    assert g.scope_violations("masscan 10.0.0.5 --rate 100000") == []
    assert g.host_literals("masscan 10.0.0.5 --rate 100000") == ["10.0.0.5"]


# --- B2: defeats confirmed by the adversarial re-review (post-055eaa4) ---

def test_scope_flags_mono_label_host_in_structured_position(monkeypatch):
    # A single-label host (localhost -> 127.0.0.1, dc01, wpad, short NetBIOS/AD names)
    # in a structured HOST POSITION (URL/UNC/user@) IS an unambiguous host: nc/curl/ssh
    # connect to it. It must be resolved and checked (it was not: _FQDN_RE requires
    # a dot).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"localhost": "127.0.0.1", "dc01": "203.0.113.9",
                            "wpad": "203.0.113.9"})
    assert g.scope_literal_violations("curl http://localhost/") == ["localhost"]
    assert g.scope_literal_violations("ssh admin@dc01") == ["dc01"]
    assert g.scope_literal_violations("smbclient //wpad/share") == ["wpad"]


def test_bare_mono_label_token_not_a_host(monkeypatch):
    # CRITICAL FP non-regression: a BARE single-label token (tool name, flag, value)
    # is NEVER a host — otherwise 'nmap'/'smb'/'admin' would be resolved = massive FP.
    # Only the structured POSITION makes a single label a host (see test above).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"resolution of a bare token forbidden: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("nmap -sV 10.0.0.5") == []
    assert g.scope_violations("nmap -sV 10.0.0.5") == []
    assert g.host_literals("nmap -sV 10.0.0.5") == ["10.0.0.5"]
    for bare in ["nmap", "smb", "admin", "crackmapexec", "-u", "-sV"]:
        assert g._host_kind(bare) is None, bare


def test_scope_flags_url_slash_confusion_literal_ip(monkeypatch):
    # http:///IP and http:/IP: urlparse sees an empty host (netloc only filled on an exact '://'),
    # but curl/wget normalize and connect to the IP. We normalize the
    # number of slashes -> the out-of-scope IP is extracted and flagged, WITHOUT DNS.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS forbidden on a literal IP: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_violations("curl http:///169.254.169.254/latest/meta-data/") == ["169.254.169.254"]
    assert g.scope_violations("curl http:/203.0.113.9/") == ["203.0.113.9"]
    assert g.scope_literal_violations("curl http:///169.254.169.254/") == ["169.254.169.254"]
    # Normal form (exact '://'): extracted as before, never over-normalized.
    assert g.scope_violations("curl http://10.0.0.5/") == []


# --- B3: defeats + regressions confirmed by the round 2 re-review ---

def test_scope_flags_trailing_dot_ipv4_literal(monkeypatch):
    # IPv4 with a trailing dot (203.0.113.9.): inet_aton REJECTS it but curl/getaddrinfo
    # strip the DNS root and connect to it. A single trailing dot is stripped ->
    # the out-of-scope IP is flagged, WITHOUT DNS.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS forbidden on a literal IP: {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_violations("nc 203.0.113.9. 4444") == ["203.0.113.9."]
    assert g.scope_violations("curl http://169.254.169.254./latest/meta-data/") == ["169.254.169.254."]
    assert g.scope_literal_violations("curl http://203.0.113.9./") == ["203.0.113.9."]


def test_scope_flags_residual_tld_host_in_url_position(monkeypatch):
    # A literal with a residual TLD (.zip/.sh) IN A URL HOST POSITION is a host
    # (never a file) -> resolved and checked. The extension filter applies only
    # to BARE tokens (file names).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.zip": "203.0.113.9", "get.sh": "203.0.113.9"})
    assert g.scope_literal_violations("curl http://evil.zip/x") == ["evil.zip"]
    assert g.scope_literal_violations("curl http://get.sh/") == ["get.sh"]


def test_bare_filename_suffix_still_not_a_host():
    # Non-regression: a BARE file name with a known extension (including .zip and the
    # offensive output formats) is NOT a host (data, not a host position).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.host_literals("nmap -oN scan.zip 10.0.0.5") == ["10.0.0.5"]
    for f in ["loot.pcap", "out.scan", "x.report", "a.cap", "r.results", "c.ndjson"]:
        assert g._host_kind(f) is None, f


def test_file_scheme_not_mangled_into_host():
    # B2 regression fixed: slash renormalization applies ONLY to network schemes.
    # file:///path, classpath:/, data:/ must NOT fabricate a phantom host.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.host_literals("curl file:///etc/passwd") == []
    assert g.host_literals("curl file:/etc/passwd") == []
    assert g.host_literals("java -cp classpath:/app 10.0.0.5") == ["10.0.0.5"]
    # but a NETWORK scheme with abnormal slashes is still normalized (bypass closed)
    assert g.scope_violations("curl http:///203.0.113.9/") == ["203.0.113.9"]


def test_identity_flag_at_value_not_host_but_bare_host_still_checked(monkeypatch):
    # B2 regression fixed WITHOUT opening a hole: the @ value of an identity flag
    # (-u svc@CONTOSO) is a UPN/credential -> not a host. BUT a BARE host after the
    # same flag keeps its check: -u = UDP for nc, -d = debug for nmap. Only the
    # @ form is skipped (otherwise nc -u IP / nmap -d IP would be bypasses).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"Unexpected DNS (@ forms skipped, pure literal IPs): {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    # @ forms (credential) -> never checked, no false positive
    assert g.scope_literal_violations("crackmapexec smb 10.0.0.5 -u svc@CONTOSO -p pw") == []
    assert g.scope_literal_violations("cme smb 10.0.0.5 -u admin@corp.local -p pw") == []
    # BARE host after -u/-d (UDP/debug collision) -> ALWAYS checked (no bypass)
    assert g.scope_violations("nc -u 203.0.113.9 4444") == ["203.0.113.9"]
    assert g.scope_violations("nmap -d 203.0.113.9") == ["203.0.113.9"]
