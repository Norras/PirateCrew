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


# --- scope_violations : backstop sur la commande RENDUE, IP LITTÉRALES seulement (sans DNS, sans FP) ---
def test_scope_violations_rendered_ip_only_out_of_scope():
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.scope_violations("nmap 203.0.113.9") == ["203.0.113.9"]  # IP pointée hors périmètre
    assert g.scope_violations("nmap 10.0.0.5") == []                   # IP pointée in-scope


def test_scope_violations_rendered_ignores_hostname_and_rate(monkeypatch):
    # FP écartés : un domaine (arg d'identité) et un grand entier (débit) rendus ne sont PAS
    # pris pour des IP -> pas de sur-blocage, et AUCUN DNS sur ce backstop.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS interdit sur le backstop IP-only : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_violations("cme smb 10.0.0.1 -u admin -d corp.local") == []
    assert g.scope_violations("masscan 10.0.0.1 --rate 100000") == []


def test_scope_violations_rendered_flags_dotted_octal_ip():
    # 0177.0.0.1 == 127.0.0.1 (octal pointé, accepté par nmap/curl via inet_aton), hors périmètre.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.scope_violations("nmap -sV 10.0.0.5 0177.0.0.1") == ["0177.0.0.1"]


def test_scope_violations_rendered_ignores_filename():
    # Un nom de fichier (extension connue) n'est pas une IP -> jamais signalé.
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    assert g.scope_violations("nmap -oN scan.txt 127.0.0.1") == []


# --- host_literals : PUR (authoring + contrôle sur gabarit), jamais de résolution ---
def test_host_literals_pure_no_dns(monkeypatch):
    import scope
    monkeypatch.setattr(scope.socket, "gethostbyname",
                        lambda n: (_ for _ in ()).throw(AssertionError("host_literals ne résout jamais")))
    assert g.host_literals("cme smb {target} -u {user} -d {domain}") == []      # placeholders ignorés
    assert g.host_literals("nmap 10.0.0.5") == ["10.0.0.5"]                      # IP pointée
    assert g.host_literals("nmap evil.example.com") == ["evil.example.com"]      # FQDN
    assert g.host_literals("nmap -sV {target} 0177.0.0.1") == ["0177.0.0.1"]     # octal pointé
    assert g.host_literals("masscan {target} --rate 100000") == []              # entier nu != hôte


# --- scope_literal_violations : contrôle sur le GABARIT (résout les noms ; modèle "résous + report") ---
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
    # {domain}/{share} sont des placeholders, un débit est un entier nu : aucun n'est un hôte,
    # donc aucune résolution et aucun sur-blocage (fin des FP domaine/débit).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname",
                        lambda n: (_ for _ in ()).throw(AssertionError(f"résolution inattendue : {n}")))
    assert g.scope_literal_violations("cme smb {target} -u {user} -d {domain} --rate 100000") == []


# --- B1 : fermeture des trois contournements de classification d'hôte (notations exotiques) ---
# Chaque notation était ignorée par la classification locale alors que l'OS (et donc l'outil
# réel : nmap/nc/curl) la résout. Le périmètre doit donc la voir. Cf. revue adversariale 17/11.

def test_scope_literal_violations_flags_trailing_dot_fqdn(monkeypatch):
    # #1 : un FQDN avec point final (racine DNS, evil.example.com.) EST un hôte — nc/curl
    # le résolvent. Il doit être résolu et contrôlé comme n'importe quel nom.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.example.com.": "203.0.113.9"})
    assert g.scope_literal_violations("nmap -sV {target} evil.example.com.") == ["evil.example.com."]


def test_scope_flags_abbreviated_ipv4_literal(monkeypatch):
    # #2 : IPv4 abrégée — 8.524296 == 8.8.0.8 via inet_aton, acceptée telle quelle par
    # nc/nmap/curl — hors périmètre. Contrôlée SANS DNS (forme IP) sur le gabarit ET le
    # backstop rendu.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS interdit sur une IP littérale : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("nc 8.524296 4444") == ["8.524296"]
    assert g.scope_violations("nc 8.524296 4444") == ["8.524296"]


def test_scope_flags_integer_host_in_url(monkeypatch):
    # #3 : entier encodant une IP en POSITION D'HÔTE d'URL — http://2130706433/ == 127.0.0.1,
    # hors périmètre. Une position d'hôte structurée est un hôte non ambigu → contrôlée
    # même en entier nu, et SANS DNS (forme IP).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS interdit sur une IP littérale : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("curl http://2130706433/") == ["2130706433"]
    assert g.scope_violations("curl http://2130706433/") == ["2130706433"]


def test_bare_integer_argument_still_not_a_host(monkeypatch):
    # Non-régression FP : un entier NU HORS position d'hôte (débit, compte, port) n'est PAS
    # une IP, même si inet_aton l'accepterait (100000 == 0.1.134.160). Pas de sur-blocage,
    # et jamais de DNS. C'est l'exact contre-exemple de #3 : seule la POSITION diffère.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS interdit : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("masscan 10.0.0.5 --rate 100000") == []
    assert g.scope_violations("masscan 10.0.0.5 --rate 100000") == []
    assert g.host_literals("masscan 10.0.0.5 --rate 100000") == ["10.0.0.5"]


# --- B2 : défaites confirmées par la re-review adversariale (post-055eaa4) ---

def test_scope_flags_mono_label_host_in_structured_position(monkeypatch):
    # Un hôte à label unique (localhost -> 127.0.0.1, dc01, wpad, noms NetBIOS/AD courts)
    # en POSITION D'HÔTE structurée (URL/UNC/user@) EST un hôte non ambigu : nc/curl/ssh
    # s'y connectent. Il doit être résolu et contrôlé (il ne l'était pas : _FQDN_RE exige
    # un point).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"localhost": "127.0.0.1", "dc01": "203.0.113.9",
                            "wpad": "203.0.113.9"})
    assert g.scope_literal_violations("curl http://localhost/") == ["localhost"]
    assert g.scope_literal_violations("ssh admin@dc01") == ["dc01"]
    assert g.scope_literal_violations("smbclient //wpad/share") == ["wpad"]


def test_bare_mono_label_token_not_a_host(monkeypatch):
    # Non-régression FP CRITIQUE : un token mono-label NU (nom d'outil, flag, valeur)
    # n'est JAMAIS un hôte — sinon 'nmap'/'smb'/'admin' seraient résolus = FP massif.
    # Seule la POSITION structurée fait d'un label unique un hôte (cf. test ci-dessus).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"résolution interdite d'un token nu : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_literal_violations("nmap -sV 10.0.0.5") == []
    assert g.scope_violations("nmap -sV 10.0.0.5") == []
    assert g.host_literals("nmap -sV 10.0.0.5") == ["10.0.0.5"]
    for nu in ["nmap", "smb", "admin", "crackmapexec", "-u", "-sV"]:
        assert g._host_kind(nu) is None, nu


def test_scope_flags_url_slash_confusion_literal_ip(monkeypatch):
    # http:///IP et http:/IP : urlparse voit un hôte vide (netloc alimenté sur '://' exact
    # seulement), mais curl/wget normalisent et se connectent à l'IP. On normalise le
    # nombre de slashs -> l'IP hors périmètre est extraite et signalée, SANS DNS.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS interdit sur une IP littérale : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_violations("curl http:///169.254.169.254/latest/meta-data/") == ["169.254.169.254"]
    assert g.scope_violations("curl http:/203.0.113.9/") == ["203.0.113.9"]
    assert g.scope_literal_violations("curl http:///169.254.169.254/") == ["169.254.169.254"]
    # Forme normale ('://' exact) : extraite comme avant, jamais sur-normalisée.
    assert g.scope_violations("curl http://10.0.0.5/") == []


# --- B3 : défaites + régressions confirmées par la re-review round 2 ---

def test_scope_flags_trailing_dot_ipv4_literal(monkeypatch):
    # IPv4 à point final (203.0.113.9.) : inet_aton la REJETTE mais curl/getaddrinfo
    # retirent la racine DNS et s'y connectent. On retire un point final unique ->
    # l'IP hors périmètre est signalée, SANS DNS.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS interdit sur une IP littérale : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    assert g.scope_violations("nc 203.0.113.9. 4444") == ["203.0.113.9."]
    assert g.scope_violations("curl http://169.254.169.254./latest/meta-data/") == ["169.254.169.254."]
    assert g.scope_literal_violations("curl http://203.0.113.9./") == ["203.0.113.9."]


def test_scope_flags_residual_tld_host_in_url_position(monkeypatch):
    # Un littéral en TLD-résiduel (.zip/.sh) EN POSITION D'HÔTE d'URL est un hôte
    # (jamais un fichier) -> résolu et contrôlé. Le filtre d'extensions ne vaut que
    # pour les tokens NUS (noms de fichiers).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    _fake_dns(monkeypatch, {"evil.zip": "203.0.113.9", "get.sh": "203.0.113.9"})
    assert g.scope_literal_violations("curl http://evil.zip/x") == ["evil.zip"]
    assert g.scope_literal_violations("curl http://get.sh/") == ["get.sh"]


def test_bare_filename_suffix_still_not_a_host():
    # Non-régression : un nom de fichier NU avec extension connue (y compris .zip et les
    # formats de sortie offensifs) n'est PAS un hôte (donnée, pas position d'hôte).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.host_literals("nmap -oN scan.zip 10.0.0.5") == ["10.0.0.5"]
    for f in ["loot.pcap", "out.scan", "x.report", "a.cap", "r.results", "c.ndjson"]:
        assert g._host_kind(f) is None, f


def test_file_scheme_not_mangled_into_host():
    # Régression B2 corrigée : la renormalisation de slashs ne s'applique QU'aux schémas
    # réseau. file:///chemin, classpath:/, data:/ ne doivent PAS fabriquer d'hôte fantôme.
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    assert g.host_literals("curl file:///etc/passwd") == []
    assert g.host_literals("curl file:/etc/passwd") == []
    assert g.host_literals("java -cp classpath:/app 10.0.0.5") == ["10.0.0.5"]
    # mais un schéma RÉSEAU à slashs anormaux reste normalisé (contournement fermé)
    assert g.scope_violations("curl http:///203.0.113.9/") == ["203.0.113.9"]


def test_identity_flag_at_value_not_host_but_bare_host_still_checked(monkeypatch):
    # Régression B2 corrigée SANS ouvrir de trou : la valeur @ d'un flag d'identité
    # (-u svc@CONTOSO) est un UPN/credential -> pas un hôte. MAIS un hôte NU après le
    # même flag garde son contrôle : -u = UDP pour nc, -d = debug pour nmap. On ne
    # skippe QUE la forme @ (sinon nc -u IP / nmap -d IP seraient des contournements).
    set_active_scope(Scope.from_lines(["10.0.0.0/24"]))
    def boom(name):
        raise AssertionError(f"DNS inattendu (formes @ skippées, IP littérales pures) : {name}")
    monkeypatch.setattr(__import__("scope").socket, "gethostbyname", boom)
    # formes @ (credential) -> jamais contrôlées, pas de faux positif
    assert g.scope_literal_violations("crackmapexec smb 10.0.0.5 -u svc@CONTOSO -p pw") == []
    assert g.scope_literal_violations("cme smb 10.0.0.5 -u admin@corp.local -p pw") == []
    # hôte NU après -u/-d (collision UDP/debug) -> TOUJOURS contrôlé (pas de contournement)
    assert g.scope_violations("nc -u 203.0.113.9 4444") == ["203.0.113.9"]
    assert g.scope_violations("nmap -d 203.0.113.9") == ["203.0.113.9"]
