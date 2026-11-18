from scope import Scope
from state.world_model import WorldModel
from catalog import load_catalog, technique_by_id
from orchestrator import (plan_tasks, route_after_integrate, reconcile_evidence,
                          _parse_services, _task_inputs_fp)
from state.world_model import Credential


def test_plan_tasks_filters_by_requires_and_ledger():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_host("10.10.10.5")
    wm.add_service("10.10.10.5", 445, name="smb")
    cat = load_catalog()
    tasks = plan_tasks(wm, cat)
    assert any(t["service"] == "smb" for t in tasks)          # technique sans requires proposée
    # une technique exigeant un cred n'apparaît pas tant qu'aucun cred applicable
    assert all("credential" not in technique_by_id(cat, t["technique_id"]).requires
               for t in tasks)


def test_author_model_configurable_par_env(monkeypatch):
    import orchestrator as o
    monkeypatch.delenv("PIRATECREW_AUTHOR_MODEL", raising=False)
    assert o._author_model_name() == "claude-sonnet-4-6"
    monkeypatch.setenv("PIRATECREW_AUTHOR_MODEL", "claude-opus-4-8")
    assert o._author_model_name() == "claude-opus-4-8"


def test_route_finishes_on_cycle_cap():
    assert route_after_integrate({"cycle": 6, "max_cycles": 6}) == "finish"


def test_author_context_rich():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb", version="Samba 4.15")
    w.add_service("10.0.0.5", 80, name="http", version="nginx 1.25")
    w.add_credential(Credential(kind="password", principal="CORP\\admin", secret="p@ss"))
    w.mark_technique("10.0.0.5", "smb", "smb-brute", status="tried", port=445)
    w.add_evidence({"phase": "execute", "technique": "smb-brute", "host": "10.0.0.5",
                    "raw": "NT_STATUS_LOGON_FAILURE pour admin"})
    ctx = _author_context(w, "smb")
    assert "445" in ctx and "Samba 4.15" in ctx          # version + port du service visé
    assert "http" in ctx                                  # service voisin
    assert "CORP\\admin" in ctx and "p@ss" not in ctx     # principal oui, secret non
    assert "smb-brute" in ctx and "LOGON_FAILURE" in ctx  # échec tenté + extrait du résultat


def test_author_context_tronque_les_sorties_longues():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    w.mark_technique("10.0.0.5", "smb", "t", status="tried", port=445)
    # long mais à basse entropie (espaces) pour tester la troncature, pas le masquage
    w.add_evidence({"phase": "execute", "technique": "t", "host": "10.0.0.5", "raw": "echec " * 1000})
    ctx = _author_context(w, "smb")
    assert "echec echec" in ctx        # début de l'extrait présent
    assert ctx.count("echec") < 60     # tronqué (pas les 1000 occurrences)


def test_author_context_masks_high_entropy_unknown_hash():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    w.mark_technique("10.0.0.5", "smb", "dump", status="tried", port=445)
    # hash NT inconnu (jamais reconcilié en Credential) dans la sortie brute
    w.add_evidence({"phase": "execute", "technique": "dump", "host": "10.0.0.5",
                    "raw": "Administrator ::: 31d6cfe0d16ae931b73c59d7e0c089c0 :::"})
    ctx = _author_context(w, "smb")   # aucun credential connu -> masquage par entropie
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in ctx
    assert "***" in ctx


def test_author_context_redacts_known_secret():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    w.add_credential(Credential(kind="password", principal="admin", secret="Summer2024!"))
    w.mark_technique("10.0.0.5", "smb", "smb-brute", status="tried", port=445)
    w.add_evidence({"phase": "execute", "technique": "smb-brute", "host": "10.0.0.5",
                    "raw": "admin:Summer2024! (valid session)"})
    ctx = _author_context(w, "smb")
    assert "Summer2024!" not in ctx   # secret connu expurgé de l'extrait envoyé au LLM
    assert "***" in ctx               # marqueur de rédaction présent


def test_author_context_ajoute_les_connaissances_rag():
    from orchestrator import _author_context
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 445, name="smb")
    assert "Connaissances" not in _author_context(w, "smb")          # sans RAG : inchangé
    ctx = _author_context(w, "smb", extra="Note : énumérer les partages en session nulle")
    assert "Connaissances" in ctx and "session nulle" in ctx


class _Doc:
    def __init__(self, text, source=""):
        self.page_content = text
        self.metadata = {"source": source} if source else {}


def test_rag_for_author_interroge_le_service_et_borne_les_extraits():
    import orchestrator as o
    queries = []

    def search(query, k):
        queries.append((query, k))
        return [_Doc("A" * 5000), _Doc("gabarit smbclient", source="llm_authored")]
    out = o._rag_for_author("smb", search=search)
    assert "smb" in queries[0][0]
    assert "A" * 500 in out and "A" * 600 not in out                  # extrait borné
    assert "gabarit smbclient" in out and "technique promue" in out   # source signalée


def test_rag_for_author_ne_leve_jamais():
    import orchestrator as o

    def boom(query, k):
        raise RuntimeError("chroma hors ligne")
    assert o._rag_for_author("smb", search=boom) == ""
    assert o._rag_for_author("smb", search=lambda q, k: []) == ""


def test_node_decide_passe_le_rag_a_l_auteur(monkeypatch, tmp_path):
    import orchestrator as o
    import offense.catalog_author as author
    w = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    w.add_service("10.0.0.5", 5432, name="postgresql")               # aucun builtin
    monkeypatch.setattr(o, "get_world", lambda tid: w)
    monkeypatch.setattr(o, "_rag_for_author", lambda svc, search=None: f"NOTE-RAG-{svc}")
    seen = []
    monkeypatch.setattr(author, "author_technique",
                        lambda svc, ctx, invoke: seen.append((svc, ctx)) or None)
    o.node_decide({"discovered_services": []}, {"configurable": {"thread_id": "t-rag"}})
    assert seen and seen[0][0] == "postgresql" and "NOTE-RAG-postgresql" in seen[0][1]


def test_node_execute_audite_chaque_technique(monkeypatch):
    # Chaque technique qui passe par node_execute laisse une ligne EXEC (id, hôte,
    # service, statut), SANS la commande rendue (qui porterait un credential).
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch, "_CATALOG", load_catalog(operator_dir="catalog/__aucun__"))
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    w.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_exec_audit"] = w
    cfg = {"configurable": {"thread_id": "t_exec_audit"}}
    planned = plan_tasks(w, orch._CATALOG)
    orch.node_execute({"planned": planned, "rag_context": ""}, cfg)
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert "EXEC" in audit
    assert "smb.port_probe" in audit and "127.0.0.1:445" in audit


def test_node_execute_audit_exec_sans_credential(monkeypatch):
    # Chemin offensif operator : l'EXEC ne doit PAS contenir le mot de passe rendu.
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    from catalog.loader import Technique
    from state.world_model import Credential
    tech = Technique(id="op.smb", name="x", domain="ad", service="smb", requires={"credential"},
                     tool="smbclient", command_template="smbclient //{target}/s -U {user}%{password} -c ls",
                     success_signal="ok", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    monkeypatch.setattr(orch.offense.executor, "execute_command",
                        lambda rendered, timeout=120: ("done", "sortie"))
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    w.add_service("127.0.0.1", 445, name="smb")
    w.add_credential(Credential(kind="password", principal="svc", secret="Zz-Secret-1!"))
    orch._MISSIONS["t_exec_nocred"] = w
    cfg = {"configurable": {"thread_id": "t_exec_nocred"}}
    orch.node_execute({"planned": plan_tasks(w, orch._CATALOG), "rag_context": ""}, cfg)
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    exec_lines = [l for l in audit.splitlines() if "| EXEC |" in l]
    assert exec_lines and any("op.smb" in l for l in exec_lines)
    assert all("Zz-Secret-1!" not in l for l in exec_lines)  # jamais le secret


def test_node_recon_audite_le_scan(monkeypatch):
    # La recon est une action : elle doit laisser une ligne dans audit.log, même si
    # ses sondes ne visent que des hôtes in-scope (pas de violation de périmètre).
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch, "_port_open", lambda h, p, timeout=1.0: False)
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    orch._MISSIONS["t_audit_recon"] = w
    orch.node_recon({"target": "127.0.0.1", "cycle": 0, "question": "", "max_cycles": 6},
                    {"configurable": {"thread_id": "t_audit_recon"}})
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert "RECON" in audit and "127.0.0.1" in audit


def test_node_decide_audite_les_taches(monkeypatch):
    # La décision de planification est une action : les techniques planifiées doivent
    # apparaître dans audit.log.
    import orchestrator as orch
    import scope as scope_mod
    from pathlib import Path
    w = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    w.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_audit_decide"] = w
    orch.node_decide({"discovered_services": []},
                     {"configurable": {"thread_id": "t_audit_decide"}})
    audit = Path(scope_mod.AUDIT_LOG).read_text(encoding="utf-8")
    assert "DECIDE" in audit
    assert "smb.port_probe" in audit or "smb.enum_shares" in audit


def test_integrate_captures_raw_evidence():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    n = reconcile_evidence(wm, "Found creds admin:Password1 on 10.10.10.5")
    assert n >= 1 and any(c.principal == "admin" for c in wm.credentials)


def test_out_of_scope_discovery_not_tasked():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_host("8.8.8.8")  # découverte hors périmètre
    assert "8.8.8.8" not in [t["host"] for t in plan_tasks(wm, load_catalog())]


def test_parse_services_ignores_substrings_and_closed_ports():
    # Un numéro de version/netmask ne doit pas créer de service par sous-chaîne,
    # et une énumération de ports fermés non plus.
    assert _parse_services("Apache/2.2.15 built 2021") == []        # "2021" != port 21
    assert _parse_services("Netmask 255.255.255.0") == []
    assert _parse_services("Host down. Checked 21,22,80,445 - none open.") == []


def test_parse_services_detects_open_services():
    txt = "PORT   STATE SERVICE\n445/tcp open  microsoft-ds\n80/tcp open http"
    svc = _parse_services(txt)
    assert "smb" in svc and "http" in svc


def test_reconcile_requires_credential_cue():
    # Prose ordinaire 'mot:valeur' SANS indice de credential => aucun faux secret.
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Server:nginx\nHost:10.10.10.9\nDomain:WORKGROUP")
    assert wm.credentials == []


def test_task_inputs_fp_changes_when_new_cred_discovered():
    # R2 : un nouveau credential applicable change l'empreinte => technique ré-ouverte.
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_credential(Credential(kind="password", principal="svcA", secret="a", source="t"))
    fp1 = _task_inputs_fp(wm, "smb", {"credential"})
    wm.add_credential(Credential(kind="password", principal="svcB", secret="b", source="t"))
    fp2 = _task_inputs_fp(wm, "smb", {"credential"})
    assert fp1 and fp2 and fp1 != fp2


def test_task_inputs_fp_empty_without_credential_requirement():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    assert _task_inputs_fp(wm, "smb", set()) == ""


# --- Milestone 1 : propagation de port + escalade « outil manquant » (Option Y) --- #
def test_plan_task_carries_service_port():
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 8080, name="http")
    http_tasks = [t for t in plan_tasks(wm, load_catalog()) if t["service"] == "http"]
    assert http_tasks and all(t.get("port") == 8080 for t in http_tasks)


def test_technique_available_python_vs_missing_binary(monkeypatch):
    import orchestrator as orch
    cat = load_catalog()
    assert orch.technique_available(technique_by_id(cat, "http.fingerprint")) is True
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)
    assert orch.technique_available(technique_by_id(cat, "smb.enum_shares")) is False


def test_render_template_fills_target_and_port():
    import orchestrator as orch
    assert orch._render_template("x http://{target}:{port}/", "127.0.0.1", 8080) == "x http://127.0.0.1:8080/"
    assert orch._render_template("", "127.0.0.1", 80) == ""


def test_render_template_substitutes_credential_fields():
    import orchestrator as orch
    from state.world_model import Credential
    creds = [Credential(kind="hash", principal="CORP\\admin", secret="aad3b:deadbeef", source="t")]
    out = orch._render_template("evil-winrm -i {target} -u {user} -H {hash}", "127.0.0.1", creds=creds)
    assert out == "evil-winrm -i 127.0.0.1 -u admin -H aad3b:deadbeef"


def test_render_template_domain_from_principal():
    import orchestrator as orch
    from state.world_model import Credential
    creds = [Credential(kind="password", principal="user@corp.local", secret="P@ss", source="t")]
    out = orch._render_template("cmd {user} {domain} {password}", "127.0.0.1", creds=creds)
    assert out == "cmd user corp.local P@ss"


def test_render_template_unknown_placeholder_returns_raw():
    import orchestrator as orch
    # Pas de cred : {user} inconnu -> gabarit brut (contrat Projet 1 inchange).
    assert orch._render_template("x {user}", "127.0.0.1") == "x {user}"


def _patch_fake_agent(monkeypatch):
    class _Msg:
        content = "OK (fake)"

    class _FakeAgent:
        def invoke(self, _):
            return {"messages": [_Msg()]}

    monkeypatch.setattr("agents.dynamic_agent.build_task_agent",
                        lambda domain, world=None, mission_context="": _FakeAgent())


def test_blocked_missing_tool_escalates_and_not_marked_tried(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    _patch_fake_agent(monkeypatch)
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)  # smbclient absent
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_block"] = wm
    cfg = {"configurable": {"thread_id": "t_block"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned}, cfg)["execution_reports"]
    assert any(r["status"] == "blocked_missing_tool" and r["tool"] == "smbclient" for r in reports)
    out = orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert "smbclient" in out["final_response"]
    # bloquée => NON marquée (replanifiable après install) ; exécutée => marquée
    assert wm.is_tried("127.0.0.1", "smb", "smb.enum_shares", inputs_fp="", port=445) is False
    assert wm.is_tried("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445) is True


def test_route_finishes_when_only_blocked_tasks_remain(monkeypatch):
    import orchestrator as orch
    monkeypatch.setattr(orch.shutil, "which", lambda b: None)  # smbclient absent
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.mark_technique("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445)
    orch._MISSIONS["t_route_block"] = wm
    assert route_after_integrate({"cycle": 1, "max_cycles": 6, "thread_id": "t_route_block"}) == "finish"


def test_route_continues_when_runnable_task_remains():
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 80, name="http")
    orch._MISSIONS["t_route_cont"] = wm
    assert route_after_integrate({"cycle": 1, "max_cycles": 6, "thread_id": "t_route_cont"}) == "continue"


def test_start_mission_reuses_worldmodel_on_same_thread():
    import orchestrator as orch
    sc = Scope.from_lines(["127.0.0.1/32"])
    w1 = orch.start_mission("t_reuse", sc)
    w1.mark_technique("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445)
    w2 = orch.start_mission("t_reuse", sc)
    assert w2 is w1 and w2.is_tried("127.0.0.1", "smb", "smb.port_probe", inputs_fp="", port=445) is True
    assert orch.start_mission("t_other_thread", sc) is not w1


def test_requested_ports_host_port():
    from orchestrator import requested_ports
    assert requested_ports("fais une analyse sur 127.0.0.1:8980") == [8980]


def test_requested_ports_word_port():
    from orchestrator import requested_ports
    assert requested_ports("vérifie le port 8980") == [8980]


def test_requested_ports_none():
    from orchestrator import requested_ports
    assert requested_ports("analyse tout le périmètre autorisé") == []


def test_requested_ports_out_of_range():
    from orchestrator import requested_ports
    assert requested_ports("port 99999") == []


def _services_named(wm, host, port):
    return [s.name for h in wm.in_scope_hosts() if h.ip == host
            for s in h.services if s.port == port]


def test_discover_services_fingerprint_names_unusual_port():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    n = discover_services(wm, ["127.0.0.1"], [80, 8980],
                          probe=lambda h, p: p == 8980,
                          fingerprint=lambda h, p: "http")
    assert n == 1
    assert _services_named(wm, "127.0.0.1", 8980) == ["http"]


def test_discover_services_known_port_uses_mapping():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    discover_services(wm, ["127.0.0.1"], [80, 8980], probe=lambda h, p: p == 80)
    assert _services_named(wm, "127.0.0.1", 80) == ["http"]


def test_discover_services_nothing_open():
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    n = discover_services(wm, ["127.0.0.1"], [80, 8980], probe=lambda h, p: False)
    assert n == 0
    assert [s for h in wm.in_scope_hosts() for s in h.services] == []


def test_reconcile_credential_on_line_after_cue():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Cred for DC :\nDamulsan:AAJJAQBenough1728!")
    assert any(c.principal == "Damulsan" and c.secret == "AAJJAQBenough1728!"
               for c in wm.credentials)


def test_reconcile_no_cue_word_adds_no_credential():
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Server:nginx\nHost:10.0.0.1")
    assert len(wm.credentials) == 0


def test_reconcile_ignores_header_like_value_near_cue():
    # Un en-tête compact « Clé:valeur » dans la fenêtre d'un indice ne doit PAS
    # devenir un faux credential (garde anti-fabrication, cf. « Server:nginx »).
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, "Password policy:\nServer:nginx")
    assert len(wm.credentials) == 0


def _creds(text):
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    reconcile_evidence(wm, text)
    return {(c.principal, c.secret) for c in wm.credentials}


def test_reconcile_cle_valeur_francais():
    # Fichier de configuration « clé = valeur » : identifiant + mot de passe voisins.
    assert _creds("[sauvegarde]\nutilisateur = svc-sauvegarde\nmot_de_passe = Lab-Fictif-2026!") \
        == {("svc-sauvegarde", "Lab-Fictif-2026!")}


def test_reconcile_cle_valeur_env_yaml_json():
    assert _creds('DB_USER=app\nDB_PASSWORD="s3cret!"') == {("app", "s3cret!")}
    assert _creds("db:\n  username: alice\n  password: 'Wond3rland'") == {("alice", "Wond3rland")}
    assert _creds('{\n  "login": "bob",\n  "passwd": "B0bPass!",\n}') == {("bob", "B0bPass!")}


def test_reconcile_cle_valeur_sans_identifiant_ou_valeur_factice():
    assert _creds("password = hunter2") == set()                      # pas d'identifiant voisin
    assert _creds("user = admin\npassword = ${DB_PASS}") == set()     # variable, pas un secret
    assert _creds("user = admin\npassword = ********") == set()       # masqué
    assert _creds("user = admin\npassword =") == set()                # vide
    assert _creds("user = admin\n\n\n\n\npassword = hunter2") == set()  # trop éloignés


def test_reconcile_nom_de_cle_jamais_pris_pour_un_identifiant():
    # « password:hunter2 » sur une ligne à indice : le principal serait « password ».
    assert _creds("password:hunter2") == set()


def test_reconcile_indice_francais_pour_la_forme_identifiant_secret():
    assert _creds("Identifiants du serveur :\nbob:Sup3rSecret") == {("bob", "Sup3rSecret")}


def test_node_integrate_lit_les_sorties_d_outils_pas_seulement_le_resume(monkeypatch, tmp_path):
    # Chemin agent (builtin) : le résumé du LLM ne recopie pas le fichier lu, mais la
    # sortie de l'outil le contient — le rattrapage doit la voir.
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)

    class _Tool:
        type = "tool"
        content = "HTTP 200\n[site]\nutilisateur = svc-x\nmot_de_passe = Xy-Fictif-99!"

    class _Final:
        type = "ai"
        content = "J'ai lu le fichier de sauvegarde."

    class _Agent:
        def invoke(self, _):
            return {"messages": [_Tool(), _Final()]}
    monkeypatch.setattr("agents.dynamic_agent.build_task_agent",
                        lambda domain, world=None, mission_context="": _Agent())
    wm = WorldModel(scope=Scope.from_lines(["10.10.10.0/24"]))
    wm.add_service("10.10.10.5", 80, name="http")
    orch._MISSIONS["t_tool_out"] = wm
    cfg = {"configurable": {"thread_id": "t_tool_out"}}
    planned = [t for t in plan_tasks(wm, orch._CATALOG) if t["technique_id"] == "http.get"]
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert any(c.principal == "svc-x" and c.secret == "Xy-Fictif-99!" for c in wm.credentials)


def test_discover_services_logs_each_open_port():
    # Mode verbose : un callback `log` reçoit une ligne par port ouvert (et aucune
    # pour les ports fermés), avec l'hôte, le port et le service détecté.
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    msgs = []
    discover_services(wm, ["127.0.0.1"], [80, 8980],
                      probe=lambda h, p: p == 8980,
                      fingerprint=lambda h, p: "http",
                      log=msgs.append)
    assert len(msgs) == 1
    assert "8980" in msgs[0] and "http" in msgs[0]


def test_vprint_respects_verbose_flag(capsys):
    # _vprint n'imprime que lorsque le mode verbose est actif ; set_verbose bascule.
    import orchestrator as orch
    orch.set_verbose(False)
    orch._vprint("caché")
    assert capsys.readouterr().out == ""
    orch.set_verbose(True)
    orch._vprint("visible")
    assert "visible" in capsys.readouterr().out
    orch.set_verbose(False)  # restaure l'état global


def test_wants_full_scan_detects_phrases():
    # Reconnaît une intention de balayage COMPLET ; ignore un port explicite ou le
    # simple mot « tout » (périmètre) sans « ports ».
    from orchestrator import wants_full_scan
    assert wants_full_scan("scanne tous les ports") is True
    assert wants_full_scan("fais un scan complet de 127.0.0.1") is True
    assert wants_full_scan("attaque 127.0.0.1:8980") is False
    assert wants_full_scan("analyse tout le périmètre autorisé") is False


def test_discover_services_parallel_finds_open_ports():
    # Sondage parallèle (workers>1) : trouve les mêmes ports ouverts, résultat
    # déterministe, enregistrement séquentiel dans le WorldModel.
    from orchestrator import discover_services
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    opened = {22, 8980}
    n = discover_services(wm, ["127.0.0.1"], [22, 80, 8980],
                          probe=lambda h, p: p in opened,
                          workers=4)
    assert n == 2
    ports_found = sorted(s.port for h in wm.in_scope_hosts() for s in h.services)
    assert ports_found == [22, 8980]


def test_autonomous_discovery_escalates_on_empty_host():
    from orchestrator import autonomous_discovery
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    # rien sur les ports par défaut ; un service sur un port haut hors défaut
    probe = lambda h, p: p == 50000
    n = autonomous_discovery(wm, ["127.0.0.1"], [80, 443], probe=probe,
                             fingerprint=lambda h, p: "http")
    assert n == 1
    assert any(s.port == 50000 and s.name == "http"
               for h in wm.in_scope_hosts() for s in h.services)


def test_autonomous_discovery_no_escalation_when_service_found():
    from orchestrator import autonomous_discovery
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    probe = lambda h, p: p in (80, 50000)   # 80 est dans les défauts
    autonomous_discovery(wm, ["127.0.0.1"], [80], probe=probe)
    ports = sorted(s.port for h in wm.in_scope_hosts() for s in h.services)
    assert ports == [80]  # pas d'escalade → 50000 jamais sondé/enregistré


def test_node_integrate_persists_world_each_cycle(tmp_path, monkeypatch):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    sc = Scope.from_lines(["127.0.0.1/32"])
    orch.start_mission("mX", sc)
    state = {"execution_reports": [], "cycle": 0, "thread_id": "mX"}
    orch.node_integrate(state, {"configurable": {"thread_id": "mX"}})
    assert (tmp_path / "mX" / "world.json").exists()


def test_requires_session_needs_authorized_session():
    import orchestrator as orch
    from state.world_model import Session
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="evil-winrm", authorized=False))
    assert orch._requires_satisfied(wm, "127.0.0.1", "smb", {"session"}) is False
    assert orch.authorize_sessions(wm, "127.0.0.1") == 1
    assert orch._requires_satisfied(wm, "127.0.0.1", "smb", {"session"}) is True


def test_authorize_sessions_counts_only_unauthorized_alive():
    import orchestrator as orch
    from state.world_model import Session
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_session(Session(host="127.0.0.1", channel="ssh", authorized=True))
    wm.add_session(Session(host="127.0.0.1", channel="x", alive=False))
    assert orch.authorize_sessions(wm, "127.0.0.1") == 0


def test_node_execute_runs_offensive_technique_deterministically(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    # agent = bombe : s'il est appelé sur une technique offensive, le test échoue
    def _boom(*a, **k): raise AssertionError("agent ne doit pas exécuter une technique offensive")
    monkeypatch.setattr("agents.dynamic_agent.build_task_agent", _boom)
    tech = Technique(id="llm.win", name="n", domain="ad", service="smb", requires=set(),
                     tool="crackmapexec", command_template="crackmapexec smb {target} -u {user} -H {hash}",
                     success_signal="Pwn3d", provided_by="llm", opens_session=True)
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda rendered, **kw: ("done", "STATUS ... (Pwn3d!) ..."))
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.add_credential(Credential(kind="hash", principal="admin", secret="h", source="t"))
    orch._MISSIONS["t_off"] = wm
    cfg = {"configurable": {"thread_id": "t_off"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    assert any(r["status"] == "done" and r["technique"] == "llm.win" for r in reports)
    assert any(s.host == "127.0.0.1" and s.authorized is False for s in wm.sessions)


def test_propose_only_skips_llm_execution(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("ne doit pas exécuter")))
    tech = Technique(id="llm.x", name="n", domain="ad", service="smb", requires=set(),
                     tool="cme", command_template="cme smb {target}", success_signal="ok",
                     provided_by="llm")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    orch.set_propose_only(True)
    try:
        wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
        wm.add_service("127.0.0.1", 445, name="smb"); orch._MISSIONS["t_po"] = wm
        cfg = {"configurable": {"thread_id": "t_po"}}
        reports = orch.node_execute({"planned": plan_tasks(wm, orch._CATALOG), "rag_context": ""}, cfg)["execution_reports"]
        assert any(r["status"] == "proposed_awaiting_operator" for r in reports)
    finally:
        orch.set_propose_only(False)


def test_dry_services_detects_service_without_technique():
    import orchestrator as orch
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 9999, name="exotic")   # aucun builtin pour "exotic"
    assert "exotic" in orch._dry_services(wm, orch._CATALOG, planned=[])
    wm.add_service("127.0.0.1", 445, name="smb")        # smb a des builtins
    assert "smb" not in orch._dry_services(wm, orch._CATALOG, planned=plan_tasks(wm, orch._CATALOG))


def test_node_execute_skips_unfillable_placeholder_without_executing(monkeypatch, tmp_path):
    # Un gabarit avec un placeholder non remplissable ({share} sans valeur) NE DOIT PAS
    # s'exécuter en brut : on remonte blocked_missing_input, l'exécuteur n'est jamais appelé.
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("ne doit pas exécuter un gabarit non rendu")))
    tech = Technique(id="llm.share", name="n", domain="ad", service="smb", requires=set(),
                     tool="smbclient", command_template="smbclient //{target}/{share} -U {user}",
                     success_signal="ok", provided_by="llm")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.add_credential(Credential(kind="password", principal="admin", secret="x", source="t"))
    orch._MISSIONS["t_share"] = wm
    cfg = {"configurable": {"thread_id": "t_share"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    r = next(r for r in reports if r["technique"] == "llm.share")
    assert r["status"] == "blocked_missing_input" and "share" in r["detail"]


def test_node_execute_blocks_out_of_scope_literal_ip(monkeypatch, tmp_path):
    # Un hôte LITTÉRAL hors périmètre dans le gabarit (opérateur/LLM) est bloqué AVANT
    # exécution (contrôle sur le gabarit), l'exécuteur n'est jamais appelé.
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("ne doit pas exécuter une technique hors périmètre")))
    tech = Technique(id="op.x", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target} 10.0.0.9",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_oos"] = wm
    cfg = {"configurable": {"thread_id": "t_oos"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    r = next(r for r in reports if r["technique"] == "op.x")
    assert r["status"] == "blocked_out_of_scope" and "10.0.0.9" in r["detail"]


def test_node_execute_blocks_out_of_scope_hostname_resolving(monkeypatch, tmp_path):
    # Un NOM D'HÔTE littéral est résolu puis contrôlé à l'exécution (modèle "résous + report").
    import orchestrator as orch
    import scope
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr(scope.socket, "gethostbyname",
                        lambda n: "203.0.113.9" if n == "evil.example.com" else (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("ne doit pas exécuter")))
    tech = Technique(id="op.h", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target} evil.example.com",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    wm.add_service("10.0.0.5", 445, name="smb")
    orch._MISSIONS["t_h"] = wm
    cfg = {"configurable": {"thread_id": "t_h"}}
    reports = orch.node_execute({"planned": plan_tasks(wm, orch._CATALOG), "rag_context": ""},
                                cfg)["execution_reports"]
    r = next(r for r in reports if r["technique"] == "op.h")
    assert r["status"] == "blocked_out_of_scope" and "evil.example.com" in r["detail"]


def test_node_integrate_marks_missing_input_tried(monkeypatch, tmp_path):
    # blocked_missing_input est marqué 'tried' (boucle-sûr : pas de replanification infinie).
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_mi"] = wm
    cfg = {"configurable": {"thread_id": "t_mi"}}
    reports = [{"technique": "llm.share", "host": "127.0.0.1", "service": "smb", "port": 445,
                "inputs_fp": "", "status": "blocked_missing_input", "detail": "manque {share}"}]
    orch.node_integrate({"planned": [], "execution_reports": reports, "cycle": 0}, cfg)
    assert wm.is_tried("127.0.0.1", "smb", "llm.share", inputs_fp="", port=445) is True


def test_blocked_no_netns_escalates_and_is_not_marked_tried(monkeypatch, tmp_path):
    # Périmètre réseau absent : la technique n'est PAS grillée (replanifiable après
    # `offense.netns up`), l'opérateur est prévenu, et le message d'erreur — qui cite
    # des adresses — n'alimente pas le modèle du monde.
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    wm = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    wm.add_service("10.0.0.5", 445, name="smb")
    orch._MISSIONS["t_nn"] = wm
    cfg = {"configurable": {"thread_id": "t_nn"}}
    reports = [{"technique": "op.n", "host": "10.0.0.5", "service": "smb", "port": 445,
                "inputs_fp": "", "status": "blocked_no_netns",
                "detail": "Le périmètre réseau installé (10.0.0.77) ne correspond pas"}]
    out = orch.node_integrate({"planned": [], "execution_reports": reports, "cycle": 0}, cfg)
    assert wm.is_tried("10.0.0.5", "smb", "op.n", inputs_fp="", port=445) is False
    assert out["netns_missing"] is True
    assert "sudo python -m offense.netns up" in out["final_response"]
    assert "10.0.0.77" not in wm.hosts


def test_no_netns_through_node_execute_then_integrate(monkeypatch, tmp_path):
    # Même contrat, de bout en bout : le statut de l'exécuteur traverse node_execute
    # tel quel, et node_integrate ne grille pas la technique.
    import orchestrator as orch
    from state import mission_io
    from catalog.loader import Technique
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    monkeypatch.setattr("offense.executor.execute_command",
                        lambda rendered, **kw: ("blocked_no_netns", "namespace absent"))
    tech = Technique(id="op.n", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target}",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_nn3"] = wm
    cfg = {"configurable": {"thread_id": "t_nn3"}}
    planned = plan_tasks(wm, orch._CATALOG)
    reports = orch.node_execute({"planned": planned, "rag_context": ""}, cfg)["execution_reports"]
    assert [r["status"] for r in reports if r["technique"] == "op.n"] == ["blocked_no_netns"]
    out = orch.node_integrate({"planned": planned, "execution_reports": reports, "cycle": 0}, cfg)
    assert out["netns_missing"] is True
    assert wm.is_tried("127.0.0.1", "smb", "op.n", inputs_fp="", port=445) is False
    assert plan_tasks(wm, orch._CATALOG)          # toujours replanifiable après `up`


def test_node_integrate_clears_netns_missing_when_nothing_blocked(monkeypatch, tmp_path):
    import orchestrator as orch
    from state import mission_io
    monkeypatch.setattr(mission_io, "MISSIONS_ROOT", tmp_path)
    wm = WorldModel(scope=Scope.from_lines(["10.0.0.0/24"]))
    orch._MISSIONS["t_nn2"] = wm
    out = orch.node_integrate({"planned": [], "execution_reports": [], "cycle": 0,
                               "netns_missing": True}, {"configurable": {"thread_id": "t_nn2"}})
    assert out["netns_missing"] is False


def _smb_exhausted(thread_id, monkeypatch):
    import orchestrator as orch
    # Catalogue builtin SEUL : ces tests portent sur l'épuisement des techniques
    # builtin du service, pas sur l'arsenal operator local (catalog/operator/*.yaml),
    # qui rendrait le résultat dépendant de la machine.
    monkeypatch.setattr(orch, "_CATALOG", load_catalog(operator_dir="catalog/__aucun__"))
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    for tid in ("smb.port_probe", "smb.enum_shares"):
        wm.mark_technique("127.0.0.1", "smb", tid, inputs_fp="", port=445)
    orch._MISSIONS[thread_id] = wm
    return wm


def test_route_continue_pour_laisser_l_auteur_traiter_un_service_epuise(monkeypatch):
    # Toutes les techniques builtin du service tentées : la mission doit repasser par
    # decide, où l'auteur LLM prend le relais — pas s'arrêter avant.
    import orchestrator as orch
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    _smb_exhausted("t_route_dry", monkeypatch)
    base = {"cycle": 1, "max_cycles": 6, "thread_id": "t_route_dry"}
    assert route_after_integrate(base) == "continue"
    # sans périmètre réseau, une technique LLM ne pourrait pas s'exécuter : fin
    assert route_after_integrate({**base, "netns_missing": True}) == "finish"


def test_auteur_une_seule_tentative_par_service(monkeypatch):
    # L'auteur ne propose rien d'utilisable : la tentative compte quand même, sinon la
    # boucle le rappellerait à chaque cycle jusqu'au cap.
    import orchestrator as orch
    import offense.catalog_author as author
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    monkeypatch.setattr(orch, "_rag_for_author", lambda svc, search=None: "")
    calls = []
    monkeypatch.setattr(author, "author_technique",
                        lambda svc, ctx, invoke: calls.append(svc) or None)
    _smb_exhausted("t_author_once", monkeypatch)
    cfg = {"configurable": {"thread_id": "t_author_once"}}
    orch.node_decide({"discovered_services": []}, cfg)
    orch.node_decide({"discovered_services": []}, cfg)
    assert calls == ["smb"]
    assert route_after_integrate({"cycle": 2, "max_cycles": 6,
                                  "thread_id": "t_author_once"}) == "finish"


def test_route_ne_boucle_pas_sur_une_technique_llm_en_propose_only(monkeypatch):
    import orchestrator as orch
    from catalog.loader import Technique
    tech = Technique(id="llm.x", name="x", domain="ad", service="smb", requires=set(),
                     tool="smbclient", command_template="smbclient -L //{target} -N",
                     success_signal="Sharename", provided_by="llm")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    wm.add_evidence({"kind": "llm_technique", "service": "smb", "id": "llm.x"})
    orch._MISSIONS["t_route_po"] = wm
    base = {"cycle": 1, "max_cycles": 6, "thread_id": "t_route_po"}
    assert route_after_integrate(base) == "continue"
    monkeypatch.setattr(orch, "_PROPOSE_ONLY", True)
    assert route_after_integrate(base) == "finish"      # proposée, jamais exécutée : pas de boucle


def test_route_finishes_when_only_netns_blocked_tasks_remain(monkeypatch):
    # Sans périmètre réseau, les techniques operator/llm ne sont pas exécutables :
    # la boucle ne tourne pas à vide jusqu'au cap de cycles.
    import orchestrator as orch
    from catalog.loader import Technique
    tech = Technique(id="op.n", name="n", domain="network", service="smb", requires=set(),
                     tool="nmap", command_template="nmap -sV {target}",
                     success_signal="open", provided_by="operator")
    monkeypatch.setattr(orch, "_CATALOG", [tech])
    monkeypatch.setattr(orch, "technique_available", lambda t: True)
    wm = WorldModel(scope=Scope.from_lines(["127.0.0.1/32"]))
    wm.add_service("127.0.0.1", 445, name="smb")
    orch._MISSIONS["t_route_netns"] = wm
    base = {"cycle": 1, "max_cycles": 6, "thread_id": "t_route_netns"}
    assert route_after_integrate(base) == "continue"
    assert route_after_integrate({**base, "netns_missing": True}) == "finish"


def test_netns_missing_is_a_declared_state_channel():
    # LangGraph n'accepte en sortie de nœud que les clés déclarées dans l'état.
    import orchestrator as orch
    assert "netns_missing" in orch.MissionState.__annotations__
