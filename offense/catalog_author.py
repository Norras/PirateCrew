"""Auteur de catalogue LLM borné : le LLM (injecté) propose une technique,
les garde-fous la valident, puis elle est persistée avec la mission."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

import yaml

from catalog.loader import Technique, _technique_from_dict
from offense.guardrails import (GuardrailError, _host_candidates, _host_kind,
                                 destructive_match, host_literals,
                                 shell_metachar, tokenize_argv)
from state.mission_io import mission_dir


def build_author_prompt(service: str, context: str) -> str:
    """Consigne contrainte : un seul objet JSON, gabarit sans métacaractères."""
    return (
        f"Propose UNE technique offensive pour le service « {service} », sur une "
        "cible autorisée et dans le périmètre.\n"
        f"État réel de la mission (tiens-en compte) :\n{context}\n\n"
        "Ne propose PAS une technique listée comme déjà tentée ci-dessus ; "
        "appuie-toi sur la version du service et sur les échecs observés.\n"
        "Réponds par exactement UN objet JSON, sans autre texte, avec les clés : "
        "id, name, domain, service, requires, tool, command_template, "
        "success_signal, opens_session.\n"
        "command_template DOIT utiliser les placeholders {target} (hôte) {port} "
        "{user} {password} (mot de passe en clair) {hash} (empreinte) {domain} "
        "{share} et JAMAIS de valeur littérale (IP, identifiant, mot de passe) : "
        "une technique à valeurs littérales n'est pas réutilisable.\n"
        "INTERDIT : métacaractères shell (; | & > < ` $) et toute action "
        "destructive (suppression, formatage, arrêt, déni de service)."
    )


def parse_technique(raw: str) -> dict | None:
    """Premier objet JSON complet de `raw` (prose/fences tolérées), sinon None."""
    if not isinstance(raw, str):
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw[raw.index("{"):])
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


# Détection d'un hôte FORGÉ par collage d'un placeholder à un littéral
# (`{target}.evil.com` → au rendu `10.0.0.5.evil.com`). Les accolades cassent la
# classification d'hôte, donc `host_literals(gabarit)` ne voit rien ; on substitue
# chaque placeholder par un label sentinelle, puis on relit les hôtes littéraux :
# tout hôte matérialisé AUTRE que la sentinelle nue (= le placeholder seul en
# position d'hôte, légitime) trahit un collage → évasion de périmètre au rendu.
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")
_TARGET_SENTINEL = "targetsentinelhost"              # {target} = seule place sanctionnée in-scope
_OTHER_SENTINEL = "othersentinelhost"                # tout AUTRE placeholder


def _materialized_host_literals(template: str) -> list[str]:
    """Hôtes RENDUS en position d'hôte qui ne sont PAS exactement {target}. Pur.

    Les accolades cassent la classification d'hôte, donc `host_literals(gabarit)` ne
    voit rien. On substitue {target} par une sentinelle et TOUT AUTRE placeholder par
    une sentinelle DISTINCTE, puis on relit les hôtes : tout hôte ≠ sentinelle {target}
    nue — placeholder frère en position d'hôte ({domain}/{share}/{user}@), ou {target}
    collé à un littéral / à un autre placeholder — trahit une position d'hôte non
    sanctionnée (évasion de périmètre au rendu). Seul {target} est garanti in-scope ;
    un placeholder NU hors position d'hôte (nmap {target} {domain}) reste un résiduel
    assumé, comme un token nu."""
    def _sub(m: "re.Match[str]") -> str:
        return _TARGET_SENTINEL if m.group(0) == "{target}" else _OTHER_SENTINEL
    subbed = _PLACEHOLDER_RE.sub(_sub, template)
    out: list[str] = []
    for cand, structured in _host_candidates(subbed):
        if _host_kind(cand, structured) is None:
            continue
        if cand == _TARGET_SENTINEL:                 # {target} seul en position d'hôte : OK
            continue
        if cand not in out:
            out.append(cand)
    return out


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _well_typed(d: dict) -> bool:
    """Types attendus des champs proposés par le LLM. Un champ mal typé (liste à
    la place d'une chaîne, id non hachable ou en forme de chemin…) rend la
    proposition inutilisable : elle est rejetée ici plutôt que de faire lever la
    planification plus tard, à chaque cycle."""
    if not isinstance(d.get("id"), str) or not _ID_RE.match(d["id"]):
        return False
    if not isinstance(d.get("command_template"), str) or not d["command_template"].strip():
        return False
    for key in ("name", "domain", "tool", "success_signal"):
        if d.get(key) is not None and not isinstance(d[key], str):
            return False
    requires = d.get("requires") or []
    if isinstance(requires, str):
        requires = [requires]
    if not isinstance(requires, list) or not all(isinstance(r, str) for r in requires):
        return False
    return isinstance(d.get("opens_session", False), bool)


def author_technique(service: str, context: str, llm_invoke) -> Technique | None:
    """Technique tagguée `llm` ou None si illisible / mal typée / gabarit refusé.
    Ne lève jamais : un appel LLM en échec ou une réponse inattendue vaut None."""
    try:
        d = parse_technique(llm_invoke(build_author_prompt(service, context)))
    except Exception:  # noqa: BLE001 - API indisponible, réponse sans .content… : pas de proposition
        return None
    if d is None or not _well_typed(d):
        return None
    d["service"] = service
    d["provided_by"] = "llm"
    try:
        tech = _technique_from_dict(d)
    except (KeyError, TypeError):
        return None
    # Garde-fous d'authoring (défense en profondeur, en plus du contrôle à
    # l'exécution) : pas de métacaractère/destructif ; la cible DOIT être le
    # placeholder {target} (jamais une valeur en dur) ; aucun autre hôte/IP
    # littéral (un second hôte littéral = évasion de périmètre à l'exécution).
    tpl = tech.command_template or ""
    reject = None
    if shell_metachar(tpl) or destructive_match(tpl):
        reject = "métacaractère shell ou action destructive"
    elif "{target}" not in tpl:
        reject = "gabarit sans placeholder {target} (cible non garantie in-scope)"
    elif host_literals(tpl):
        reject = f"hôte/IP littéral interdit : {', '.join(host_literals(tpl))}"
    else:
        glued = _materialized_host_literals(tpl)
        if glued:                                     # {target}.evil.com → hôte forgé au rendu
            reject = ("placeholder collé à un hôte littéral (hôte forgé au rendu, "
                      f"évasion de périmètre) : {', '.join(glued)}")
    if reject:
        try:
            from tools.registry import _audit
            _audit("LLM_TECH_REJECTED", f"{tech.id}: {reject}: {tpl}")
        except Exception:
            pass
        return None
    return tech


def persist_llm_technique(tech: Technique, mission_id: str, root=None) -> Path:
    """Ajoute `tech` à missions/<id>/llm_catalog.yaml (relisible par le loader)."""
    d = mission_dir(mission_id, root)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "llm_catalog.yaml"
    entries = []
    if path.exists():
        entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    entry = asdict(tech)
    entry["requires"] = sorted(tech.requires)
    entries.append(entry)
    path.write_text(yaml.safe_dump(entries, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    return path


_IP_LITERAL = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"                      # IPv4
    r"|::[0-9A-Fa-f]{0,4}"                               # IPv6 compressé (::1, fe80::1)
    r"|(?:[0-9A-Fa-f]{1,4}:){4,}[0-9A-Fa-f]{0,4}"        # IPv6 non compressé / MAC (>=4 groupes)
)
# La branche `::` sur-rejette un `::` isolé non-IP (ex. PowerShell [Ns]::Methode,
# pwdump `user:::`) : sur-rejection ASSUMÉE (fail-safe). Resserrer risquerait un
# faux NÉGATIF sur une vraie IPv6 — un trou, lui. On préfère sur-rejeter.

# Jeton à forte entropie : empreinte/hash/clé/token probable. Volontairement
# large (fail-closed) : hex >=16, ou base64 >=20 (couvre une clé de 16 octets,
# ~22 car.). On n'inclut PAS `_`/`-` dans la classe base64 : ils joignent des
# identifiants normaux (ex. NT_STATUS_LOGON_FAILURE) et provoqueraient un
# sur-masquage / sur-rejet. base64url strict non couvert → résiduel assumé.
_HIGH_ENTROPY = re.compile(r"\b[0-9A-Fa-f]{16,}\b|[A-Za-z0-9+/]{20,}={0,2}")

# Flags portant une valeur de credential : leur valeur DOIT être un {placeholder}
# (un nombre est toléré : un port n'est pas un secret). Les formes courtes
# `-p`/`-u` servent aussi de port/URL — `-H` (en-tête ou hash) est EXCLU car un
# vrai hash est déjà capté par l'entropie, ce qui évite de rejeter `curl -H ...`.
_CRED_FLAGS = frozenset({"-p", "--password", "--pass", "-passwd", "-pw",
                         "-hashes", "--hashes", "--hash",
                         "-u", "--user", "--username"})


def _carries_target_data(text: str, forbidden) -> bool:
    """Vrai si `text` porte une donnée de cible : IP littérale, jeton à forte
    entropie (hash/clé/token), ou une chaîne interdite (secret/principal connu,
    comparaison insensible à la casse). Fail-closed : en cas de doute, True."""
    if _IP_LITERAL.search(text) or _HIGH_ENTROPY.search(text):
        return True
    low = text.lower()
    return any(bad and len(bad) >= 3 and bad.lower() in low for bad in forbidden)


def _flag_value_is_literal(template: str) -> bool:
    """Vrai si un flag porteur de credential est suivi d'une valeur LITTÉRALE
    (ni {placeholder} ni nombre/port) — gabarit spécifique à la mission."""
    try:
        argv = tokenize_argv(template)
    except GuardrailError:
        return True  # non tokenisable → fail-closed
    for i in range(len(argv) - 1):
        val = argv[i + 1]
        if argv[i] in _CRED_FLAGS and "{" not in val and not val.isdigit():
            return True
    return False


def _rag_candidate(t, forbidden) -> dict | None:
    """Ce qui serait stocké pour `t` ({id, text, metadata}), ou None si le filtre
    l'écarte. Peut lever sur une technique mal formée (géré par l'appelant)."""
    reqs = ", ".join(sorted(t.requires)) if t.requires else "aucun"
    text = (
        f"Technique « {t.name} » pour le service {t.service} "
        f"(outil {t.tool or '?'}). Commande : {t.command_template}. "
        f"Signal de succès : {t.success_signal or '?'}. Prérequis : {reqs}. "
        f"Ouvre une session : {t.opens_session}. Source : auteur LLM."
    )
    meta = {"source": "llm_authored", "service": t.service,
            "technique_id": t.id, "tool": t.tool or ""}
    # Scan de TOUT le contenu persisté (page_content + metadata), pas d'un
    # sous-ensemble de champs.
    scanned = text + " " + " ".join(str(v) for v in meta.values())
    if _carries_target_data(scanned, forbidden) or _flag_value_is_literal(t.command_template):
        return None  # spécifique à la mission → jamais dans le RAG partagé
    digest = hashlib.sha1(
        f"{t.service}|{t.command_template}".encode("utf-8")).hexdigest()[:16]
    return {"id": f"llm:{digest}", "text": text, "metadata": meta}


def rag_candidates(techniques, forbidden=()) -> list[dict]:
    """Candidats à la promotion RAG : `[{id, text, metadata}]`, exactement ce qui
    serait écrit. N'écrit rien.

    Filtre de PRÉ-TRI, pas une garantie : est écartée toute technique dont le
    contenu porte une IP littérale, un jeton à forte entropie (hash/clé/token),
    une chaîne de `forbidden` (secrets, principals, noms d'hôte connus —
    insensible à la casse), ou une valeur LITTÉRALE après un flag de credential.
    Il ne reconnaît PAS toute donnée de cible : nom ou identifiant vu dans une
    sortie d'outil mais absent de `forbidden`, valeur de moins de 3 caractères,
    forme encodée, valeur attachée (--user=…), userinfo d'URL, argument
    positionnel. La garantie est l'accord de l'opérateur, qui relit ces textes
    avant écriture (commande « promote » du REPL).

    Une technique mal formée (champ non textuel…) est écartée seule, sans lever
    ni faire perdre le lot ; deux techniques de même (service, gabarit) ne
    donnent qu'un candidat (id stable = hash(service|gabarit) → upsert idempotent).
    """
    forbidden = [f for f in forbidden if isinstance(f, str)]
    out: list[dict] = []
    seen: set[str] = set()
    for t in techniques or []:
        try:
            cand = _rag_candidate(t, forbidden)
        except Exception:  # noqa: BLE001 - fail-closed par technique : écartée, jamais écrite
            cand = None
        if cand is None or cand["id"] in seen:
            continue
        seen.add(cand["id"])
        out.append(cand)
    return out


def store_candidates(candidates, store=None) -> int:
    """Écrit des candidats (issus de `rag_candidates`) dans le RAG partagé, en un
    appel. `store=None` → import paresseux du vectorstore. Renvoie le nombre écrit."""
    if not candidates:
        return 0
    if store is None:
        from agents.pirate_agent import vectorstore as store  # import paresseux
    store.add_texts([c["text"] for c in candidates],
                    metadatas=[c["metadata"] for c in candidates],
                    ids=[c["id"] for c in candidates])
    return len(candidates)


def promote_techniques_to_rag(techniques, mission_id: str, forbidden=(), store=None) -> int:
    """Filtre (`rag_candidates`) puis écrit (`store_candidates`) en une fois.
    `mission_id` est accepté mais volontairement ABSENT de ce qui est stocké (il
    contient l'IP cible). Renvoie le nombre promu.

    Le REPL ne l'appelle plus en fin de mission : il passe par `rag_candidates`,
    montre les textes à l'opérateur et n'écrit que sur son ordre."""
    return store_candidates(rag_candidates(techniques, forbidden), store=store)
