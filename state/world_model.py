"""Modèle du terrain partagé d'une mission PirateCrew.

Objet central d'une mission : ce qui est connu (hôtes, services), trouvé
(credentials, butin, sessions, preuves) et tenté (ledger des techniques).
L'orchestrateur le lit pour décider de l'action suivante ; les agents
exécutants y écrivent leurs trouvailles de façon structurée.

Pur modèle de données + helpers : aucune action réseau, aucun payload. Le
périmètre d'autorisation vit dans `scope` ; ce module ne fait que CLASSER les
hôtes (in_scope / hors-liste) et n'importe jamais le paquet `tools`
(`tools.registry` importe `state` en aval — l'inverse serait circulaire).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

import scope


@dataclass
class Service:
    host: str
    port: int
    proto: str = "tcp"
    name: str = ""
    version: str | None = None


@dataclass
class Host:
    ip: str
    hostname: str | None = None
    in_scope: bool = True
    services: list[Service] = field(default_factory=list)


@dataclass
class Credential:
    kind: str  # password | hash | ticket | key
    principal: str
    secret: str
    source: str = ""
    works_on: list[str] = field(default_factory=list)


@dataclass
class Session:
    host: str
    channel: str  # ex. evil-winrm, meterpreter, ssh
    via_cred: str | None = None
    alive: bool = True
    handle: str = ""


def inputs_fingerprint(inputs: dict) -> str:
    """Empreinte stable des entrées réellement utilisées par une technique.

    '' quand il n'y a aucune entrée. Sert à CLÉFER le ledger : une même
    technique relancée avec des entrées différentes (ex. un cred nouvellement
    trouvé) lit comme « non tentée » et redevient donc exécutable.
    """
    if not inputs:
        return ""
    return hashlib.sha1(repr(sorted(inputs.items())).encode()).hexdigest()[:12]


@dataclass
class WorldModel:
    scope: "scope.Scope"
    hosts: dict[str, Host] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    loot: list[dict] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    technique_ledger: dict[tuple[str, str, str, str, int], str] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Hôtes / services
    # ------------------------------------------------------------------ #
    def add_host(self, ip: str, hostname: str | None = None) -> Host:
        """Enregistre un hôte, classé via `scope.contains` (ne lève jamais).

        Un hôte hors-périmètre est tout de même stocké avec `in_scope=False`
        (le drapeau EST la trace) mais exclu de `in_scope_hosts()` : il ne
        sera jamais tâché. Le refus est aussi tracé dans l'audit.
        """
        in_scope = self.scope.contains(ip)
        host = self.hosts.get(ip)
        if host is None:
            host = Host(ip=ip, hostname=hostname, in_scope=in_scope)
            self.hosts[ip] = host
        else:
            host.in_scope = in_scope
            if hostname:
                host.hostname = hostname
        if not in_scope:
            self._trace_out_of_scope(ip)
        return host

    def add_service(self, host: str, port: int, name: str = "",
                    proto: str = "tcp", version: str | None = None) -> Service:
        h = self.hosts.get(host) or self.add_host(host)
        for existing in h.services:
            if existing.port == port and existing.proto == proto:
                # Dédup par (port, proto), mais on enrichit un service d'abord vu
                # anonymement : un name='' initial le rendrait invisible au
                # planificateur (plan_tasks filtre sur svc.name) — perte silencieuse.
                if name and not existing.name:
                    existing.name = name
                if version and not existing.version:
                    existing.version = version
                return existing
        svc = Service(host=host, port=port, proto=proto, name=name, version=version)
        h.services.append(svc)
        return svc

    # ------------------------------------------------------------------ #
    # Trouvailles
    # ------------------------------------------------------------------ #
    def add_credential(self, cred: Credential) -> Credential:
        key = (cred.kind, cred.principal, cred.secret)
        for c in self.credentials:
            if (c.kind, c.principal, c.secret) == key:
                return c
        self.credentials.append(cred)
        return cred

    def add_session(self, sess: Session) -> Session:
        self.sessions.append(sess)
        return sess

    def add_loot(self, item: dict) -> None:
        self.loot.append(item)

    def add_evidence(self, item: dict) -> None:
        self.evidence.append(item)

    def creds_applicable(self, service: str) -> list[Credential]:
        """Credentials utilisables sur `service` : ceux sans cible connue
        (`works_on` vide) ou explicitement marqués pour ce service."""
        return [c for c in self.credentials if not c.works_on or service in c.works_on]

    # ------------------------------------------------------------------ #
    # Ledger des techniques tentées (clé par entrées, cf. inputs_fingerprint)
    # ------------------------------------------------------------------ #
    def mark_technique(self, host: str, service: str, tech_id: str,
                       inputs_fp: str = "", status: str = "tried", port: int = 0) -> None:
        self.technique_ledger[(host, service, tech_id, inputs_fp, port)] = status

    def is_tried(self, host: str, service: str, tech_id: str,
                 inputs_fp: str = "", port: int = 0) -> bool:
        return (host, service, tech_id, inputs_fp, port) in self.technique_ledger

    # ------------------------------------------------------------------ #
    # Vues
    # ------------------------------------------------------------------ #
    def in_scope_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.in_scope]

    # ------------------------------------------------------------------ #
    # Interne
    # ------------------------------------------------------------------ #
    @staticmethod
    def _trace_out_of_scope(ip: str) -> None:
        """Trace best-effort d'un hôte hors-périmètre dans l'audit partagé.

        Écrit vers `scope.AUDIT_LOG` lu à l'appel (les tests le redirigent
        vers un tmp), même format que les autres lignes d'audit. Ne lève
        jamais : une trace ratée ne doit pas casser l'enregistrement.
        """
        try:
            line = f"{datetime.now().isoformat(timespec='seconds')} | OUT_OF_SCOPE | {scope._audit_escape(ip)}\n"
            with open(scope.AUDIT_LOG, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass
