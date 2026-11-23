"""Shared world model of a PirateCrew mission.

Central object of a mission: what is known (hosts, services), found
(credentials, loot, sessions, evidence) and attempted (technique ledger).
The orchestrator reads it to decide the next action; the executing agents
write their findings into it in a structured way.

Pure data model + helpers: no network action, no payload. The authorization
scope lives in `scope`; this module only CLASSIFIES hosts (in_scope /
off-list) and never imports the `tools` package (`tools.registry` imports
`state` downstream — the reverse would be circular).
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
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
    channel: str  # e.g. evil-winrm, meterpreter, ssh
    via_cred: str | None = None
    alive: bool = True
    handle: str = ""
    authorized: bool = False  # session obtained through an explicitly authorized action


def inputs_fingerprint(inputs: dict) -> str:
    """Stable fingerprint of the inputs actually used by a technique.

    '' when there are no inputs. Used to KEY the ledger: the same technique
    re-run with different inputs (e.g. a newly found cred) reads as "not
    tried" and therefore becomes executable again.
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

    def to_dict(self) -> dict:
        """JSON-serializable snapshot of the model (secrets in clear).

        The ledger, keyed by tuple, becomes a list of named entries.
        """
        return {
            "hosts": {ip: asdict(h) for ip, h in self.hosts.items()},
            "credentials": [asdict(c) for c in self.credentials],
            "loot": list(self.loot),
            "sessions": [asdict(s) for s in self.sessions],
            "evidence": list(self.evidence),
            "technique_ledger": [
                {"host": h, "service": svc, "technique": t,
                 "inputs_fp": fp, "port": port, "status": status}
                for (h, svc, t, fp, port), status in self.technique_ledger.items()
            ],
        }

    # ------------------------------------------------------------------ #
    # Hosts / services
    # ------------------------------------------------------------------ #
    def add_host(self, ip: str, hostname: str | None = None) -> Host:
        """Register a host, classified via `scope.contains` (never raises).

        An out-of-scope host is still stored with `in_scope=False` (the flag
        IS the trace) but excluded from `in_scope_hosts()`: it will never be
        tasked. The refusal is also traced in the audit.
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
                # Dedup by (port, proto), but enrich a service first seen
                # anonymously: an initial name='' would make it invisible to the
                # planner (plan_tasks filters on svc.name) — a silent loss.
                if name and not existing.name:
                    existing.name = name
                if version and not existing.version:
                    existing.version = version
                return existing
        svc = Service(host=host, port=port, proto=proto, name=name, version=version)
        h.services.append(svc)
        return svc

    # ------------------------------------------------------------------ #
    # Findings
    # ------------------------------------------------------------------ #
    def add_credential(self, cred: Credential) -> Credential:
        scope.register_secret(cred.secret)  # redacted from every future audit line
        key = (cred.kind, cred.principal, cred.secret)
        for c in self.credentials:
            if (c.kind, c.principal, c.secret) == key:
                return c
        self.credentials.append(cred)
        return cred

    def add_session(self, sess: Session) -> Session:
        """Add a session, deduplicated by (host, channel): an existing session
        is refreshed (alive/handle/via_cred) and keeps its `authorized`."""
        for s in self.sessions:
            if s.host == sess.host and s.channel == sess.channel:
                s.alive = sess.alive
                s.handle = sess.handle
                s.via_cred = sess.via_cred
                return s
        self.sessions.append(sess)
        return sess

    def add_loot(self, item: dict) -> None:
        self.loot.append(item)

    def add_evidence(self, item: dict) -> None:
        self.evidence.append(item)

    def creds_applicable(self, service: str) -> list[Credential]:
        """Credentials usable on `service`: those with no known target
        (empty `works_on`) or explicitly marked for this service."""
        return [c for c in self.credentials if not c.works_on or service in c.works_on]

    # ------------------------------------------------------------------ #
    # Ledger of attempted techniques (keyed by inputs, see inputs_fingerprint)
    # ------------------------------------------------------------------ #
    def mark_technique(self, host: str, service: str, tech_id: str,
                       inputs_fp: str = "", status: str = "tried", port: int = 0) -> None:
        self.technique_ledger[(host, service, tech_id, inputs_fp, port)] = status

    def is_tried(self, host: str, service: str, tech_id: str,
                 inputs_fp: str = "", port: int = 0) -> bool:
        return (host, service, tech_id, inputs_fp, port) in self.technique_ledger

    # ------------------------------------------------------------------ #
    # Views
    # ------------------------------------------------------------------ #
    def in_scope_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.in_scope]

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #
    @staticmethod
    def _trace_out_of_scope(ip: str) -> None:
        """Best-effort trace of an out-of-scope host in the shared audit log.

        Writes to `scope.AUDIT_LOG`, read at call time (tests redirect it to a
        tmp file), same format as the other audit lines. Never raises: a
        failed trace must not break the registration.
        """
        try:
            line = f"{datetime.now().isoformat(timespec='seconds')} | OUT_OF_SCOPE | {scope._audit_escape(ip)}\n"
            with open(scope.AUDIT_LOG, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass
