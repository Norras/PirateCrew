# 🏴‍☠️ PirateCrew

**Multi-agent orchestration** platform (Python / LangGraph) for running **authorized
security audits** autonomously and traceably. A **fail-closed** authorization scope sits
at the heart of the architecture.

> ⚠️ **Authorized use only.** PirateCrew only acts on targets from an allowlist
> (`scope.txt`) that you **own** or have **explicit permission** to test (training lab,
> personal VM, agreed audit scope). Without a valid scope, **no mission starts**. You are
> solely responsible for how you use it.

---

## Table of contents
- [What it is](#what-it-is)
- [Security (fail-closed)](#security-fail-closed)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running](#running)
- [How it works](#how-it-works)
- [Tools & catalog](#tools--catalog)
- [Recommended environment (Kali)](#recommended-environment-kali)
- [Tests](#tests)
- [Project structure](#project-structure)
- [Project status](#project-status)
- [License](#license)

---

## What it is

A stateful orchestrator that coordinates several specialized LLM agents:

- a **master supervisor** routes each request to the right strategy: autonomous
  mission, knowledge base (RAG), code analysis, or direct answer;
- an **autonomous mission** runs a **bounded** loop *recon → decision →
  execution → integration* (guaranteed to stop: cycle cap + task exhaustion);
- a shared **world model** (`WorldModel`) centralizes hosts, services,
  credentials, sessions, evidence and the **ledger of techniques already attempted**;
- a **pluggable YAML catalog** describes techniques declaratively;
- a **RAG knowledge base** (Chroma + embeddings) enriches the reasoning.

Agents are built on the fly (*factory* pattern) and only receive the tools of their
domain, plus the mandatory tools (audit + scope check).

## Security (fail-closed)

- No valid `scope.txt` → the mission **refuses to start**. No default action.
- **Single checkpoint**: every target, whatever the tool, goes through
  `_validate_target` → `assert_in_scope` (syntactic filter + scope membership).
  No tool can touch a target outside the allowlist.
- The **IP validated** by the scope is contacted, never a re-resolved name
  (protection against DNS hijacking).
- Every action is timestamped in `audit.log`: scope, recon, planning decision,
  technique execution (`EXEC`) and findings (`FINDING`). Line breaks are neutralized
  there (protection against forged log lines). **`audit.log` never contains a
  secret**: no password, no rendered command, no loot content - only structural fields
  (technique, host, port, service, principal, status).

### Network scope (offensive path)

The `operator` and `llm` techniques are command templates: no check on the *text* of a
command can reliably tell where the tool will connect (decimal IP, hexadecimal, trailing
dot, twisted URL...). For this path, it is therefore the **kernel** that enforces the
scope: the command runs in a *network namespace* (`pc-offense`) whose only exit is
filtered by nftables on the IPs of `scope.txt`. How the host is written no longer
matters.

```bash
sudo python -m offense.netns up            # re-run after any change to scope.txt
sudo python -m offense.netns up --dns IP   # same, with an in-scope resolver (e.g. a DC)
python -m offense.netns status             # what the kernel actually allows
sudo python -m offense.netns down
```

- **Fail-closed, no bypass**: if the namespace is missing, or if the kernel set is not
  exactly the active scope, the technique is not executed (`blocked_no_netns`), is not
  "burned" in the ledger, and the operator is warned. Recon and the builtin tools stay
  usable (they already contact the validated IP).
- **Linux only, root for setup.** `up` installs a helper script
  (`/usr/local/sbin/pc-netns-exec`) and a sudoers rule limited to that script; the command
  then runs with **your** privileges, not as root. `up` enables
  `net.ipv4.ip_forward`, which `down` does not reset.
- **DNS closed by default** in the namespace (`/etc/hosts` stays visible); services of the
  machine itself (loopback, local IPs) are unreachable; IPv6 is disabled.
- **A `127.0.0.1` scope is therefore unreachable through this path**: inside the namespace,
  the loopback is the namespace's own, and it is empty. `up` and the mission gate announce
  it (`[NETNS] Warning: ...`). Recon and the builtin tools, for their part, still reach
  `127.0.0.1`. For a local lab, give the target its own address - see
  [Local lab](#local-lab) below.
- The internal host ↔ namespace link uses `100.127.77.0/30` (carrier-grade shared range,
  outside the private ranges): only a scope that overlaps this range is rejected.

#### Local lab

To practise on a service running on the machine itself, start it in a second
namespace (`pc-lab`) that has its own address, `192.0.2.2` (documentation range, never
routed on the Internet):

```bash
sudo python -m offense.lab up                                   # creates the 192.0.2.2 target
sudo python -m offense.lab run -- python3 -m http.server 8000   # your service, in the foreground
# in scope.txt: 192.0.2.2   then: sudo python -m offense.netns up
sudo python -m offense.lab down
```

`run` starts the command with **your** privileges; Ctrl-C stops it. Recon (from the
machine) and the offensive path (from `pc-offense`, through the filter) both reach
`192.0.2.2`; the machine's local services stay out of reach of the offensive path. The lab
only separates the service's network, not its files.

##### Stocked lab (ready to use)

`lab/start.sh` brings up the target and runs **two services filled with fictional data**
on it: an HTTP intranet (port 80) and an SMB file server (port 445), all in the foreground
(Ctrl-C stops and tears everything down):

```bash
sudo bash lab/start.sh
# then, in another terminal: 192.0.2.2 in scope.txt, then sudo python -m offense.netns up
```

The intranet leaves lying around the password of a service account that opens a protected
SMB share (`archives`, denied anonymously). For the "password found → share access" chain to
run deterministically, copy the provided `operator` template (the `operator` arsenal stays
local, not versioned):

```bash
cp lab/operator-smb.yaml catalog/operator/smb.yaml
```

A `scan and enumerate 192.0.2.2` mission then chains: recon → reading the intranet →
retrieving the password → authenticated listing of the `archives` share.

Known limitations:

- pivoting through an in-scope host (`curl -x` to a proxy inside the scope);
- local reads (`curl file://...`) - that is not networking;
- inbound connections to the namespace (reverse shell: would need a DNAT);
- IPv6 scope not enforced (IPv4 only);
- raw-socket scans as non-root (`nmap -sS`): set `setcap cap_net_raw+ep` on nmap;
- the namespace confines the **network** of the processes it starts, not their other ways
  of talking to an outside process: path-based Unix sockets (`docker.sock`, ssh
  ControlMaster, tmux server, `systemd-run --user`). The command runs as the same user as
  PirateCrew;
- under WSL2, Windows interop (`curl.exe`, `powershell.exe`... which would run on the
  Windows side, outside the filter) is **masked** in the namespace - verified by the
  integration tests; it stays active everywhere else;
- `sudo` logs every rendered command, credentials included, in the system journal;
- a command **already running** is no longer filtered if the nftables table is deleted by
  hand (`down` cuts the link first; subsequent commands are refused, including if the rules
  are merely flushed or if the namespace has disappeared);
- another firewall with `DROP` on transit (Docker, iptables `FORWARD`) can block in-scope
  targets: the symptom is a timeout, not a leak.

## Prerequisites

- **Python 3.11+** (tested on 3.13)
- An **Anthropic API key**
- *(recommended)* a Linux environment with the pentest tools - see
  [Recommended environment (Kali)](#recommended-environment-kali)

## Installation

```bash
python -m venv venv
# Windows:         venv\Scripts\activate
# Linux / Kali:    source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file at the root with your API key:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Define the **authorized scope** from the provided example:

```bash
cp scope.txt.example scope.txt      # Windows: copy scope.txt.example scope.txt
```

`scope.txt` contains **one IP or CIDR per line**, e.g.:

```
10.10.10.0/24
127.0.0.1/32
```

## Running

```bash
python orchestrator.py
```

Then, in natural language:

```
You > scan and enumerate 10.10.10.5
```

The supervisor recognizes an autonomous mission, loads the scope, then runs the
loop. The final answer summarizes the findings (hosts, services, credentials...) and
**flags any missing tool** to install.

Prompt commands (in addition to natural language):

| Command | Effect |
|---|---|
| `verbose [on\|off]` | detailed diagnostics (also: `PIRATECREW_VERBOSE=1`) |
| `propose-only [on\|off]` | techniques written by the LLM author are shown, not executed |
| `sessions` | sessions obtained during the last mission, authorized or pending |
| `authorize <host>` | authorizes this host's pending sessions and resumes the mission |
| `promote` | adds the LLM techniques proposed at the end of the mission to the shared RAG |
| `exit` / `quit` | quit |

Nothing is written to the shared RAG by default: at the end of a mission, the techniques
written by the LLM author are **displayed** as they would be stored, and only the
`promote` command adds them. The automatic filter (secrets, known credentials and host
names, IPs, high-entropy tokens) is only a pre-screen: review before promoting.

Detailed results are in `missions/<id>/report.md` (readable report) and
`missions/<id>/world.json` (full state, rewritten at every cycle).

> ⚠️ **Secrets at rest.** PirateCrew harvests and reuses credentials: by design,
> `report.md` and `world.json` contain the secrets found **in clear text**
> (credentials, rendered commands, tool output). This is inherent to a pentest
> orchestrator, not a leak. The `missions/` folder is gitignored (never versioned);
> on a shared machine, restrict it (`chmod 700 missions/`). If you want no secret at
> rest, do not run techniques that use a credential, or purge
> `missions/` after exploitation. `audit.log`, for its part, never contains any (see
> [Security](#security-fail-closed)).

## How it works

```
request ──► master supervisor
               ├─ autonomous mission ──► enter (fail-closed scope)
               │                         └─► recon ─► decide ─► execute ─► integrate ─┐
               │                                        ▲                             │
               │                                        └──────── continue ◄──────────┘
               │                                                 (otherwise: end)
               ├─ knowledge base (RAG)
               ├─ code analysis
               └─ direct answer
```

- **recon**: scan of common ports / nmap if available; open services are
  fed back into the `WorldModel`.
- **decide**: for each (in-scope host, service), plans the catalog techniques
  whose prerequisites are met and that have not already been attempted (ledger).
- **execute**: one agent per task runs the technique through its tools; findings
  are reported in a structured way (`report_finding`).
- **integrate**: updates the ledger, extracts findings from the raw text, and decides
  whether to continue or finish.

## Tools & catalog

Agents only call **declared tools** (`@tool`), all subject to the scope check. Tools by
domain:

| Domain         | Tools                               |
|----------------|-------------------------------------|
| `network`      | `nmap_scan`, `tcp_port_check`       |
| `web`          | `http_fingerprint`, `http_get`      |
| `ad`           | `smb_port_probe`, `smb_list_shares` |
| *mandatory*    | `log_audit_event`, `scope_check`    |
| *+*            | `report_finding` (bound to the `WorldModel`) |

The **catalog** describes techniques declaratively: `catalog/builtin/` (provided)
and `catalog/operator/` (local, not versioned - templates to fill in, see
`catalog/operator.example.yaml`).

### Adding a tool

1. **Write** the `@tool` function in `tools/registry.py`: validate the target via
   `_validate_target(...)`, log via `_audit(...)`, and **never raise**
   (return a message on failure).
2. **Declare** the tool in `TOOL_CATALOG[domain]` (or `MANDATORY_TOOLS`).
3. **Describe** a technique in the catalog (`catalog/builtin/*.yaml`): `service`, `tool`,
   `command_template` (placeholders `{target}` / `{port}`), `success_signal`.

> *"Having the tool" (step 2) and "being tasked with using it" (step 3) are distinct.*

### Missing tool (escalation)

If a technique requires an **external binary that is absent** (checked with `shutil.which`),
the mission does not run it: it **flags** it ("install `smbclient`"), does not "burn" it
in the ledger, and **resumes** it automatically after installation + relaunch of the
mission. The human stays in control of the installed capabilities.

## Recommended environment (Kali)

On Windows, the easiest way to get a real arsenal (`nmap`, `smbclient`,
`gobuster`...) is to run PirateCrew in **WSL2 Kali**. The agents then detect and
use the binaries that are present; missing ones are flagged (see above).

This is also where the [network scope](#network-scope-offensive-path)
(namespaces + nftables, verified on the WSL2 kernel) works: without it, the
`operator`/`llm` techniques do not run.

## Tests

```bash
pytest -q
```

Integration proof of the network scope (Linux, root - creates two local namespaces,
nothing leaves the machine):

```bash
sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_netns_integration.py tests/test_netns_round3_replay.py -v
```

`test_netns_round3_replay.py` replays, with the real tools (`curl`, `sqlmap`, `ffuf`, `wfuzz`,
`scp`, `rsync`, `nmap`, `smbclient`, `ssh`), the text-check bypasses confirmed by
the adversarial review of 2026-11-18: no packet reaches the out-of-scope target, and the
filter does count the packets each tool tried to send.

> On Windows, the **first** run can take a few minutes: the antivirus
> scans the `langchain` imports at load time. The tests make **no** real LLM
> or network call.

## Project structure

```
orchestrator.py        # master loop + autonomous mission + CLI
scope.py               # fail-closed scope + audit log
state/world_model.py   # shared world model (hosts, services, creds, ledger...)
agents/
  dynamic_agent.py     # intervention agent factory
  pirate_agent.py      # RAG agent (knowledge base)
  analyst_agent.py     # code analysis agent
tools/registry.py      # @tool tools (network / web / ad) + scope chokepoint
offense/
  guardrails.py        # text guardrails (shell, destructive, best-effort scope)
  executor.py          # deterministic executor for operator/llm templates
  netns.py             # kernel-enforced scope (namespace + nftables)
catalog/
  builtin/             # provided techniques (recon / web / smb)
  operator/            # operator's local techniques (not versioned)
tests/                 # pytest suite
scripts/               # one-off utilities (RAG database inspection)
```

## Project status

**Functional prototype covered by tests** (282 passing tests), not yet hardened
for production. Depends on an LLM API key and, for the full scan, on optional system
tools (pure-Python fallback otherwise).

## License

MIT - see [LICENSE](LICENSE).
