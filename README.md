# 🏴‍☠️ PirateCrew

Plateforme d'**orchestration multi-agents** (Python / LangGraph) pour conduire des
**audits de sécurité autorisés** de façon autonome et traçable. Un périmètre
d'autorisation **fail-closed** est au cœur de l'architecture.

> ⚠️ **Usage strictement autorisé.** PirateCrew n'agit que sur les cibles d'une liste
> blanche (`scope.txt`) que vous **possédez** ou avez le **droit explicite** de tester
> (lab d'entraînement, VM perso, périmètre d'audit consenti). Sans périmètre valide,
> **aucune mission ne démarre**. Vous êtes seul responsable de l'usage que vous en faites.

---

## Sommaire
- [Ce que c'est](#ce-que-cest)
- [Sécurité (fail-closed)](#sécurité-fail-closed)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Lancement](#lancement)
- [Comment ça marche](#comment-ça-marche)
- [Outils & catalogue](#outils--catalogue)
- [Environnement recommandé (Kali)](#environnement-recommandé-kali)
- [Tests](#tests)
- [Structure du projet](#structure-du-projet)
- [État du projet](#état-du-projet)

---

## Ce que c'est

Un orchestrateur à état qui coordonne plusieurs agents LLM spécialisés :

- un **superviseur maître** route chaque requête vers la bonne stratégie : mission
  autonome, base de connaissances (RAG), analyse de code, ou réponse directe ;
- une **mission autonome** déroule une boucle **bornée** *reconnaissance → décision →
  exécution → intégration* (arrêt garanti : plafond de cycles + épuisement des tâches) ;
- un **modèle du terrain** partagé (`WorldModel`) centralise hôtes, services,
  identifiants, sessions, preuves et le **registre des techniques déjà tentées** ;
- un **catalogue YAML enfichable** décrit les techniques de façon déclarative ;
- une **base de connaissances RAG** (Chroma + embeddings) enrichit le raisonnement.

Les agents sont construits à la volée (pattern *factory*) et ne reçoivent que les
outils de leur domaine, plus les outils obligatoires (audit + vérification de périmètre).

## Sécurité (fail-closed)

- Pas de `scope.txt` valide → la mission **refuse de démarrer**. Aucune action par défaut.
- **Point de contrôle unique** : toute cible, quel que soit l'outil, passe par
  `_validate_target` → `assert_in_scope` (filtre syntaxique + appartenance au périmètre).
  Aucun outil ne peut toucher une cible hors de la liste blanche.
- On contacte l'**IP validée** par le périmètre, jamais un nom ré-résolu
  (protection contre le détournement DNS).
- Chaque action est horodatée dans `audit.log` : périmètre, recon, décision de
  planification, exécution de technique (`EXEC`) et trouvailles (`FINDING`). Les sauts
  de ligne y sont neutralisés (anti-forge de fausses lignes). **`audit.log` ne contient
  jamais de secret** : ni mot de passe, ni commande rendue, ni contenu de butin — seuls
  des champs structurels (technique, hôte, port, service, principal, statut).

### Périmètre réseau (chemin offensif)

Les techniques `operator` et `llm` sont des gabarits de commande : aucun contrôle sur le
*texte* d'une commande ne peut dire de façon fiable où l'outil va se connecter (IP décimale,
hexadécimale, point final, URL tordue…). Pour ce chemin, c'est donc le **noyau** qui applique
le périmètre : la commande s'exécute dans un *network namespace* (`pc-offense`) dont la seule
sortie est filtrée par nftables sur les IP de `scope.txt`. L'écriture de l'hôte n'a plus
d'importance.

```bash
sudo python -m offense.netns up            # à relancer après toute modification de scope.txt
sudo python -m offense.netns up --dns IP   # idem, avec un résolveur in-scope (ex. un DC)
python -m offense.netns status             # ce que le noyau autorise réellement
sudo python -m offense.netns down
```

- **Fail-closed, sans contournement** : si le namespace est absent, ou si le set du noyau
  n'est pas exactement le périmètre actif, la technique n'est pas exécutée
  (`blocked_no_netns`), n'est pas « grillée » dans le ledger, et l'opérateur est prévenu.
  La reconnaissance et les outils builtin restent utilisables (ils contactent déjà l'IP
  validée).
- **Linux uniquement, root pour la mise en place.** `up` installe un script d'aide
  (`/usr/local/sbin/pc-netns-exec`) et une règle sudoers limitée à ce script ; la commande
  s'exécute ensuite avec **vos** privilèges, pas en root. `up` active
  `net.ipv4.ip_forward`, que `down` ne remet pas à zéro.
- **DNS fermé par défaut** dans le namespace (`/etc/hosts` reste visible) ; services de la
  machine elle-même (loopback, IP locales) injoignables ; IPv6 désactivé.
- **Un périmètre `127.0.0.1` est donc injoignable par ce chemin** : dans le namespace, la
  boucle locale est celle du namespace, vide. `up` et la porte de mission l'annoncent
  (`[NETNS] Attention : …`). La reconnaissance et les outils builtin, eux, atteignent
  toujours `127.0.0.1`. Pour un lab local, donnez à la cible sa propre adresse — voir
  [Lab local](#lab-local) ci-dessous.
- Le lien interne hôte ↔ namespace utilise `100.127.77.0/30` (plage partagée des
  opérateurs, hors plages privées) : seul un périmètre qui chevauche cette plage est refusé.

#### Lab local

Pour s'exercer sur un service qui tourne sur la machine elle-même, lancez-le dans un second
namespace (`pc-lab`) qui a sa propre adresse, `192.0.2.2` (plage de documentation, jamais
routée sur Internet) :

```bash
sudo python -m offense.lab up                                   # crée la cible 192.0.2.2
sudo python -m offense.lab run -- python3 -m http.server 8000   # votre service, au premier plan
# dans scope.txt : 192.0.2.2   puis : sudo python -m offense.netns up
sudo python -m offense.lab down
```

`run` lance la commande avec **vos** privilèges ; Ctrl-C l'arrête. La reconnaissance (depuis
la machine) et le chemin offensif (depuis `pc-offense`, à travers le filtre) atteignent tous
deux `192.0.2.2` ; les services locaux de la machine restent hors d'atteinte du chemin
offensif. Le lab ne sépare que le réseau du service, pas ses fichiers.

##### Lab garni (prêt à l'emploi)

`lab/demarrer.sh` monte la cible et y lance **deux services remplis de données fictives** :
un intranet HTTP (port 80) et un serveur de fichiers SMB (port 445), le tout au premier plan
(Ctrl-C arrête et démonte) :

```bash
sudo bash lab/demarrer.sh
# puis, dans un autre terminal : 192.0.2.2 dans scope.txt, puis sudo python -m offense.netns up
```

L'intranet laisse traîner le mot de passe d'un compte de service qui ouvre un partage SMB
protégé (`archives`, refusé en anonyme). Pour que le chaînage « mot de passe trouvé → accès
au partage » s'exécute de façon déterministe, copiez le gabarit `operator` fourni (l'arsenal
`operator` reste local, non versionné) :

```bash
cp lab/operator-smb.yaml catalog/operator/smb.yaml
```

Une mission `scanne et énumère 192.0.2.2` enchaîne alors : recon → lecture de l'intranet →
récupération du mot de passe → listing authentifié du partage `archives`.

Limites connues :

- rebond par un hôte in-scope (`curl -x` vers un proxy du périmètre) ;
- lectures locales (`curl file://…`) — ce n'est pas du réseau ;
- connexions entrantes vers le namespace (reverse shell : demanderait un DNAT) ;
- périmètre IPv6 non appliqué (IPv4 seulement) ;
- scans à sockets brutes en non-root (`nmap -sS`) : poser `setcap cap_net_raw+ep` sur nmap ;
- le namespace confine le **réseau** des processus qu'il lance, pas leurs autres moyens de
  parler à un processus extérieur : sockets Unix par chemin (`docker.sock`, ControlMaster
  ssh, serveur tmux, `systemd-run --user`). La commande tourne avec le même utilisateur
  que PirateCrew ;
- sous WSL2, l'interop Windows (`curl.exe`, `powershell.exe`… qui s'exécuteraient côté
  Windows, hors filtre) est **masquée** dans le namespace — vérifié par les tests
  d'intégration ; elle reste active partout ailleurs ;
- `sudo` journalise chaque commande rendue, identifiants compris, dans le journal système ;
- une commande **déjà en cours** n'est plus filtrée si la table nftables est supprimée à la
  main (`down` coupe d'abord le lien ; les commandes suivantes sont refusées, y compris si
  les règles sont seulement vidées ou si le namespace a disparu) ;
- un autre pare-feu en `DROP` sur le transit (Docker, iptables `FORWARD`) peut bloquer des
  cibles in-scope : le symptôme est un timeout, pas une fuite.

## Prérequis

- **Python 3.11+** (testé en 3.13)
- Une **clé API Anthropic**
- *(recommandé)* un environnement Linux disposant des outils de pentest — voir
  [Environnement recommandé (Kali)](#environnement-recommandé-kali)

## Installation

```bash
python -m venv venv
# Windows :        venv\Scripts\activate
# Linux / Kali :   source venv/bin/activate
pip install -r requirements.txt
```

Créer un fichier `.env` à la racine avec votre clé API :

```
ANTHROPIC_API_KEY=sk-ant-...
```

Définir le **périmètre autorisé** à partir de l'exemple fourni :

```bash
cp scope.txt.example scope.txt      # Windows : copy scope.txt.example scope.txt
```

`scope.txt` contient une **IP ou un CIDR par ligne**, p.ex. :

```
10.10.10.0/24
127.0.0.1/32
```

## Lancement

```bash
python orchestrator.py
```

Puis, en langage naturel :

```
Vous > scanne et énumère 10.10.10.5
```

Le superviseur reconnaît une mission autonome, charge le périmètre, puis déroule la
boucle. La réponse finale résume les trouvailles (hôtes, services, identifiants…) et
**signale tout outil manquant** à installer.

Commandes de l'invite (en plus du langage naturel) :

| Commande | Effet |
|---|---|
| `verbose [on\|off]` | diagnostics détaillés (aussi : `PIRATECREW_VERBOSE=1`) |
| `propose-only [on\|off]` | les techniques rédigées par l'auteur LLM sont montrées, pas exécutées |
| `sessions` | sessions obtenues pendant la dernière mission, autorisées ou en attente |
| `authorize <hôte>` | autorise les sessions en attente de cet hôte et reprend la mission |
| `promote` | ajoute au RAG partagé les techniques LLM proposées en fin de mission |
| `exit` / `quit` | quitter |

Rien n'est écrit d'office dans le RAG partagé : en fin de mission, les techniques rédigées
par l'auteur LLM sont **affichées** telles qu'elles seraient stockées, et seule la commande
`promote` les y ajoute. Le filtre automatique (secrets, identifiants et noms d'hôte connus,
IP, jetons à forte entropie) n'est qu'un pré-tri : relisez avant de promouvoir.

Les résultats détaillés sont dans `missions/<id>/rapport.md` (rapport lisible) et
`missions/<id>/world.json` (état complet, réécrit à chaque cycle).

> ⚠️ **Secrets au repos.** PirateCrew récolte et réutilise des identifiants : par
> conception, `rapport.md` et `world.json` contiennent les secrets trouvés **en clair**
> (credentials, commandes rendues, sorties d'outils). C'est inhérent à un orchestrateur
> de pentest, pas une fuite. Le dossier `missions/` est gitignoré (jamais versionné) ;
> sur une machine partagée, restreignez-le (`chmod 700 missions/`). Si vous ne voulez
> aucun secret au repos, n'exécutez pas de technique utilisant un credential, ou purgez
> `missions/` après exploitation. `audit.log`, lui, n'en contient jamais (voir
> [Sécurité](#sécurité-fail-closed)).

## Comment ça marche

```
requête ──► superviseur maître
               ├─ mission autonome ──► enter (scope fail-closed)
               │                         └─► recon ─► decide ─► execute ─► integrate ─┐
               │                                        ▲                             │
               │                                        └──────── continue ◄──────────┘
               │                                                 (sinon : fin)
               ├─ base de connaissances (RAG)
               ├─ analyse de code
               └─ réponse directe
```

- **recon** : scan des ports courants / nmap si disponible ; les services ouverts sont
  remontés dans le `WorldModel`.
- **decide** : pour chaque (hôte in-scope, service), planifie les techniques du catalogue
  dont les prérequis sont satisfaits et qui n'ont pas déjà été tentées (ledger).
- **execute** : un agent par tâche exécute la technique via ses outils ; les trouvailles
  sont remontées de façon structurée (`report_finding`).
- **integrate** : met à jour le ledger, récupère les trouvailles du texte brut, et décide
  de continuer ou de terminer.

## Outils & catalogue

Les agents n'appellent que des **outils déclarés** (`@tool`), tous soumis au contrôle de
périmètre. Outils par domaine :

| Domaine        | Outils                              |
|----------------|-------------------------------------|
| `network`      | `nmap_scan`, `tcp_port_check`       |
| `web`          | `http_fingerprint`, `http_get`      |
| `ad`           | `smb_port_probe`, `smb_list_shares` |
| *obligatoires* | `log_audit_event`, `scope_check`    |
| *+*            | `report_finding` (lié au `WorldModel`) |

Le **catalogue** décrit les techniques de façon déclarative : `catalog/builtin/` (fourni)
et `catalog/operator/` (local, non versionné — gabarits à remplir, cf.
`catalog/operator.example.yaml`).

### Ajouter un outil

1. **Écrire** la fonction `@tool` dans `tools/registry.py` : valider la cible via
   `_validate_target(...)`, journaliser via `_audit(...)`, et **ne jamais lever**
   (renvoyer un message en cas d'échec).
2. **Déclarer** l'outil dans `TOOL_CATALOG[domaine]` (ou `MANDATORY_TOOLS`).
3. **Décrire** une technique au catalogue (`catalog/builtin/*.yaml`) : `service`, `tool`,
   `command_template` (placeholders `{target}` / `{port}`), `success_signal`.

> *« Avoir l'outil » (étape 2) et « être chargé de l'utiliser » (étape 3) sont distincts.*

### Outil manquant (escalade)

Si une technique requiert un **binaire externe absent** (vérifié par `shutil.which`), la
mission ne l'exécute pas : elle la **signale** (« installe `smbclient` »), ne la « grille »
pas dans le ledger, et la **reprend** automatiquement après installation + relance de la
mission. L'humain reste maître des capacités installées.

## Environnement recommandé (Kali)

Sous Windows, le plus simple pour disposer d'un vrai arsenal (`nmap`, `smbclient`,
`gobuster`…) est de faire tourner PirateCrew dans **WSL2 Kali**. Les agents détectent et
utilisent alors les binaires présents ; ceux qui manquent sont signalés (voir ci-dessus).
Étapes détaillées : [`docs/MILESTONES.md`](docs/MILESTONES.md).

C'est aussi là que fonctionne le [périmètre réseau](#périmètre-réseau-chemin-offensif)
(namespaces + nftables, vérifié sur le noyau WSL2) : sans lui, les techniques
`operator`/`llm` ne s'exécutent pas.

## Tests

```bash
pytest -q
```

Preuve d'intégration du périmètre réseau (Linux, root — crée deux namespaces locaux, rien
ne sort de la machine) :

```bash
sudo PIRATECREW_NETNS_IT=1 venv/bin/pytest tests/test_netns_integration.py tests/test_netns_round3_replay.py -v
```

`test_netns_round3_replay.py` rejoue, avec les vrais outils (`curl`, `sqlmap`, `ffuf`, `wfuzz`,
`scp`, `rsync`, `nmap`, `smbclient`, `ssh`), les contournements du contrôle texte confirmés par
la revue adverse du 18/11/2026 : aucun paquet n'atteint la cible hors périmètre, et le filtre
compte bien les paquets que chaque outil a tenté d'émettre.

> Sous Windows, le **premier** lancement peut prendre quelques minutes : l'antivirus
> scanne les imports `langchain` au chargement. Les tests n'effectuent **aucun** appel
> LLM ni réseau réel.

## Structure du projet

```
orchestrator.py        # boucle maître + mission autonome + CLI
scope.py               # périmètre fail-closed + journal d'audit
state/world_model.py   # modèle du terrain partagé (hôtes, services, creds, ledger…)
agents/
  dynamic_agent.py     # fabrique d'agents d'intervention (factory)
  pirate_agent.py      # agent RAG (base de connaissances)
  analyst_agent.py     # agent d'analyse de code
tools/registry.py      # outils @tool (network / web / ad) + chokepoint de périmètre
offense/
  guardrails.py        # garde-fous texte (shell, destructif, périmètre best-effort)
  executor.py          # exécuteur déterministe des gabarits operator/llm
  netns.py             # périmètre appliqué par le noyau (namespace + nftables)
catalog/
  builtin/             # techniques fournies (recon / web / smb)
  operator/            # techniques locales de l'opérateur (non versionné)
tests/                 # suite pytest
docs/                  # rapports & suivi (MILESTONES, RAPPORT-AVANCEMENT)
```

## État du projet

Prototype **fonctionnel et couvert par les tests** (274 tests verts), pas encore durci
pour une mise en production. Dépend d'une clé API LLM et, pour le scan complet, d'outils
système optionnels (repli en Python pur sinon). Suivi de l'avancement :
[`docs/MILESTONES.md`](docs/MILESTONES.md).
