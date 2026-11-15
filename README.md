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
- Chaque action est horodatée dans `audit.log` (sauts de ligne neutralisés pour
  empêcher la forge de fausses lignes de log).

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

## Tests

```bash
pytest -q
```

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
catalog/
  builtin/             # techniques fournies (recon / web / smb)
  operator/            # techniques locales de l'opérateur (non versionné)
tests/                 # suite pytest
docs/                  # rapports & suivi (MILESTONES, RAPPORT-AVANCEMENT)
```

## État du projet

Prototype **fonctionnel et couvert par les tests** (52 tests verts), pas encore durci
pour une mise en production. Dépend d'une clé API LLM et, pour le scan complet, d'outils
système optionnels (repli en Python pur sinon). Suivi de l'avancement :
[`docs/MILESTONES.md`](docs/MILESTONES.md).
