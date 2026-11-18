"""Exécuteur offensif déterministe.

Exécute une commande rendue UNIQUEMENT après passage des garde-fous
(`offense.guardrails`), en argv liste (`shell=False`). Ne lève jamais :
renvoie toujours un couple `(statut, sortie)`.
"""
from offense import netns
from offense.guardrails import GuardrailError, evaluate, tokenize_argv


def _audit_block(tag: str, detail: str) -> None:
    """Audit d'un blocage, au mieux (import paresseux, jamais bloquant)."""
    try:
        from tools.registry import _audit
        _audit("OFFENSE_BLOCKED", f"{tag}: {detail}")
    except Exception:
        pass


def execute_command(rendered: str, *, timeout: int = 120, runner=None) -> tuple[str, str]:
    """Exécute `rendered` si les garde-fous passent. Ne lève jamais.

    Retourne `(statut, sortie)` avec statut dans {"done", "error",
    "blocked_shell_meta", "blocked_destructive", "blocked_out_of_scope",
    "blocked_no_netns"}.
    `runner(argv, timeout) -> str` est injectable. Par défaut la commande tourne
    dans le namespace réseau filtré (`offense.netns.run_isolated`) : c'est le
    noyau qui applique le périmètre, quelle que soit l'écriture de l'hôte. Si ce
    namespace n'est pas en place ou ne correspond pas au périmètre actif, rien
    n'est exécuté (`blocked_no_netns`) — il n'existe pas de repli sans namespace.
    Un blocage court-circuite : le runner n'est jamais appelé.
    """
    if not (rendered or "").strip():
        return ("error", "(aucune commande)")

    try:
        verdict = evaluate(rendered)
    except Exception as e:  # défense en profondeur : ne jamais lever
        return ("error", f"garde-fou: {type(e).__name__}")
    if verdict is not None:
        _audit_block(*verdict)
        return verdict

    try:
        argv = tokenize_argv(rendered)
    except GuardrailError as e:
        return ("error", str(e))

    try:
        if runner is None:
            runner = netns.run_isolated  # résolu à l'appel : frontière réseau par défaut
        return ("done", runner(argv, timeout))
    except netns.NetnsError as e:
        _audit_block("blocked_no_netns", str(e))
        return ("blocked_no_netns", str(e))
    except Exception as e:  # le mode « ne lève jamais » prime
        return ("error", f"Échec d'exécution : {e}")
