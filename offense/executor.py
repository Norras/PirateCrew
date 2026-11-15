"""Exécuteur offensif déterministe.

Exécute une commande rendue UNIQUEMENT après passage des garde-fous
(`offense.guardrails`), en argv liste (`shell=False`). Ne lève jamais :
renvoie toujours un couple `(statut, sortie)`.
"""
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
    "blocked_shell_meta", "blocked_destructive", "blocked_out_of_scope"}.
    `runner(argv, timeout) -> str` est injectable (défaut : `tools.registry._run`).
    Un blocage court-circuite : le runner n'est jamais appelé.
    """
    if not (rendered or "").strip():
        return ("error", "(aucune commande)")

    verdict = evaluate(rendered)
    if verdict is not None:
        _audit_block(*verdict)
        return verdict

    try:
        argv = tokenize_argv(rendered)
    except GuardrailError as e:
        return ("error", str(e))

    try:
        if runner is None:
            from tools.registry import _run as runner  # lazy : évite un cycle d'import
        return ("done", runner(argv, timeout))
    except Exception as e:  # le mode « ne lève jamais » prime
        return ("error", f"Échec d'exécution : {e}")
