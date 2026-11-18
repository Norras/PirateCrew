"""Deterministic offensive executor.

Runs a rendered command ONLY after it has passed the guardrails
(`offense.guardrails`), as an argv list (`shell=False`). Never raises:
always returns a `(status, output)` pair.
"""
from offense import netns
from offense.guardrails import GuardrailError, evaluate, tokenize_argv


def _audit_block(tag: str, detail: str) -> None:
    """Audit a block, best effort (lazy import, never blocking)."""
    try:
        from tools.registry import _audit
        _audit("OFFENSE_BLOCKED", f"{tag}: {detail}")
    except Exception:
        pass


def execute_command(rendered: str, *, timeout: int = 120, runner=None) -> tuple[str, str]:
    """Run `rendered` if the guardrails pass. Never raises.

    Returns `(status, output)` with status in {"done", "error",
    "blocked_shell_meta", "blocked_destructive", "blocked_out_of_scope",
    "blocked_no_netns"}.
    `runner(argv, timeout) -> str` is injectable. By default the command runs
    in the filtered network namespace (`offense.netns.run_isolated`): the
    kernel enforces the perimeter, however the host is written. If that
    namespace is not in place or does not match the active scope, nothing
    is run (`blocked_no_netns`) — there is no fallback without a namespace.
    A block short-circuits: the runner is never called.
    """
    if not (rendered or "").strip():
        return ("error", "(no command)")

    try:
        verdict = evaluate(rendered)
    except Exception as e:  # defense in depth: never raise
        return ("error", f"guardrail: {type(e).__name__}")
    if verdict is not None:
        _audit_block(*verdict)
        return verdict

    try:
        argv = tokenize_argv(rendered)
    except GuardrailError as e:
        return ("error", str(e))

    try:
        if runner is None:
            runner = netns.run_isolated  # resolved at call time: network boundary by default
        return ("done", runner(argv, timeout))
    except netns.NetnsError as e:
        _audit_block("blocked_no_netns", str(e))
        return ("blocked_no_netns", str(e))
    except Exception as e:  # the "never raises" contract takes precedence
        return ("error", f"Execution failed: {e}")
