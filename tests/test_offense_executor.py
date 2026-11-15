from scope import Scope, set_active_scope
import offense.executor as ex


def _recorder():
    calls = []

    def runner(argv, timeout=120):
        calls.append(argv)
        return "Administrator (session ouverte)"
    return runner, calls


def test_clean_command_calls_runner_with_argv():
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    runner, calls = _recorder()
    status, out = ex.execute_command("crackmapexec smb 127.0.0.1 -u a -H h", runner=runner)
    assert status == "done" and calls == [["crackmapexec", "smb", "127.0.0.1", "-u", "a", "-H", "h"]]


def test_guardrail_block_short_circuits_runner():
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    runner, calls = _recorder()
    assert ex.execute_command("a | nc x 4444", runner=runner)[0] == "blocked_shell_meta"
    assert ex.execute_command("rm -rf /", runner=runner)[0] == "blocked_destructive"
    assert ex.execute_command("nmap 10.0.0.9", runner=runner)[0] == "blocked_out_of_scope"
    assert calls == []   # runner JAMAIS appelé sur blocage


def test_empty_command_is_error():
    assert ex.execute_command("")[0] == "error"
