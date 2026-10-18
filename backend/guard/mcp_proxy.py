"""stdio JSON-RPC MCP proxy: sits between an MCP client and a real MCP server.

    client <--stdio--> blastradius-proxy <--stdio--> child MCP server

Every message is forwarded untouched except `tools/call` requests. Those go to the Guard
(decide.check, which queries FalkorDB) first:
    ALLOW     -> forwarded to the child
    DENY      -> answered by the proxy with an MCP error result; the child never sees the call
    ESCALATE  -> held until a human approves or rejects (UI click, or a prompt on the terminal)

MCP stdio framing is one JSON object per line. The proxy never logs to stdout (that is the
protocol channel); diagnostics go to stderr.

Usage:
  python -m backend.guard.mcp_proxy --stack <stack-id> [--session <id>] [--approve ui|cli|deny]
         -- <child command...>
"""
import argparse
import json
import subprocess
import sys
import threading
import uuid

from backend.guard import approvals, decide
from backend.llm import base as llm


def log(msg: str) -> None:
    print(f"[blastradius] {msg}", file=sys.stderr, flush=True)


class GuardProxy:
    def __init__(self, stack: str, session: str, child_cmd: list[str], approve_mode: str = "ui",
                 approval_timeout: float = 120.0, child_env: dict | None = None):
        self.stack = stack
        self.session = session
        self.child_cmd = child_cmd
        self.approve_mode = approve_mode
        self.approval_timeout = approval_timeout
        self.child_env = child_env
        self._out_lock = threading.Lock()
        self._child_lock = threading.Lock()
        self.child: subprocess.Popen | None = None

    # ---- plumbing --------------------------------------------------------------------
    def _write_client(self, msg: dict) -> None:
        with self._out_lock:
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def _write_child(self, msg: dict) -> None:
        with self._child_lock:
            assert self.child and self.child.stdin
            self.child.stdin.write(json.dumps(msg) + "\n")
            self.child.stdin.flush()

    def _pump_child(self) -> None:
        assert self.child and self.child.stdout
        for line in self.child.stdout:
            line = line.strip()
            if not line:
                continue
            with self._out_lock:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()

    # ---- the interception ------------------------------------------------------------
    def denial(self, req_id, d: decide.Decision, extra: str = "") -> dict:
        text = f"BlastRadius {d.decision}: " + "; ".join(d.reasons) + extra
        return {"jsonrpc": "2.0", "id": req_id,
                "result": {"isError": True, "content": [{"type": "text", "text": text}],
                           "_blastradius": {"decision": d.decision, "seq": d.seq,
                                            "session": d.session}}}

    def handle_tool_call(self, msg: dict) -> None:
        params = msg.get("params") or {}
        tool, args = params.get("name", ""), params.get("arguments") or {}
        d = decide.check(self.session, self.stack, tool, args)
        log(f"{d.decision} {tool} (seq {d.seq}, score {d.score}, {d.latency_ms} ms): "
            + "; ".join(d.reasons))
        if d.decision == decide.ALLOW:
            self._write_child(msg)
            return
        if d.decision == decide.DENY:
            self._write_client(self.denial(msg.get("id"), d))
            return
        outcome = self._await_human(d)
        if outcome == "approved":
            self._write_child(msg)
        else:
            why = " (timed out waiting for a human)" if outcome == "pending" else \
                " (rejected by a human)"
            self._write_client(self.denial(msg.get("id"), d, why))

    def _await_human(self, d: decide.Decision) -> str:
        if self.approve_mode == "deny":
            approvals.resolve(self.session, d.seq, approve=False)
            return "rejected"
        if self.approve_mode == "cli":
            return self._cli_prompt(d)
        log(f"waiting for a human: approve session={self.session} seq={d.seq} in the UI")
        return approvals.wait_for_resolution(self.session, d.seq, self.approval_timeout)

    def _cli_prompt(self, d: decide.Decision) -> str:
        try:
            tty = open("/dev/tty", "r+")
        except OSError:
            log("no terminal for --approve cli; rejecting")
            approvals.resolve(self.session, d.seq, approve=False)
            return "rejected"
        with tty:
            tty.write(f"\n[blastradius] ESCALATE {d.tool}: {'; '.join(d.reasons)}\n"
                      "Allow this call? [y/N] ")
            tty.flush()
            ans = tty.readline().strip().lower()
        ok = ans in ("y", "yes")
        approvals.resolve(self.session, d.seq, approve=ok)
        return "approved" if ok else "rejected"

    # ---- main loop -------------------------------------------------------------------
    def run(self) -> int:
        st = llm.llm_status()
        if st["mock_mode"]:
            log(f"MOCK MODE: {st['reason']} (the Guard itself never uses an LLM)")
        log(f"guarding stack={self.stack} session={self.session} child={' '.join(self.child_cmd)}")
        self.child = subprocess.Popen(
            self.child_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
            env=self.child_env,
        )
        threading.Thread(target=self._pump_child, daemon=True).start()
        workers: list[threading.Thread] = []
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._write_child_raw(line)
                continue
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                t = threading.Thread(target=self._safe_tool_call, args=(msg,), daemon=True)
                t.start()
                workers.append(t)
            else:
                self._write_child(msg)
        for t in workers:
            t.join(timeout=self.approval_timeout)
        if self.child.stdin:
            self.child.stdin.close()
        return self.child.wait(timeout=10)

    def _write_child_raw(self, line: str) -> None:
        with self._child_lock:
            assert self.child and self.child.stdin
            self.child.stdin.write(line + "\n")
            self.child.stdin.flush()

    def _safe_tool_call(self, msg: dict) -> None:
        try:
            self.handle_tool_call(msg)
        except Exception as e:  # noqa: BLE001 - any failure must close the door, not open it
            log(f"error while guarding call, denying: {type(e).__name__}: {e}")
            self._write_client({
                "jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"isError": True, "content": [{
                    "type": "text",
                    "text": f"BlastRadius DENY: guard error, failing closed ({type(e).__name__}: {e})",
                }]},
            })


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" not in argv:
        print("usage: mcp_proxy --stack ID [--session ID] [--approve ui|cli|deny] -- CMD...",
              file=sys.stderr)
        return 2
    split = argv.index("--")
    ap = argparse.ArgumentParser(prog="blastradius-proxy")
    ap.add_argument("--stack", required=True)
    ap.add_argument("--session", default=None)
    ap.add_argument("--approve", choices=["ui", "cli", "deny"], default="ui")
    ap.add_argument("--approval-timeout", type=float, default=120.0)
    args = ap.parse_args(argv[:split])
    child = argv[split + 1:]
    if not child:
        print("missing child command after --", file=sys.stderr)
        return 2
    session = args.session or f"proxy-{uuid.uuid4().hex[:8]}"
    return GuardProxy(args.stack, session, child, args.approve, args.approval_timeout).run()


if __name__ == "__main__":
    raise SystemExit(main())
