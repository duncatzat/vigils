#!/usr/bin/env python3
"""Minimal MCP stdio client to functionally probe `vigil-hub serve --stdio`.

Drives the newline-delimited JSON-RPC handshake the way a real MCP host does:
  initialize -> notifications/initialized -> tools/list

Robust framing (proper JSON over a real subprocess pipe) replaces fragile
shell `printf | ssh` attempts whose nested quoting mangled the request.

Usage:  mcp_probe.py <vigil-hub> [extra serve args...]
Exit 0 + 'PASS:' lines when initialize (and ideally tools/list) succeed.
"""
import json
import subprocess
import sys
import threading
import time


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: mcp_probe.py <vigil-hub> [extra serve args...]", file=sys.stderr)
        return 2
    hub = sys.argv[1]
    extra = sys.argv[2:]
    proc = subprocess.Popen(
        [hub, "serve", "--stdio", *extra],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    results: dict = {}

    def send(obj: dict) -> None:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("id") == 1 and "result" in msg:
                results["init"] = msg["result"]
            elif msg.get("id") == 2 and "result" in msg:
                results["tools"] = msg["result"]

    threading.Thread(target=reader, daemon=True).start()

    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "vigil-acceptance-probe", "version": "1"},
        },
    })
    for _ in range(100):
        if "init" in results:
            break
        time.sleep(0.05)
    if "init" not in results:
        err = (proc.stderr.read() if proc.stderr else "")[:400]
        print(f"FAIL: no initialize result; stderr head: {err!r}")
        proc.kill()
        return 1

    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    for _ in range(100):
        if "tools" in results:
            break
        time.sleep(0.05)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    si = results["init"].get("serverInfo", {})
    print(
        f"PASS: initialize ok (server={si.get('name', '?')} "
        f"v{si.get('version', '?')}, protocol={results['init'].get('protocolVersion', '?')})"
    )
    if "tools" in results:
        tools = results["tools"].get("tools", [])
        names = [t.get("name") for t in tools][:8]
        print(f"PASS: tools/list ok ({len(tools)} tool(s): {names})")
    else:
        print("WARN: no tools/list result (server may expose no tools without an upstream)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
