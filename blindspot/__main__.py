"""
Command line interface.

    python -m blindspot scan samples/extensions          analyse a folder, write report + policy
    python -m blindspot agent --server http://HOST:8000  inventory THIS computer and send it
    python -m blindspot agent --server ... --every 15    keep watching: report again every 15 minutes
    python -m blindspot demo-fleet --server http://HOST:8000
    python -m blindspot fixtures                         rebuild fixtures/seed.json for the frontend

Owner: D
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from blindspot import __version__
from blindspot.contract import REPO_ROOT
from blindspot.pipeline import analyze_tree
from blindspot.policy.policy import generate_policy, render_windows_reg
from blindspot.report.report import build_report, write_report

COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[32m"}
RESET = "\033[0m"


def _print_table(results: list[dict]) -> None:
    # Classic Windows PowerShell prints ANSI codes literally; Windows Terminal (WT_SESSION) renders them.
    color = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
             and (os.name != "nt" or "WT_SESSION" in os.environ))
    where = any("browser" in r for r in results)
    head = f"{'BROWSER / PROFILE':<22} " if where else ""
    print(f"\n{'SCORE':>5}  {'LEVEL':<7} {'ACTION':<7} {'EXTENSION':<28} {head}MAIN REASON")
    print("-" * (96 + (23 if where else 0)))
    for r in results:
        level = f"{COLORS[r['level']]}{r['level']:<7}{RESET}" if color else f"{r['level']:<7}"
        reason = r["findings"][0]["title"] if r["findings"] else ""
        loc = f"{(r.get('browser', '') + ' / ' + r.get('profile', ''))[:22]:<22} " if where else ""
        print(f"{r['score']:>5}  {level} {r['recommendation']:<7} {r['name'][:28]:<28} {loc}{reason[:50]}")
    print()


def _write_policy(results: list[dict], out: Path, default_deny: bool, protect_all: bool = False) -> dict:
    policy = generate_policy(results, default_deny=default_deny, protect_all=protect_all)
    (out / "policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")
    (out / "chrome_managed_policy.json").write_text(json.dumps(policy["chrome_policy"], indent=2), encoding="utf-8")
    (out / "chrome_policy.reg").write_text(render_windows_reg(policy["chrome_policy"]), encoding="utf-8")
    return policy


def cmd_scan(args) -> int:
    results = analyze_tree(args.path)
    if not results:
        print(f"No extensions found under {args.path}", file=sys.stderr)
        return 1
    if not args.quiet:
        _print_table(results)
    out = Path(args.out)
    report = build_report(results, scope={"source": str(args.path)})
    paths = write_report(report, out)
    _write_policy(results, out, args.default_deny, args.protect_all)
    print(f"Report:  {paths['html']}\n         {paths['json']}\nPolicy:  {out / 'policy.json'}")

    if args.server:
        from blindspot.collector.agent import machine_info, post
        payload = {"machine": machine_info(args.machine_id),
                   "extensions": [{k: v for k, v in r.items() if k != "path"} for r in results],
                   "software": []}
        print("Server:", post(payload, args.server))

    if args.fail_on and any(r["level"] == args.fail_on or (args.fail_on == "medium" and r["level"] == "high")
                            for r in results):
        return 2
    return 0


def cmd_agent(args) -> int:
    if args.every:
        import time
        print(f"Watching: a new report every {args.every} minute(s). Ctrl+C to stop.")
        while True:
            try:
                _agent_once(args)
            except Exception as exc:  # noqa: BLE001 -- a watcher must survive a bad round
                print("Round failed:", exc, file=sys.stderr)
            try:
                time.sleep(args.every * 60)
            except KeyboardInterrupt:
                return 0
    return _agent_once(args)


def _agent_once(args) -> int:
    from blindspot.collector.agent import collect, post
    payload = collect(include_software=not args.no_software, machine_id=args.machine_id)
    print(f"{len(payload['extensions'])} extensions, {len(payload['software'])} software items "
          f"on {payload['machine']['hostname']}")
    _print_table(sorted(payload["extensions"], key=lambda r: r["score"], reverse=True))
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print("Saved", args.out)
    if args.server:
        answer = post(payload, args.server)
        print("Server:", {k: v for k, v in answer.items() if k != "guard"} if isinstance(answer, dict) else answer)
        for hit in (answer.get("guard") or []) if isinstance(answer, dict) else []:
            if hit["action"] != "pinned":
                print(f"  Guard: {hit['ext_id']} {hit['version']} {hit['action']}"
                      + (": " + "; ".join(hit.get("reasons", [])) if hit.get("reasons") else ""))
    return 0


def cmd_demo_fleet(args) -> int:
    from blindspot.collector.agent import post
    from blindspot.demo import demo_payloads
    results = analyze_tree(REPO_ROOT / "samples" / "extensions")
    for payload in demo_payloads(results):
        answer = post(payload, args.server)
        guard = [f"{g['action']} {g['version']}" for g in answer.get("guard", [])] if isinstance(answer, dict) else []
        print(payload["machine"]["hostname"], "->", "ok", ("| Guard: " + ", ".join(guard)) if guard else "")
    return 0


def cmd_fixtures(args) -> int:
    from blindspot.demo import demo_payloads
    from blindspot.store import Store
    results = analyze_tree(REPO_ROOT / "samples" / "extensions")
    store = Store(":memory:")
    for payload in demo_payloads(results):
        store.ingest(payload)
    seed = {
        "_comment": "Generated by `python -m blindspot fixtures` from samples/ and the synthetic demo fleet. "
                    "Same shapes as the live API. Do not edit by hand.",
        "summary": store.summary(),
        "extensions": store.extensions(),
        "details": {e["id"]: store.extension(e["id"]) for e in store.extensions()},
        "machines": store.machines(),
        "software": store.software(),
        "exposure": store.exposure(),
        "machine_details": {m["machine_id"]: store.machine(m["machine_id"]) for m in store.machines()},
        "guard": store.guard(),
    }
    target = REPO_ROOT / "fixtures" / "seed.json"
    target.write_text(json.dumps(seed, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Wrote", target.relative_to(REPO_ROOT), "(synthetic, for tests and development; the dashboard never shows it)")
    return 0


def cmd_test_extension(args) -> int:
    from blindspot.testext import DEFAULT_DIR, run
    print(run(args.action, Path(args.path) if args.path else DEFAULT_DIR))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blindspot", description="Browser extension risk analyzer")
    parser.add_argument("--version", action="version", version=f"blindspot {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse unpacked extensions in a folder")
    scan.add_argument("path", help="extension folder, Extensions/ tree, or folder of samples")
    scan.add_argument("--out", default="reports", help="output folder (default: reports)")
    scan.add_argument("--server", help="also send results to this Blindspot server")
    scan.add_argument("--machine-id", help="machine id to use with --server")
    scan.add_argument("--default-deny", action="store_true", help="policy blocks everything not allowlisted")
    scan.add_argument("--protect-all", action="store_true",
                      help="keep EVERY extension, including unknown future ones, off the crown-jewel hosts")
    scan.add_argument("--fail-on", choices=["high", "medium"], help="exit code 2 if any extension is at this level")
    scan.add_argument("--quiet", action="store_true")
    scan.set_defaults(func=cmd_scan)

    agent = sub.add_parser("agent", help="inventory this computer")
    agent.add_argument("--server", help="Blindspot server, e.g. http://192.168.1.20:8000")
    agent.add_argument("--out", help="also save the payload to this JSON file")
    agent.add_argument("--machine-id")
    agent.add_argument("--no-software", action="store_true")
    agent.add_argument("--every", type=float, metavar="MINUTES",
                       help="keep running and report again every MINUTES (continuous monitoring)")
    agent.set_defaults(func=cmd_agent)

    fleet = sub.add_parser("demo-fleet", help="send the synthetic demo fleet to a server")
    fleet.add_argument("--server", required=True)
    fleet.set_defaults(func=cmd_demo_fleet)

    fixtures = sub.add_parser("fixtures", help="rebuild fixtures/seed.json (synthetic test data)")
    fixtures.set_defaults(func=cmd_fixtures)

    test = sub.add_parser("test-extension", help="harmless test extension to prove Guard on this computer")
    test.add_argument("action", choices=["create", "hijack", "restore", "critical"])
    test.add_argument("--path", help="folder (default: ~/blindspot-test-extension)")
    test.set_defaults(func=cmd_test_extension)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
