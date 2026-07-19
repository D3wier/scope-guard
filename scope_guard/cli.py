"""CLI entry point."""

import argparse
import sys
import os
import yaml
from pathlib import Path
from .checker import ScopeChecker
from .parser import parse_h1_scope, parse_scope_file

CONFIG_DIR = Path.home() / ".scope-guard"
ACTIVE_FILE = CONFIG_DIR / ".active"

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"


def get_active_scope() -> str:
    if ACTIVE_FILE.exists():
        return ACTIVE_FILE.read_text().strip()
    scopes = list(CONFIG_DIR.glob("*.yaml"))
    if len(scopes) == 1:
        return scopes[0].stem
    return ""


def load_checker(program: str = "") -> ScopeChecker:
    if not program:
        program = get_active_scope()
    if not program:
        print("No active program. Run: scope-guard use <program>", file=sys.stderr)
        sys.exit(1)

    scope_file = CONFIG_DIR / f"{program}.yaml"
    if not scope_file.exists():
        print(f"Scope file not found: {scope_file}", file=sys.stderr)
        sys.exit(1)

    return ScopeChecker.from_file(str(scope_file))


def cmd_init(args):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    scope_file = CONFIG_DIR / f"{args.program}.yaml"

    template = {
        "program": args.program,
        "platform": "custom",
        "in_scope": [
            {"type": "domain", "value": "*.example.com"},
        ],
        "out_of_scope": [
            {"type": "domain", "value": "blog.example.com"},
        ],
        "rules": {
            "no_automated_scanning": False,
            "rate_limit": "30/min",
            "no_destructive": True,
        },
    }

    scope_file.write_text(yaml.dump(template, default_flow_style=False))
    ACTIVE_FILE.write_text(args.program)
    print(f"Created scope file: {scope_file}")
    print(f"Edit it to add your program's scope.")


def cmd_import(args):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if args.h1:
        data = parse_h1_scope(args.h1)
        if not data:
            print("Failed to fetch HackerOne scope", file=sys.stderr)
            sys.exit(1)
        program = args.h1
    elif args.file:
        data = parse_scope_file(args.file)
        program = data.get("program", Path(args.file).stem)
    else:
        print("Specify --h1 <handle> or --file <path>", file=sys.stderr)
        sys.exit(1)

    scope_file = CONFIG_DIR / f"{program}.yaml"
    scope_file.write_text(yaml.dump(data, default_flow_style=False))
    ACTIVE_FILE.write_text(program)
    print(f"Imported scope: {scope_file}")
    print(f"  In-scope rules: {len(data.get('in_scope', []))}")
    print(f"  Out-of-scope rules: {len(data.get('out_of_scope', []))}")


def cmd_check(args):
    checker = load_checker()
    result = checker.check(args.target)

    if args.quiet:
        sys.exit(0 if result.in_scope else 1)

    if result.in_scope:
        print(f"{GREEN}✓ IN SCOPE{RESET}: {args.target}")
        print(f"  Matched: {result.matched_rule}")
    else:
        print(f"{RED}✗ OUT OF SCOPE{RESET}: {args.target}")
        print(f"  Reason: {result.reason}")
        if result.matched_rule:
            print(f"  Matched exclusion: {result.matched_rule}")


def cmd_filter(args):
    checker = load_checker()

    for line in sys.stdin:
        target = line.strip()
        if not target:
            continue

        result = checker.check(target)
        if result.in_scope:
            if args.verbose:
                print(f"{GREEN}✓{RESET} {target}")
            else:
                print(target)
        elif args.verbose:
            print(f"{RED}✗{RESET} {target}", file=sys.stderr)


def cmd_use(args):
    scope_file = CONFIG_DIR / f"{args.program}.yaml"
    if not scope_file.exists():
        print(f"No scope file for '{args.program}'", file=sys.stderr)
        sys.exit(1)
    ACTIVE_FILE.write_text(args.program)
    print(f"Active program: {args.program}")


def cmd_list(args):
    if not CONFIG_DIR.exists():
        print("No programs configured. Run: scope-guard init <name>")
        return

    active = get_active_scope()
    for f in sorted(CONFIG_DIR.glob("*.yaml")):
        marker = " ←" if f.stem == active else ""
        data = yaml.safe_load(f.read_text())
        n_in = len(data.get("in_scope", []))
        n_out = len(data.get("out_of_scope", []))
        print(f"  {BOLD}{f.stem}{RESET} ({n_in} in, {n_out} out){marker}")


def cmd_show(args):
    checker = load_checker()
    print(f"{BOLD}Program:{RESET} {checker.program}")
    print(f"\n{GREEN}In Scope:{RESET}")
    for rule in checker.in_scope:
        print(f"  [{rule.type}] {rule.value}")
    print(f"\n{RED}Out of Scope:{RESET}")
    for rule in checker.out_of_scope:
        print(f"  [{rule.type}] {rule.value}")


def main():
    parser = argparse.ArgumentParser(prog="scope-guard", description="Bug bounty scope checker")
    subparsers = parser.add_subparsers(dest="command")

    init_p = subparsers.add_parser("init", help="Create new scope file")
    init_p.add_argument("program", help="Program name")

    import_p = subparsers.add_parser("import", help="Import scope from platform")
    import_p.add_argument("--h1", help="HackerOne program handle")
    import_p.add_argument("--bc", help="Bugcrowd program handle")
    import_p.add_argument("--file", help="Import from JSON/YAML file")

    check_p = subparsers.add_parser("check", help="Check if target is in scope")
    check_p.add_argument("target", help="URL, domain, or IP to check")
    check_p.add_argument("--quiet", "-q", action="store_true", help="Exit code only")

    filter_p = subparsers.add_parser("filter", help="Filter stdin to in-scope only")
    filter_p.add_argument("--verbose", "-v", action="store_true", help="Show verdicts")

    use_p = subparsers.add_parser("use", help="Set active program")
    use_p.add_argument("program", help="Program name")

    subparsers.add_parser("list", help="List configured programs")
    subparsers.add_parser("show", help="Show current scope")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "import": cmd_import,
        "check": cmd_check,
        "filter": cmd_filter,
        "use": cmd_use,
        "list": cmd_list,
        "show": cmd_show,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
