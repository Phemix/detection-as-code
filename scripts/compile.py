#!/usr/bin/env python3
"""
compile.py — Multi-backend detection rule compiler.

Routes each rule to one or more backend compilers based on the
--backend flag. Each backend reads the appropriate search field
from the rule YAML and writes a compiled output file.

Backends:
  splunk    → reads 'search' field, writes .spl to compiled/splunk/
  sentinel  → reads 'kql_search' field, writes .kql to compiled/sentinel/
  all       → runs all configured backends

Usage:
  python scripts/compile.py                          # all backends
  python scripts/compile.py --backend splunk         # Splunk only
  python scripts/compile.py --backend sentinel       # Sentinel only
  python scripts/compile.py --file rules/...         # single rule
  python scripts/compile.py --dry-run               # preview only
"""

import argparse
import importlib
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"  {ANSI_RED}✗{ANSI_RESET}  Failed to load {path.name}: {e}")
        return None


def collect_rules(config: dict, single_file: Path | None = None) -> list[Path]:
    if single_file:
        return [single_file.resolve()]
    paths = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            paths.extend(sorted(rule_dir.glob("*.yml")))
    return paths


def get_backend_module(backend_name: str):
    """Dynamically import a backend module from scripts/backends/."""
    try:
        module = importlib.import_module(f"backends.{backend_name}")
        return module
    except ImportError as e:
        print(f"  {ANSI_RED}✗{ANSI_RESET}  Backend '{backend_name}' not found: {e}")
        return None


def get_output_dir(config: dict, backend_name: str) -> Path:
    """Get the output directory for a backend from sigma_config.yml."""
    backends = config.get("backends", {})
    backend_cfg = backends.get(backend_name, {})
    output_dir = backend_cfg.get("output_dir", f"compiled/{backend_name}")
    return ROOT / output_dir


def compile_rule(
    rule: dict,
    path: Path,
    backend_name: str,
    output_dir: Path,
    dry_run: bool = False
) -> tuple[bool, str, bool]:
    """
    Compile a single rule with the specified backend.
    Returns (success, message, skipped).
    """
    module = get_backend_module(backend_name)
    if not module:
        return False, f"Backend '{backend_name}' not available", False

    ok, msg = module.compile(rule, path, output_dir, dry_run)

    # Treat SKIP as a graceful non-failure
    skipped = msg.startswith("SKIP:")
    if skipped:
        return True, msg, True

    return ok, msg, False


def main():
    parser = argparse.ArgumentParser(description="Compile detection rules to backend query formats")
    parser.add_argument(
        "--backend",
        choices=["splunk", "sentinel", "all"],
        default="all",
        help="Backend to compile for (default: all)"
    )
    parser.add_argument("--file", type=Path, help="Compile a single rule file")
    parser.add_argument("--dry-run", action="store_true", help="Preview output without writing files")
    args = parser.parse_args()

    config = load_config()
    paths = collect_rules(config, args.file)

    if not paths:
        print("No rule files found.")
        sys.exit(0)

    # Determine which backends to run
    configured_backends = list(config.get("backends", {}).keys()) or ["splunk"]
    if args.backend == "all":
        backends_to_run = configured_backends
    else:
        backends_to_run = [args.backend]

    dry_label = "  [dry-run]" if args.dry_run else ""
    print(f"\n{ANSI_BOLD}Detection Rule Compiler{ANSI_RESET}{dry_label}  "
          f"({len(paths)} rules  |  backends: {', '.join(backends_to_run)})\n")

    # Track results per backend
    results: dict[str, dict] = {
        b: {"compiled": 0, "skipped": 0, "failed": 0}
        for b in backends_to_run
    }

    for path in paths:
        rule = load_rule(path)
        if not rule:
            for b in backends_to_run:
                results[b]["failed"] += 1
            continue

        title = rule.get("title") or rule.get("name", path.stem)
        rule_id = str(rule.get("id", ""))
        print(f"  {title} ({rule_id})")

        for backend_name in backends_to_run:
            output_dir = get_output_dir(config, backend_name)
            ok, msg, skipped = compile_rule(rule, path, backend_name, output_dir, args.dry_run)

            if skipped:
                print(f"    {ANSI_DIM}↷  [{backend_name}] {msg}{ANSI_RESET}")
                results[backend_name]["skipped"] += 1
            elif ok:
                print(f"    {ANSI_GREEN}✓{ANSI_RESET}  [{backend_name}] → {msg}")
                results[backend_name]["compiled"] += 1
            else:
                print(f"    {ANSI_RED}✗{ANSI_RESET}  [{backend_name}] {msg}")
                results[backend_name]["failed"] += 1

    # Summary
    print(f"\n{'─'*55}")
    total_failed = 0
    for backend_name in backends_to_run:
        r = results[backend_name]
        total_failed += r["failed"]
        skip_str = f"  skipped: {ANSI_YELLOW}{r['skipped']}{ANSI_RESET}" if r["skipped"] else ""
        fail_str = f"  failed: {ANSI_RED}{r['failed']}{ANSI_RESET}" if r["failed"] else f"  failed: {r['failed']}"
        print(f"  {ANSI_BOLD}{backend_name:<10}{ANSI_RESET}"
              f"  compiled: {ANSI_GREEN}{r['compiled']}{ANSI_RESET}"
              f"{skip_str}"
              f"{fail_str}")

    print()
    if total_failed > 0:
        print(f"{ANSI_RED}✗ Compilation completed with errors{ANSI_RESET}\n")
        sys.exit(1)
    else:
        print(f"{ANSI_GREEN}✓ Compilation complete{ANSI_RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()