"""
main.py — Entry point.

Usage (on target Windows machine):
    python main.py

Flow:
    Phase 0 — Auto-discovery
    Phase 1 — Setup wizard
    Phase 2 — Run tools (winPEAS, SharpHound, PowerView, Seatbelt)
    Phase 3 — Parse output → generate Report 1 + Report 2
"""

import sys
import os
import traceback

sys.path.insert(0, os.path.dirname(__file__))

from core.wizard import run as run_wizard, C, _section
from core.runner import run_all
from core.parser import parse_all
from core.report import generate_all


def main():
    try:
        # ── Phase 0 + 1: Discovery & Wizard ──────────────────────────────
        config = run_wizard()

        # ── Phase 2: Enumeration ─────────────────────────────────────────
        raw_outputs = run_all(config)

        if not raw_outputs:
            print(f"\n  {C.YELLOW}[!] No tool output collected. "
                  f"Check that binaries are present and the target is reachable.{C.RESET}")
            sys.exit(1)

        # ── Phase 3: Parse & Report ───────────────────────────────────────
        _section("PHASE 3 — Parsing & Report Generation")

        print(f"  {C.CYAN}[*]{C.RESET} Parsing tool outputs...")
        findings = parse_all(raw_outputs)

        if not findings:
            print(f"  {C.YELLOW}[!] No findings parsed — check raw output files in output/raw/.{C.RESET}")
        else:
            print(f"  {C.GREEN}[+]{C.RESET} Parsed {len(findings)} finding(s).")

        print(f"  {C.CYAN}[*]{C.RESET} Generating reports...")
        r1, r2, md = generate_all(findings, config, raw_outputs=raw_outputs)

        _section("Done")
        print(f"  {C.GREEN}[✓]{C.RESET} Report 1 (Findings):         {r1}")
        print(f"  {C.GREEN}[✓]{C.RESET} Report 2 (Attack Commands):   {r2}")
        print(f"  {C.GREEN}[✓]{C.RESET} Combined Markdown:            {md}")
        print()
        print(f"  {C.DIM}Open the HTML files in any browser to view the reports.{C.RESET}\n")

    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Interrupted by user.{C.RESET}\n")
        sys.exit(0)
    except Exception:
        print(f"\n  {C.RED}[!] Unexpected error:{C.RESET}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
