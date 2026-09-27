#!/usr/bin/env python3
"""
AEGIS CRYPT - Unified Entry Point
===================================
Double-click / run with no arguments  -> launches the desktop GUI.
Run with a subcommand (encrypt/decrypt/info) -> runs as a CLI tool.

Examples:
    python aegis.py                          # opens the GUI
    python aegis.py encrypt -i report.pdf    # CLI encrypt
    python aegis.py decrypt -i report.pdf.axc
"""
import sys


def main() -> int:
    if len(sys.argv) > 1:
        import aegis_cli
        return aegis_cli.main(sys.argv[1:])
    else:
        import aegis_gui
        aegis_gui.main()
        return 0


if __name__ == "__main__":
    sys.exit(main())
