#!/usr/bin/env python3
"""
DNSGuard (dnscheck) executable entry point.
Supports both rich CLI diagnostics and local Web/Desktop UI dashboard (`dnscheck ui`).
"""

import sys
from dnscheck.cli.commands import main

if __name__ == "__main__":
    sys.exit(main())
