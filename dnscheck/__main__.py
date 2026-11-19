"""Allow running DNSGuard via `python3 -m dnscheck`."""

import sys

from dnscheck.cli.commands import main

if __name__ == "__main__":
    sys.exit(main())
