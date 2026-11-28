#!/usr/bin/env python3
"""Fails if a C crypto library is in the normal dependency graph of any target platform."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANNED = ("openssl-sys", "aws-lc-sys")
# `--target all` also covers Windows and macOS dependencies when run on Linux.
TREE = ["cargo", "tree", "--workspace", "--edges", "normal", "--target", "all"]


def cargo_tree(*extra):
    try:
        result = subprocess.run(
            TREE + list(extra), cwd=ROOT, capture_output=True, text=True, check=False
        )
    except OSError as error:
        sys.exit(f"could not run cargo: {error}")
    if result.returncode != 0:
        sys.exit(f"cargo tree failed:\n{result.stderr.strip()}")
    return result.stdout


def main():
    pattern = re.compile(r"^(" + "|".join(map(re.escape, BANNED)) + r") v", re.MULTILINE)
    found = sorted(set(pattern.findall(cargo_tree("--prefix", "none"))))
    if not found:
        print("PURE_RUST_CRYPTO_OK")
        return 0
    for crate in found:
        print(f"banned crypto crate: {crate}", file=sys.stderr)
        print(cargo_tree("--invert", crate), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
