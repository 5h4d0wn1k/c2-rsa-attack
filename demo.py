#!/usr/bin/env python3
"""
C2 — RSA Common-Attack Suite: offline demo.

Each attack runs against an intentionally weak keygen and verifies the
recovered key/message really is correct. Fully offline, exits 0 on success.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firmware import rsa_attacks as rsa


def main():
    print("C2 RSA Common-Attack Suite — offline demo (authorized lab only)")
    # Deterministic for reproducible offline verification
    rng = random.Random(0xC0FFEE)
    results = []
    results.append(rsa.demo_fermat(256, rng))
    results.append(rsa.demo_common_modulus(256, rng))
    results.append(rsa.demo_wiener(256, rng))
    results.append(rsa.demo_hastad(rng, recips=3))
    print("\n--- summary ---")
    for r in results:
        print(f"  {r['attack']}: recovered={r['recovered']}")
    assert all(r["recovered"] for r in results)
    rd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    rsa.save_report(results, rd)
    print("\nAll offline demos PASSED: 4 attacks, real key recovery.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
