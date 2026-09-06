#!/usr/bin/env python3
"""
C2 — RSA Common-Attack Suite
============================

Real RSA attack demonstrations for AUTHORIZED security testing / education.

Implemented attacks (stdlib-only, fully deterministic given seeded inputs):
  * Fermat factorization       -> factors N when p,q are close together
  * Common modulus             -> recovers m when same N, coprime e1/e2
  * Wiener's attack            -> recovers d when d < N^(1/4)/3
  * Hastad broadcast (via CRT) -> recovers m when e copies share m (e=3)

Every attack is demonstrated offline with parameter labels and verifies that
the recovered key/message actually decrypts / matches the plaintext.

IMPORTANT: Read before use. Educational / authorized use only.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Number theory primitives (stdlib only)
# ---------------------------------------------------------------------------

def mod_inverse(a: int, m: int) -> int:
    """Modular inverse of a mod m, or raises ValueError if not coprime."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return (gcd, x, y) such that a*x + b*y == gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rng: random.Random) -> int:
    """Generate a probable prime of the given bit length."""
    lo = 1 << (bits - 1)
    hi = (1 << bits) - 1
    while True:
        candidate = rng.randrange(lo, hi) | 1
        if is_probable_prime(candidate, rounds=30):
            return candidate


def generate_keypair(rng: random.Random, bits: int = 256, e: int = 65537):
    """Generate (p, q, n, e, d, phi)."""
    p = generate_prime(bits // 2, rng)
    q = generate_prime(bits // 2, rng)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return p, q, n, e, d, phi


def rsa_encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def rsa_decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def generate_fermat_keypair(rng: random.Random, bits: int = 256):
    """Generate N = p*q with p,q close (q = next_prime(p)) for Fermat."""
    p = generate_prime(bits // 2, rng)
    q = p + 2
    while not is_probable_prime(q, rounds=30):
        q += 2
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return p, q, n, e, d


def generate_small_d_keypair(rng: random.Random, bits: int = 256):
    """Generate RSA with a small d for Wiener's attack."""
    while True:
        p = generate_prime(bits // 2, rng)
        q = generate_prime(bits // 2, rng)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = rng.randrange(3, phi)
        # small d: about 1/4 of n bits
        d = rng.randrange(2, (1 << (bits // 4)) + 1)
        if gcd(d, phi) == 1:
            e = mod_inverse(d, phi)
            return n, e, d


# ---------------------------------------------------------------------------
# Attack 1: Fermat factorization
# ---------------------------------------------------------------------------

def fermat_factorization(n: int, max_iter: int = 1000000) -> Optional[Tuple[int, int]]:
    """Fermat's method: works when p and q are close together."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    for _ in range(max_iter):
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == n:
                return (p, q)
        a += 1
        b2 = a * a - n
    return None


# ---------------------------------------------------------------------------
# Attack 2: Common modulus
# ---------------------------------------------------------------------------

def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> Optional[int]:
    """Recover m when c1=m^e1 mod n, c2=m^e2 mod n and gcd(e1,e2)==1."""
    g, s, t = extended_gcd(e1, e2)
    if g != 1:
        return None
    # Python pow() supports negative exponents (modular inverse)
    return (pow(c1, s, n) * pow(c2, t, n)) % n


# ---------------------------------------------------------------------------
# Attack 3: Wiener's attack
# ---------------------------------------------------------------------------

def continued_fraction(num: int, den: int) -> List[int]:
    cf = []
    while den:
        q, r = divmod(num, den)
        cf.append(q)
        num, den = den, r
    return cf


def convergents(cf: List[int]) -> List[Tuple[int, int]]:
    out = []
    for i in range(len(cf)):
        if i == 0:
            out.append((cf[0], 1))
        elif i == 1:
            out.append((cf[0] * cf[1] + 1, cf[1]))
        else:
            h = cf[i] * out[i - 1][0] + out[i - 2][0]
            k = cf[i] * out[i - 1][1] + out[i - 2][1]
            out.append((h, k))
    return out


def wiener_attack(e: int, n: int) -> Optional[int]:
    """Recover d when d is small (d < n^(1/4)/3)."""
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sq = math.isqrt(disc)
        if sq * sq != disc:
            continue
        p = (s + sq) // 2
        q = (s - sq) // 2
        if p * q == n:
            return d
    return None


# ---------------------------------------------------------------------------
# Attack 4: Hastad broadcast (CRT + e-th root)
# ---------------------------------------------------------------------------

def crt(remainders: List[int], moduli: List[int]) -> int:
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        x += r * Mi * mod_inverse(Mi, m)
    return x % M


def integer_nth_root(c: int, e: int) -> Optional[int]:
    """Return integer e-th root of c if it is a perfect power, else None."""
    lo, hi = 0, 1
    while hi ** e <= c:
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** e >= c:
            hi = mid
        else:
            lo = mid + 1
    if lo ** e == c:
        return lo
    return None


def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int) -> Optional[int]:
    """Recover m from e ciphertexts of the same m under coprime moduli."""
    if len(ciphertexts) < e or len(moduli) < e:
        return None
    combined = crt(ciphertexts[:e], moduli[:e])
    return integer_nth_root(combined, e)


# ---------------------------------------------------------------------------
# CLI + labelled offline demos
# ---------------------------------------------------------------------------

def _fmt(n: int) -> str:
    s = str(n)
    return s if len(s) <= 40 else s[:20] + "..." + s[-10:] + f"({len(s)} digits)"


def demo_fermat(bits: int, rng: random.Random) -> dict:
    print("\n[Fermat factorization]  (offsets: p,q close together)")
    p, q, n, e, d = generate_fermat_keypair(rng, bits)
    print(f"  n={_fmt(n)}  bits={bits}")
    t0 = time.time()
    res = fermat_factorization(n)
    elapsed = time.time() - t0
    if res is None:
        raise AssertionError("Fermat attack failed to factor N")
    p2, q2 = res
    ok = p2 * q2 == n
    print(f"  recovered p x q = n: {ok}  ({elapsed:.3f}s)")
    assert ok, "Fermat factors do not multiply to n"
    return {"attack": "fermat", "n_bits": bits, "recovered": ok,
            "elapsed_sec": round(elapsed, 4)}


def demo_common_modulus(bits: int, rng: random.Random) -> dict:
    print("\n[Common modulus]  (offsets: same n, coprime e1/e2)")
    _, _, n, e, d, _ = generate_keypair(rng, bits)
    e1, e2 = 65537, 17
    if gcd(e1, e2) != 1:
        return None
    m = secrets.randbits(64)
    c1, c2 = rsa_encrypt(m, e1, n), rsa_encrypt(m, e2, n)
    recovered = common_modulus_attack(c1, c2, e1, e2, n)
    ok = recovered == m
    print(f"  e1={e1} e2={e2}  message={m}")
    print(f"  recovered==message: {ok}")
    assert ok, "Common modulus attack failed"
    return {"attack": "common_modulus", "bits": bits, "recovered": ok}


def demo_wiener(bits: int, rng: random.Random) -> dict:
    print("\n[Wiener's attack]  (offsets: small private exponent d < N^0.25)")
    n, e, d = generate_small_d_keypair(rng, bits)
    recovered = wiener_attack(e, n)
    ok = recovered == d
    print(f"  n bits={bits}  d_bits={d.bit_length()}  recovered_d_bits={(recovered or 0).bit_length()}")
    print(f"  recovered d == actual d: {ok}")
    assert ok, "Wiener attack failed"
    return {"attack": "wiener", "n_bits": bits, "d_bits": d.bit_length(), "recovered": ok}


def demo_hastad(rng: random.Random, recips: int = 3, e: int = 3, msg_bits: int = 128) -> dict:
    print(f"\n[Hastad broadcast]  (offsets: e={e} identical messages, CRT)")
    m = secrets.randbits(msg_bits)
    moduli, cts = [], []
    for _ in range(e):
        while True:
            p = generate_prime(128, rng)
            q = generate_prime(128, rng)
            n = p * q
            if gcd(e, (p - 1) * (q - 1)) == 1:
                break
        moduli.append(n)
        cts.append(rsa_encrypt(m, e, n))
    recovered = hastad_broadcast_attack(cts, moduli, e)
    ok = recovered == m
    print(f"  message={m}")
    print(f"  recovered==message: {ok}")
    assert ok, "Hastad broadcast attack failed"
    return {"attack": "hastad_broadcast", "e": e, "recipients": e, "recovered": ok}


def run_all(bits: int, recips: int) -> List[dict]:
    seed = int.from_bytes(os.urandom(4), "big")
    rng = random.Random(seed)
    print(f"C2 RSA attack suite — seed={seed}")
    results = []
    results.append(demo_fermat(bits, rng))
    results.append(demo_common_modulus(bits, rng))
    results.append(demo_wiener(bits, rng))
    results.append(demo_hastad(rng, recips=recips))
    return results


def save_report(data, report_dir: str):
    os.makedirs(report_dir, exist_ok=True)
    fname = os.path.join(report_dir, f"c2_report_{int(time.time()*1000)}.json")
    with open(fname, "w") as fh:
        json.dump(data, fh, indent=2)
    return fname


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="rsa_attacks",
        description="C2 — RSA Common-Attack Suite (AUTHORIZED testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Attacks: fermat | common-modulus | wiener | hastad | all",
    )
    parser.add_argument("attack", choices=[
        "fermat", "common-modulus", "wiener", "hastad", "all"])
    parser.add_argument("--bits", type=int, default=256, help="RSA modulus bits")
    parser.add_argument("--recips", type=int, default=3, help="Hastad recipients")
    parser.add_argument("--seed", type=int, default=None, help="Deterministic seed")
    parser.add_argument("--report-dir", default="reports")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed) if args.seed is not None else random.Random()
    print("=" * 60)
    print("C2 — RSA Common-Attack Suite")
    print("=" * 60)

    dispatch = {
        "fermat": lambda: [demo_fermat(args.bits, rng)],
        "common-modulus": lambda: [demo_common_modulus(args.bits, rng)],
        "wiener": lambda: [demo_wiener(args.bits, rng)],
        "hastad": lambda: [demo_hastad(rng, recips=args.recips)],
        "all": lambda: run_all(args.bits, args.recips),
    }
    results = dispatch[args.attack]()

    print("\n" + "=" * 60)
    for r in results:
        print(f"  {r['attack']}: recovered={r['recovered']}")
    print("=" * 60)
    if args.report_dir:
        print(f"[*] Report written: {save_report(results, args.report_dir)}")
    all_ok = all(r["recovered"] for r in results)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
