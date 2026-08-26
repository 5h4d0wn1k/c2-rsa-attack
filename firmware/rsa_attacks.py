#!/usr/bin/env python3
"""
C2 — RSA Common-Attack Suite
Educational RSA attack demonstrations for authorized security testing only.
"""

import argparse
import math
import secrets
import sys
from typing import Tuple, Optional, List
from fractions import Fraction
from sympy import isprime, mod_inverse, factorint, gcd, sqrt, Rational

# === RSA Key Generation ===

def generate_prime(bits: int) -> int:
    """Generate a random prime number of specified bit length."""
    while True:
        p = secrets.randbits(bits) | (1 << bits - 1) | 1
        if isprime(p):
            return p

def generate_rsa_keypair(bits: int = 512) -> Tuple[int, int, int, int]:
    """Generate RSA keypair (n, e, d, phi)."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return n, e, d, phi

def generate_weak_rsa(bits: int = 512, small_d: bool = False) -> Tuple[int, int, int, int]:
    """Generate RSA with weak parameters for attack demonstration."""
    if small_d:
        # Generate small d for Wiener attack
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = secrets.randbits(bits) | 1
        d = secrets.randbits(bits // 4) | 1  # Small d
        while gcd(d, phi) != 1:
            d += 2
        e = mod_inverse(d, phi) % phi
        return n, e, d, phi
    else:
        # Generate close p, q for Fermat factorization
        p = generate_prime(bits // 2)
        q = p + 2  # Close primes
        while not isprime(q):
            q += 2
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = mod_inverse(e, phi)
        return n, e, d, phi

def rsa_encrypt(m: int, e: int, n: int) -> int:
    """RSA encryption."""
    return pow(m, e, n)

def rsa_decrypt(c: int, d: int, n: int) -> int:
    """RSA decryption."""
    return pow(c, d, n)


# === Wiener Attack ===

def continued_fraction_expansion(num: int, den: int) -> List[int]:
    """Compute continued fraction expansion of num/den."""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf

def convergents_from_cf(cf: List[int]) -> List[Tuple[int, int]]:
    """Generate convergents from continued fraction expansion."""
    convergents = []
    for i in range(len(cf)):
        if i == 0:
            convergents.append((cf[0], 1))
        elif i == 1:
            convergents.append((cf[0] * cf[1] + 1, cf[1]))
        else:
            h = cf[i] * convergents[i-1][0] + convergents[i-2][0]
            k = cf[i] * convergents[i-1][1] + convergents[i-2][1]
            convergents.append((h, k))
    return convergents

def wiener_attack(e: int, n: int) -> Optional[int]:
    """
    Wiener's attack on RSA with small private exponent.
    Recovers d when d < n^(1/4) / 3.
    """
    cf = continued_fraction_expansion(e, n)
    convergents = convergents_from_cf(cf)
    
    for k, d in convergents:
        if k == 0 or d == 0:
            continue
        phi = (e * d - 1) // k
        # Check if phi is valid
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc = int(math.isqrt(discriminant))
        if sqrt_disc * sqrt_disc == discriminant:
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            if p * q == n:
                return d
    return None

def demo_wiener_attack(bits: int = 512):
    """Demonstrate Wiener attack."""
    print("\n[Wiener Attack]")
    print("Generating RSA with small private exponent...")
    n, e, d, _ = generate_weak_rsa(bits, small_d=True)
    
    message = 123456789
    ciphertext = rsa_encrypt(message, e, n)
    
    print(f"Public Key:  (e={e}, n={n})")
    print(f"Original d:  {d}")
    
    recovered_d = wiener_attack(e, n)
    
    if recovered_d and recovered_d == d:
        print(f"Recovered d: {recovered_d}")
        decrypted = rsa_decrypt(ciphertext, recovered_d, n)
        print(f"Attack SUCCESSFUL! Message: {decrypted}")
    else:
        print("Attack failed or d not recovered")


# === Hastad Broadcast Attack ===

def crt(remainders: List[int], moduli: List[int]) -> int:
    """Chinese Remainder Theorem."""
    if len(remainders) != len(moduli):
        raise ValueError("Must have same number of remainders and moduli")
    
    M = 1
    for m in moduli:
        M *= m
    
    x = 0
    for i in range(len(moduli)):
        Mi = M // moduli[i]
        yi = mod_inverse(Mi, moduli[i])
        x += remainders[i] * Mi * yi
    
    return x % M

def cube_root(n: int) -> Optional[int]:
    """Compute integer cube root if it exists."""
    if n == 0:
        return 0
    x = int(round(n ** (1.0/3.0)))
    for i in range(max(0, x-2), x+3):
        if i**3 == n:
            return i
    return None

def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int) -> Optional[int]:
    """
    Hastad's broadcast attack.
    When same message encrypted with e different moduli using e=3.
    """
    if len(ciphertexts) < e:
        return None
    
    # Use CRT to combine ciphertexts
    combined = crt(ciphertexts[:e], moduli[:e])
    
    # Take e-th root
    plaintext = cube_root(combined)
    
    return plaintext

def demo_hastad_broadcast(bits: int = 512, e: int = 3):
    """Demonstrate Hastad broadcast attack."""
    print("\n[Hastad Broadcast Attack]")
    print(f"Generating {e} RSA keypairs with e={e}...")
    
    message = secrets.randbits(bits // 4)
    ciphertexts = []
    moduli = []
    
    for i in range(e):
        while True:
            p = generate_prime(bits // 2)
            q = generate_prime(bits // 2)
            n = p * q
            phi = (p - 1) * (q - 1)
            if gcd(e, phi) == 1:
                break
        
        c = pow(message, e, n)
        ciphertexts.append(c)
        moduli.append(n)
        print(f"  Recipient {i+1}: n={n}")
    
    print(f"Original message: {message}")
    
    recovered = hastad_broadcast_attack(ciphertexts, moduli, e)
    
    if recovered == message:
        print(f"Recovered message: {recovered}")
        print("Attack SUCCESSFUL!")
    else:
        print("Attack failed")


# === Franklin-Reiter Related Message Attack ===

def franklin_reiter_attack(c1: int, c2: int, e: int, n: int, delta: int) -> Optional[int]:
    """
    Franklin-Reiter related message attack.
    When m2 = m1 + delta and both encrypted with same (n, e).
    """
    # For e=3, use the formula
    if e == 3:
        # Compute GCD of polynomials
        # c1 = m1^3 mod n
        # c2 = (m1 + delta)^3 mod n
        # We use the formula for e=3
        a = delta
        b = (2 * c1 - pow(delta, 3, n) + 2 * c2) % n
        
        # m1 = (b * inverse(3 * a, n)) % n if 3*a is invertible
        inv_3a = mod_inverse(3 * a, n)
        if inv_3a is None:
            return None
        m1 = (b * inv_3a) % n
        return m1
    return None

def demo_franklin_reiter(bits: int = 512):
    """Demonstrate Franklin-Reiter attack."""
    print("\n[Franklin-Reiter Related Message Attack]")
    
    n, e, d, phi = generate_rsa_keypair(bits)
    
    # Generate related messages
    m1 = secrets.randbits(bits // 4)
    delta = secrets.randbits(32)
    m2 = m1 + delta
    
    # Encrypt
    c1 = rsa_encrypt(m1, e, n)
    c2 = rsa_encrypt(m2, e, n)
    
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"delta = {delta}")
    print(f"m1 = {m1}")
    print(f"m2 = {m2}")
    
    recovered = franklin_reiter_attack(c1, c2, e, n, delta)
    
    if recovered is not None:
        print(f"Recovered m1: {recovered}")
        if recovered == m1:
            print("Attack SUCCESSFUL!")
        else:
            print("Attack failed: wrong value recovered")
    else:
        print("Attack failed: could not recover message")


# === Fermat Factorization ===

def fermat_factorization(n: int) -> Optional[Tuple[int, int]]:
    """
    Fermat's factorization method.
    Works when p and q are close together.
    """
    a = math.isqrt(n) + 1
    b2 = a * a - n
    b = math.isqrt(b2)
    
    attempts = 0
    max_attempts = 1000000
    
    while attempts < max_attempts:
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == n:
                return (p, q)
        a += 1
        b2 = a * a - n
        b = math.isqrt(b2)
        attempts += 1
    
    return None

def demo_fermat(bits: int = 1024):
    """Demonstrate Fermat factorization."""
    print("\n[Fermat Factorization]")
    
    # Generate close primes
    p = generate_prime(bits // 2)
    q = p + 2
    while not isprime(q):
        q += 2
    
    n = p * q
    print(f"n = {n}")
    print(f"(Generated with p and q close together)")
    
    print("Attempting factorization...")
    result = fermat_factorization(n)
    
    if result:
        p_found, q_found = result
        print(f"Found p = {p_found}")
        print(f"Found q = {q_found}")
        if p_found * q_found == n:
            print("Attack SUCCESSFUL!")
        else:
            print("Attack failed: factors don't multiply to n")
    else:
        print("Attack failed: could not factor n")


# === Common Modulus Attack ===

def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> Optional[int]:
    """
    Common modulus attack.
    When same message encrypted with same n but different exponents.
    """
    # Extended Euclidean algorithm
    g, s, t = extended_gcd(e1, e2)
    
    if g != 1:
        return None  # Exponents must be coprime
    
    # Compute s and t with proper signs
    if s < 0:
        c1 = pow(c1, -s, n)
        s = -s
    if t < 0:
        c2 = pow(c2, -t, n)
        t = -t
    
    # Recover message
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def demo_common_modulus(bits: int = 512):
    """Demonstrate common modulus attack."""
    print("\n[Common Modulus Attack]")
    
    n, e, d, phi = generate_rsa_keypair(bits)
    
    # Choose two coprime exponents
    e1 = 65537
    e2 = 3
    while gcd(e1, e2) != 1:
        e2 += 2
    
    message = secrets.randbits(bits // 4)
    
    c1 = rsa_encrypt(message, e1, n)
    c2 = rsa_encrypt(message, e2, n)
    
    print(f"n = {n}")
    print(f"e1 = {e1}")
    print(f"e2 = {e2}")
    print(f"message = {message}")
    
    recovered = common_modulus_attack(c1, c2, e1, e2, n)
    
    if recovered == message:
        print(f"Recovered message: {recovered}")
        print("Attack SUCCESSFUL!")
    else:
        print("Attack failed")


# === Main CLI ===

def main():
    parser = argparse.ArgumentParser(
        description="C2 — RSA Common-Attack Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attacks:
  wiener         Wiener's attack on small private exponent
  hastad         Hastad's broadcast attack
  franklin-reiter  Franklin-Reiter related message attack
  fermat         Fermat factorization (close p, q)
  common-modulus Common modulus attack
  all            Run all demonstrations
        """
    )
    
    parser.add_argument("attack", 
                       choices=["wiener", "hastad", "franklin-reiter", "fermat", "common-modulus", "all"],
                       help="Attack to demonstrate")
    
    parser.add_argument("--bits", type=int, default=512,
                       help="RSA key size in bits (default: 512)")
    
    parser.add_argument("--recipients", type=int, default=3,
                       help="Number of recipients for Hastad attack (default: 3)")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("C2 — RSA Common-Attack Suite")
    print("=" * 60)
    
    if args.attack == "wiener":
        demo_wiener_attack(args.bits)
    elif args.attack == "hastad":
        demo_hastad_broadcast(args.bits, args.recipients)
    elif args.attack == "franklin-reiter":
        demo_franklin_reiter(args.bits)
    elif args.attack == "fermat":
        demo_fermat(args.bits)
    elif args.attack == "common-modulus":
        demo_common_modulus(args.bits)
    elif args.attack == "all":
        demo_wiener_attack(args.bits)
        demo_hastad_broadcast(args.bits, 3)
        demo_franklin_reiter(args.bits)
        demo_fermat(args.bits)
        demo_common_modulus(args.bits)
    
    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
