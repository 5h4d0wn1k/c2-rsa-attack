# C2 — RSA Common-Attack Suite

A real RSA attack toolkit for **authorized security testing and education**.
Each attack is implemented with real number-theory mechanics, runs fully
offline, and verifies that the recovered key/message is genuinely correct.

## IMPORTANT: Read before use.

**For educational and authorized security testing purposes only.**

- You MUST have explicit written authorization to test a system before
  applying cryptanalysis to it.
- Breaking encryption you do not own or lack authorization to test may violate
  the **Computer Fraud and Abuse Act (CFAA)**, the **Digital Millennium
  Copyright Act (DMCA)**, state computer-crime statutes, and applicable export
  controls. You are solely responsible for lawful use.
- Use only on your own systems or within a defined lab scope (lab-* hosts,
  192.0.2.x ranges, example.com).
- Provided "AS IS", no warranty; the author is not liable for misuse or damage.

## What genuinely works (real mechanics, stdlib only)

- **Fermat factorization** — factors N when p and q are close together.
- **Common modulus attack** — recovers m from c1=m^e1, c2=m^e2 under the same
  N with coprime e1/e2 (extended Euclidean + negative-exponent `pow`).
- **Wiener's attack** — recovers the private exponent d from (e,n) via
  continued fractions when d < N^(1/4)/3.
- **Hastad broadcast attack** — recovers m from e ciphertexts of the same
  message under different coprime moduli using the Chinese Remainder Theorem
  followed by an integer e-th root (e=3).

Each demo generates deliberately weak lab keys and **asserts** the recovered
value actually matches (key recovery check), so a nonzero exit means a failed
attack. No third-party crypto libraries are required (pure stdlib `hashlib`/
`math`/`random` + Miller-Rabin primality).

## Requirements

- Python 3.8+ (standard library only).

## Usage

```bash
# List options
python3 firmware/rsa_attacks.py --help

# Individual attacks (diagnostics with parameter labels)
python3 firmware/rsa_attacks.py fermat --bits 256
python3 firmware/rsa_attacks.py common-modulus --bits 256
python3 firmware/rsa_attacks.py wiener --bits 256
python3 firmware/rsa_attacks.py hastad --recips 3

# Deterministic seed
python3 firmware/rsa_attacks.py all --seed 42

# Full run
python3 firmware/rsa_attacks.py all
```

Exit code is 0 only if every attack reported a true key/message recovery.

## Demo (offline, deterministic)

```bash
python3 demo.py
```

Runs all four attacks against seeded lab keys and verifies recovery. Exits 0
on success.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. **Offline unit tests**: `python3 -m unittest discover -s tests` — validates
   number theory primitives and each attack against generated lab keys.
2. **Offline demo**: `python3 demo.py` — run all 4 attacks, confirm exit 0.
3. **Reproducibility**: `python3 firmware/rsa_attacks.py all --seed 42` must
   produce the same key recovery output each run.
4. **Cross-validation**: on a lab host, generate an RSA modulus with close
   primes or a small d and confirm the suite recovers the factors/exponent.
5. **Lab scope**: never run against third-party hosts or keys without written
   authorization.

## Metrics

- Attacks: **4** (Fermat, Common Modulus, Wiener, Hastad broadcast).
- Primality: Miller-Rabin (40 rounds default, 30 for generation).
- Determinism: fixed `--seed` yields reproducible runs.
- Verification: every demo asserts `recovered == original` before reporting.
- Reports: JSON under `reports/`, `gitignored`.

## License

MIT
