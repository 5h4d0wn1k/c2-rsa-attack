> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C2 — RSA Common-Attack Suite

An **RSA cryptanalysis** laboratory implementing **Wiener's attack, Hastad
broadcast, Fermat factorization**, and the **common modulus attack** against
deliberately weak lab keys — with verified key/message recovery.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/c2-rsa-attack)](https://github.com/5h4d0wn1k/c2-rsa-attack)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c2-rsa-attack)](https://github.com/5h4d0wn1k/c2-rsa-attack)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/c2-rsa-attack)](https://github.com/5h4d0wn1k/c2-rsa-attack)

## Why C2

RSA's security depends on key parameters — and when those parameters are weak,
the math works against it. C2 is an **educational cryptanalysis** lab that
implements, from pure number theory, four classic RSA attacks: Fermat
factorization for close primes, the common modulus attack via the extended
Euclidean algorithm, Wiener's continued-fraction attack for small private
exponents, and Hastad's broadcast attack with CRT plus an integer e-th root.
Each attack runs offline, asserts the recovered value actually matches, and
shows exactly when RSA key parameters become vulnerable. Break only keys you
own or are authorized to test — cryptanalysis of third-party material may
violate CFAA, DMCA, and export controls.

## Features

- **Wiener's attack** — recovers `d` from `(e, n)` via continued fractions when `d < n⁰·²⁵/3`
- **Hastad broadcast attack** — recovers `m` from `e` ciphertexts under different moduli (CRT + integer root)
- **Common modulus attack** — recovers `m` from two ciphertexts sharing `N` with coprime exponents
- **Fermat factorization** — factors `N` when `p` and `q` are close
- **Weak keygen** — deliberate weak lab keys (small d, close primes, shared modulus)
- **Verified recovery** — every demo asserts `recovered == original`
- **Deterministic** — reproducible `--seed` runs
- **Pure stdlib** — Miller-Rabin, `math`, `random`; no third-party crypto libraries

## Quickstart

```bash
# Offline demo — all four attacks, key-recovery asserted, exit 0
python3 demo.py

# Individual attacks
python3 firmware/rsa_attacks.py fermat --bits 256
python3 firmware/rsa_attacks.py common-modulus --bits 256
python3 firmware/rsa_attacks.py wiener --bits 256
python3 firmware/rsa_attacks.py hastad --recips 3

# Full deterministic run
python3 firmware/rsa_attacks.py all --seed 42

# Tests
python3 -m unittest discover -s tests
```

## Project structure

- `firmware/rsa_attacks.py` — number-theory primitives and all four attacks
- `demo.py` — offline demo harness writing `reports/`
- `tests/` — math primitives and per-attack recovery checks
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ETHICS.md`, `SCOPE.md`, `SECURITY.md` — standards and legal scope

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)