# C2 — RSA Common-Attack Suite

A comprehensive toolkit for demonstrating common RSA vulnerabilities and attack vectors.

## Overview

This project implements various RSA attacks to demonstrate cryptographic weaknesses when RSA is improperly implemented. These attacks exploit mathematical properties of RSA when certain conditions are met.

## Features

- **Wiener Attack**: Exploits small private exponents using continued fractions
- **Hastad Broadcast Attack**: Decrypts RSA when same message is sent to multiple recipients
- **Franklin-Reiter Attack**: Related message attack with polynomial GCD
- **Fermat Factorization**: Factors N when p and q are close together
- **Common Modulus Attack**: Recovers message when same N is used with different exponents

## Installation

```bash
pip install pycryptodome gmpy2
```

## Usage

```bash
# Wiener attack demonstration
python3 rsa_attacks.py wiener --bits 1024

# Hastad broadcast attack
python3 rsa_attacks.py hastad --recipients 3 --bits 512

# Franklin-Reiter related message attack
python3 rsa_attacks.py franklin-reiter --bits 512

# Fermat factorization
python3 rsa_attacks.py fermat --bits 1024

# Common modulus attack
python3 rsa_attacks.py common-modulus --bits 512

# Run all demonstrations
python3 rsa_attacks.py all
```

## Attack Descriptions

### Wiener Attack
Exploits RSA when the private exponent d is small (d < N^0.25). Uses continued fraction expansion of e/N to recover d.

### Hastad Broadcast Attack
When the same plaintext is encrypted with the same modulus N but different public exponents e1, e2, e3... and the exponents are coprime, we can use CRT to recover the plaintext.

### Franklin-Reiter Attack
When two messages m1 and m2 are related (e.g., m2 = m1 + delta), and encrypted with the same (N, e), the messages can be recovered using polynomial GCD.

### Fermat Factorization
When p and q are close together, N can be factored by searching for a = sqrt(N) + k until a² - N is a perfect square.

### Common Modulus Attack
When the same message is encrypted with same N but different exponents that are coprime, the message can be recovered using extended Euclidean algorithm.

## Example Output

```
=== C2 — RSA Common-Attack Suite ===

[Wiener Attack]
Generated RSA with small private exponent
Public Key:  (65537, 1234567890...)
Recovered d: 12345...
Original d:  12345...
Attack SUCCESSFUL!

[Hastad Broadcast Attack]
Generated 3 recipients with e=3
Encrypted same message to all
Recovered via CRT: b'Attack successful!'
Attack SUCCESSFUL!
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Cryptanalysis of systems you do not own or have authorization to test is illegal
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Digital Millennium Copyright Act (DMCA)**: Circumvention of technological protection measures may be illegal
- **State Laws**: Many states have additional computer crime statutes
- **Export Controls**: Cryptographic tools may be subject to export regulations

### Acceptable Use
- Testing security of your own cryptographic implementations
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training
- CTF competitions and challenges

### Prohibited Use
- Attacking systems you do not own or have authorization to test
- Breaking encryption for unauthorized access
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
