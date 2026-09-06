#!/usr/bin/env python3
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from firmware import rsa_attacks as rsa


class TestNumberTheory(unittest.TestCase):
    def test_mod_inverse(self):
        self.assertEqual(rsa.mod_inverse(3, 11), 4)
        self.assertEqual((3 * rsa.mod_inverse(3, 11)) % 11, 1)

    def test_extended_gcd(self):
        g, x, y = rsa.extended_gcd(30, 42)
        self.assertEqual(g, 6)
        self.assertEqual(30 * x + 42 * y, 6)

    def test_gcd(self):
        self.assertEqual(rsa.gcd(252, 105), 21)

    def test_prime(self):
        self.assertTrue(rsa.is_probable_prime(2))
        self.assertTrue(rsa.is_probable_prime(97))
        self.assertFalse(rsa.is_probable_prime(1))
        self.assertFalse(rsa.is_probable_prime(100))

    def test_generate_prime_bits(self):
        p = rsa.generate_prime(64, random.Random(9))
        self.assertTrue(rsa.is_probable_prime(p))
        self.assertEqual(p.bit_length(), 64)

    def test_crt(self):
        # x ≡ 2 mod 3, x ≡ 3 mod 5, x ≡ 2 mod 7  -> small result
        x = rsa.crt([0, 3, 2], [3, 5, 7])  # x ≡0 mod3, ≡3 mod5, ≡2 mod7
        self.assertEqual(x % 3, 0)
        self.assertEqual(x % 5, 3)
        self.assertEqual(x % 7, 2)

    def test_integer_nth_root(self):
        self.assertEqual(rsa.integer_nth_root(9, 2), 3)
        self.assertIsNone(rsa.integer_nth_root(10, 2))
        self.assertEqual(rsa.integer_nth_root(27, 3), 3)


class TestFermat(unittest.TestCase):
    def test_demo(self):
        r = rsa.demo_fermat(256, random.Random(1234))
        self.assertTrue(r["recovered"])

    def test_p_q_aside(self):
        p = 10007
        q = 10009
        n = p * q
        res = rsa.fermat_factorization(n)
        self.assertIsNotNone(res)
        self.assertEqual(set(res), {p, q})


class TestCommonModulus(unittest.TestCase):
    def test_attack(self):
        rng = random.Random(1)
        _, _, n, _, _, _ = rsa.generate_keypair(rng, 256)
        e1, e2 = 65537, 17
        self.assertEqual(rsa.gcd(e1, e2), 1)
        m = 0xDEADBEEF12345678
        c1, c2 = rsa.rsa_encrypt(m, e1, n), rsa.rsa_encrypt(m, e2, n)
        self.assertEqual(rsa.common_modulus_attack(c1, c2, e1, e2, n), m)

    def test_demo(self):
        r = rsa.demo_common_modulus(256, random.Random(1234))
        self.assertTrue(r["recovered"])


class TestWiener(unittest.TestCase):
    def test_attack(self):
        rng = random.Random(7)
        n, e, d = rsa.generate_small_d_keypair(rng, 256)
        self.assertLess(d.bit_length(), (256 // 4) + 2)
        self.assertEqual(rsa.wiener_attack(e, n), d)

    def test_demo(self):
        r = rsa.demo_wiener(256, random.Random(1234))
        self.assertTrue(r["recovered"])


class TestHastad(unittest.TestCase):
    def test_attack(self):
        rng = random.Random(3)
        m = 0xC0FFEE
        cts, mods = [], []
        for _ in range(3):
            while True:
                p = rsa.generate_prime(64, rng)
                q = rsa.generate_prime(64, rng)
                n = p * q
                if rsa.gcd(3, (p - 1) * (q - 1)) == 1:
                    break
            mods.append(n)
            cts.append(rsa.rsa_encrypt(m, 3, n))
        self.assertEqual(rsa.hastad_broadcast_attack(cts, mods, 3), m)

    def test_demo(self):
        r = rsa.demo_hastad(random.Random(1234))
        self.assertTrue(r["recovered"])


class TestKeypair(unittest.TestCase):
    def test_rsa_roundtrip(self):
        rng = random.Random(5)
        _, _, n, e, d, _ = rsa.generate_keypair(rng, 256)
        m = 123456789
        self.assertEqual(rsa.rsa_decrypt(rsa.rsa_encrypt(m, e, n), d, n), m)


class TestCLI(unittest.TestCase):
    def test_help(self):
        old = sys.argv
        sys.argv = ["rsa_attacks", "--help"]
        try:
            with self.assertRaises(SystemExit):
                rsa.main()
        finally:
            sys.argv = old

    def test_all_exits_zero(self):
        self.assertEqual(rsa.main(["all", "--bits", "192", "--seed", "42"]), 0)


if __name__ == "__main__":
    unittest.main()
