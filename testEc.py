#!/usr/bin/eval python
"""
Tests for elliptic curve module.
"""
from testcommon import *
from ec import *
from unittest import TestCase, SkipTest
import unittest


class EcTests(TestCase):
    """
    Tests fopr the EC module
    """
    def mulCommute(self):
        """
        Verifies that multiplication is commutative.
        """
        a,b = randomZ(orderEc()), randomZ(orderEc())
        G = generatorEc()

        # Perform multiplication in different orders and compare the result.
        P1 = b*(a*G)
        P2 = a*(b*G)
        self.assertEqual(P1, P2)


    def mulNonDegnerate(self):
        """
        Verifies that multiplication is non-degenerate.
        """
        a,b = randomZ(orderEc()), randomZ(orderEc())
        G = generatorEc()

        # Perform multiplication in different orders and compare the result.
        P = (a*G)
        Q = a*P
        self.assertNotEqual(P, 0)
        self.assertNotEqual(Q, 0)


    def serializeRT(self):
        """
        Tests serialization by performing serialize-deserialize and comparing
        the result to the original value.
        """
        a= randomZ(orderEc())
        G = generatorEc()
        P1 = a*G

        x = serializeEc(P1)
        P2 = deserializeEc(x)
        self.assertEqual(P1, P2)


    def testMulCommute(self):
        repeat(self.mulCommute, 100)


    def testMulND(self):
        repeat(self.mulNonDegnerate, 100)


    def testSerializeRT(self):
        repeat(self.serializeRT, 100)


from ecdh import *
class EcdhTests(TestCase):
    """
    Tests for the EC Diffie-Hellman module.
    """
    def dhKeyAgreement(self):
        """
        Runs and tests DH key agreement.
        """
        x, X = newKeyPair()
        y, Y = newKeyPair()
        k1 = x*Y
        k2 = y*X

        self.assertEqual(k1, k2)


    def testDh(self):
        repeat(self.dhKeyAgreement, 100)

# Run!
if __name__ == '__main__':
    unittest.main()