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


    def addCommute(self):
        """
        Verify that addition is commutative.
        """
        P,Q = randomEcPoint(), randomEcPoint()
        R1 = P + Q
        R2 = Q + P
        self.assertEqual(R1, R2)


    def addDistribute(self):
        """
        Verify that addition is distributive.
        """
        X,Y,Z = randomEcPoint(), randomEcPoint(), randomEcPoint()
        R1 = (X+Y)+Z
        R2 = X+(Y+Z)
        self.assertEqual(R1, R2)


    def serializeRT(self):
        """
        Tests serialization by performing serialize-deserialize and comparing
        the result to the original value.
        """
        a = randomZ(orderEc())
        G = generatorEc()
        P1 = a*G

        x = serializeEc(P1)
        P2 = deserializeEc(x)
        self.assertEqual(P1, P2)


    def testAddCommute(self):
        repeat(self.addCommute, 100)


    def testAddDistribute(self):
        repeat(self.addDistribute, 100)


    def testMulCommute(self):
        repeat(self.mulCommute, 100)


    def testMulND(self):
        repeat(self.mulNonDegnerate, 100)


    def testSerializeRT(self):
        repeat(self.serializeRT, 100)


    def testRandom(self):
        """
        Tests the randomEcPoint() function doesn't generate repeats over a 
        small size.
        """
        randomNoRepeat(randomEcPoint, 1000)


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


    def testProto(self):
        x, X = newKeyPair()
        y, Y = newKeyPair()

        # LT server keys
        s, S = newKeyPair()

        k1 = sharedKeyServer(X, y, s, "AD text")
        k2 = sharedKeyClient(x, Y, S, "AD text")
        dp(k1=k1, k2=k2)

        self.assertEqual(k1, k2)


from ecqv import *
class EcqvTests(TestCase):
    """
    Tests for ECQV implicit certificates.
    """
    def setUp(self):
        # Standing keys
        self.caKeyPair = newKeyPair()
        self.serverSecret = newKeyPair()


    def testSignValidate(self):
        """
        Generate an implicit cert and validate it.
        """
        alpha, alphaG = self.serverSecret
        caPrivkey, caPubkey = self.caKeyPair
        idText = "delphi.remote-crypto.io"

        r, cert = sign(idText, alphaG, caPrivkey)
        s,S = validate(idText, alpha, r, cert, caPubkey)


    def testRecoverPubkey(self):
        """
        Tests that client and server can generate the same pubkey.
        """
        # Generate the cert
        alpha, alphaG = self.serverSecret
        caPrivkey, caPubkey = self.caKeyPair
        idText = "delphi.remote-crypto.io"
        r, cert = sign(idText, alphaG, caPrivkey)

        # Generate the pubkey using the server method
        _,pubkey1 = validate(idText, alpha, r, cert, caPubkey)

        # Generate the pubkey using the client method
        pubkey2 = recoverPubkey(idText, cert, caPubkey)

        # Compare
        self.assertEqual(pubkey1, pubkey2)        






# Run!
if __name__ == '__main__':
    unittest.main()