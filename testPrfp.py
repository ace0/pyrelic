#!/usr/bin/eval python

from testcommon import *
import unittest
from unittest import TestCase
from prfp import *

class PrfpTests(TestCase):
    """
    Tests for the Vpop class.
    """
    def testKeyGen(self):
        msk = "12l3k4jh1lk23jh51l34b5l1k34j5nl134jn51lk3b51lk34b5"
        w = "super secret key selector"
        z = "lkjasdf;lkjaew;jas; dlkjas;ldfkjas;dlfkjas ;df"
        genKw(w,msk,z)


    def testEvalStable(self, n=100):
        """
        Runs eval() @n times and ensures that after deblinding, the result
        is deterministic.
        """
        Y = None
        w = "Some super-secret ensemble key selector"
        t = "Totally random and unpredictable tweak"
        m = "This is a secret message"
        msk = "lkjasdf;lkjas;dlkfa;slkdf;laskdjf"
        s = "Super secret table value"

        for _ in range(n):
            y,_,_ = eval(w,t,m,msk,s)

            # Save the first output
            if not Y:
                Y = y

            # Compare each output to the first.
            self.assertTrue(y == Y)


    def testProof(self):
        """
        Tests that the zero-knowledge proof passes verification when generated 
        using randomly selected inputs.
        """
        kw = randomZ()
        x = randomG1()
        t = ";lkjasd;flkqj23;lrkqm2d;lkmq3;klmq3; tcq93u4 t[0q34 pq9j43p9jq3 4p"
        beta = hashG1(long(kw) + t + m)
        y = pair(x*kw, tTilde)

        pi = prove(x, tTilde, kw, y)
        self.assertTrue( verify(x, t, y, pi, errorOnFail=False) )


    def testBadProof(self):
        """
        Tests that an invalid proof is reported as invalid.
        """
        kw = randomZ()
        x = randomG1()
        t = long(randomZ())
        tTilde = hashG2(t)
        y = randomGt()

        pi = prove(x, tTilde, kw, y)
        self.assertFalse( verify(x, t, y, pi, errorOnFail=False) )


    def testBadPubkey(self):
        """
        Tests that an invalid proof with a bad pubkey is reported invalid.
        """
        kw = randomZ()
        x = randomG1()
        t = randomZ()
        tTilde = hashG2(t)
        y = pair(x*kw, tTilde)

        # Generate a valid proof
        (p,c,u) = prove(x, tTilde, kw, y)

        # Swap out the pubkey p with a bogus value
        badP = randomG1()
        pi = (badP, c, u)

        self.assertFalse( verify(x, t, y, pi, errorOnFail=False) )


    def testVerifyFailRandom(self, n=100):
        """
        Tests that random inputs are not reported as a valid proof.
        """
        x = randomG1()
        t = randomZ()
        y = randomGt()
        pi = (randomG1(), randomZ(orderGt()), randomZ(orderGt()))
        self.assertFalse( verify(x, t, y, pi, errorOnFail=False) )


    def testProtocol(self):
        """
        Tests a full pass of the protocol.
        """
        # TODO: Factor these into class variables
        w = "Some super-secret ensemble key selector"
        t = "Totally random and unpredictable tweak"
        m = "This is a secret message"
        msk = "lkjasdf;lkjas;dlkfa;slkdf;laskdjf"
        s = "Super secret table value"

        # Run the protocol 
        r, x = blind(m)
        y,kw,tTilde = eval(w,t,x,msk,s)
        pi = prove(x, tTilde, kw, y)
        z = deblind(r, y)

        # Check the proof
        self.assertTrue( verify(x, t, y, pi) )


    def testProtocolStable(self, n=10):
        """
        Tests that multiple passes of the protocol produce the same z,p values.
        """
        w = "Some super-secret ensemble key selector"
        t = "Totally random and unpredictable tweak"
        m = "This is a secret message"
        msk = "lkjasdf;lkjas;dlkfa;slkdf;laskdjf"
        s = "Super secret table value"

        # Run the protocol and report the z,p values
        def proto():
            r, x = blind(m)
            y,kw,tTilde = eval(w,t,x,msk,s)
            (p,_,_) = prove(x, tTilde, kw, y)
            z = deblind(r, y)
            return z,p

        # Establish initial values
        Z,P = proto()
        Zinv = ~Z

        # Run the protocol and check the results against expected results
        def protoCheck():
            z,p = proto()
            self.assertTrue(z == Z or z == Zinv)
            self.assertEqual(P, p)

        repeat(protoCheck, n=n)

# Run!
if __name__ == '__main__':
    unittest.main()