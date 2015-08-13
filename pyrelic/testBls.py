#!/usr/bin/eval python
from testcommon import *
import unittest
from unittest import TestCase
from bls import *
from common import hmac

class BlsTests(TestCase):
    """
    Tests for the BLS PRF
    """
    def testEvalStable(self, n=10):
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
        m = randomstr()
        t = randomstr()
        beta = hashG1(t, m)
        y = beta*kw

        pi = prove(None, None, kw, None)
        self.assertTrue( verify(m, t, y, pi, errorOnFail=False) )


    def testBadProof(self):
        """
        Tests that an invalid proof is reported as invalid.
        """
        kw = randomZ()
        m = randomstr()
        t = randomstr()
        y = randomG1()

        pi = prove(None, None, kw, None)
        self.assertFalse( verify(m, t, y, pi, errorOnFail=False) )


    def testBadPubkey(self):
        """
        Tests that an invalid proof with a bad pubkey is reported invalid.
        """
        # Generate a correct result @y and proof using random inputs.
        kw = randomZ()
        m = randomstr()
        t = randomstr()
        beta = hashG1(t, m)
        y = beta*kw

        # Generate a valid proof
        (p,c,u) = prove(None, None, kw, None)

        # Swap out the pubkey p with a bogus value
        badP = randomG2()
        pi = (badP, None, None)

        self.assertFalse( verify(m, t, y, pi, errorOnFail=False) )


    def testVerifyFailRandom(self, n=100):
        """
        Tests that random inputs are not reported as a valid proof.
        """
        m = randomstr()
        t = randomstr()
        y = randomG1()
        pi = (randomG2(), None, None)
        self.assertFalse( verify(m, t, y, pi, errorOnFail=False) )


    def testProtocol(self):
        """
        Tests a full pass of the protocol.
        """
        w = "Some super-secret ensemble key selector"
        t = "Totally random and unpredictable tweak"
        m = "This is a secret message"
        salt = randomstr()
        x = hmac(salt, m)
        msk = randomstr()
        s = randomstr()

        # Run the protocol 
        y,kw,beta = eval(w,t,x,msk,s)
        pi = prove(None, None, kw, None)

        # Check the proof
        self.assertTrue( verify(x, t, y, pi, errorOnFail=False) )


# Run!
if __name__ == '__main__':
    unittest.main()