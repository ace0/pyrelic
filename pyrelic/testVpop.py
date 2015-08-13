#!/usr/bin/eval python

from testcommon import *
import unittest
from unittest import TestCase
from vpop import *

# Global values for test cases
w = "Some super-secret ensemble key selector"
t = "Totally random and unpredictable tweak"
m = "This is a secret message"
msk = "lkjasdf;lkjas;dlkfa;slkdf;laskdjf"
s = "Super secret table value"


class VpopTests(TestCase):
    """
    Tests for the Vpop class.
    """
    def testKeyGen(self):
        msk = "12l3k4jh1lk23jh51l34b5l1k34j5nl134jn51lk3b51lk34b5"
        w = "super secret key selector"
        z = "lkjasdf;lkjaew;jas; dlkjas;ldfkjas;dlfkjas ;df"
        genKw(w,msk,z)


    def testBlindRandomized(self, n=100):
        """
        Verifies that the blinding method is randomized.
        """
        m = "This is a very sensitive passphrase."
        def doBlind():
            _, x = blind(m)
            return x

        randomNoRepeat(doBlind, n=n)


    def testEvalStable(self, n=100):
        """
        Runs eval() @n times and ensures that after deblinding, the result
        is deterministic.
        """
        Z = None

        for _ in range(n):
            r, x = blind(m)
            y,_,_ = eval(w,t,x,msk,s)
            z = deblind(r, y)

            # Save the first output
            if not Z:
                Z = z 

            # Compare each output to the first.
            self.assertTrue(z == Z)


    def testProof(self):
        """
        Tests that the zero-knowledge proof passes verification when generated 
        using randomly selected inputs.
        """
        # TODO: Consolidate random selection to a test setup to speed up unit
        # tests
        kw = randomZ()
        x = randomG1()
        t = ";lkjasd;flkqj23;lrkqm2d;lkmq3;klmq3; tcq93u4 t[0q34 pq9j43p9jq3 4p"
        tTilde = hashG2(t)
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
        # Run the protocol and report the z,p values
        def proto():
            r, x = blind(m)
            y,kw,tTilde = eval(w,t,x,msk,s)
            (p,_,_) = prove(x, tTilde, kw, y)
            z = deblind(r, y)
            return z,p

        # Establish initial values
        Z,P = proto()

        # Run the protocol and check the results against expected results
        def protoCheck():
            z,p = proto()
            self.assertTrue(z == Z)
            self.assertEqual(P, p)

        repeat(protoCheck, n=n)


    def testUpdate(self):
        """
        Tests updating an encrypted value to a new key.
        """
        wPrime = "Definitely not the original value w"
        sPrime = "Totally new state value"

        # Run the protocol under the original inputs
        z = simpleProto(w,t,msk,s,m)

        # Get an update token and apply it
        delta,_ = getDelta((w,msk,s), (wPrime,msk,sPrime))
        zPrime1 = update(z, delta)

        # Re-run the protocol under the new inputs
        zPrime2 = simpleProto(wPrime,t,msk,sPrime,m)

        # Compare z' 
        self.assertEqual(zPrime1, zPrime2)


def simpleProto(w,t,msk,s,m):
    """
    Runs the protocol without generating or checking proofs and returns
    the result @z.
    """
    r,x = blind(m)
    y,_,_ = eval(w,t,x,msk,s)
    return deblind(r, y)


# Run!
if __name__ == '__main__':
    unittest.main()