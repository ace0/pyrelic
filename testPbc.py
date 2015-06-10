



#!/usr/bin/eval python

from testcommon import *
from pbc import *
from timeit import timeit
from unittest import TestCase, SkipTest
import unittest


class PbcTests(TestCase):
    """
    Tests for the pairing-based crypto classes and related module functions.
    """
    def testHashG1Same(self):
        self.hashTest(hashG1)


    def testHashG2Same(self):
        self.hashTest(hashG2)


    def hashTest(self, hashfunc):
        """
        Each hash of the same string must give the same result
        """
        # We want to messages that give the same bytes, but are not identical
        # objects.
        m1 = "This is a very long string. It makes a nice test message."
        m2 = "This is a very long string." + " It makes a nice" + " test message."

        # Ensure we have two unique objects with identical values
        self.assertEqual(m1, m2)
        self.assertIsNot(m1, m2)

        h1 = hashfunc(m1)
        h2 = hashfunc(m2)
        self.assertEqual(h1, h2)


    def testPair(self):
        """
        Test pairing funciton by checking the multiplicative homomorphic 
        property.
        """
        r = randomZ()
        p = randomG1()
        q = randomG2()

        t1 = pair(p*r,q)
        t2 = pair(p,q*r)

        self.assertEqual(t1, t2)


    def testFastMultiplyG2Correct(self):
        """
        Tests that fast multiplication is correct by cross-checking with slow 
        multiplication.
        """
        p = randomG2()
        r = randomZ()
        q1 = p.mul_fast(r)
        q2 = p.mul_basic(r)
        self.assertEqual(q1, q2)


    def testFastMultiplyG2Faster(self):
        """
        Ensures that fast multiplication is indeed faster than basic multiply.
        """
        p = randomG2()
        r = randomZ()

        fastTime = timeit(lambda:p.mul_fast(r), number=100)
        basicTime = timeit(lambda:p.mul_basic(r), number=100)
        self.assertLess(fastTime, basicTime)


    def testRandomG1(self):
        """
        Grabs random elements from G1 an ensure there are no duplicates. 
        """
        randomNoRepeat(randomG1)


    def testRandomG2(self):
        """
        Grabs random elements from G2 an ensure there are no duplicates. 
        """
        randomNoRepeat(randomG2)


    def testRandomZ(self):
        """
        Grab @n random elements from Z an ensure there are no duplicates. 
        """
        randomNoRepeat(randomZ)


import base64

class PbcSerialBase(TestCase):
    """
    Base class for testing the de/serialization of G1, G2, and Gt elements.
    """
    def setUp(self):
        raise unittest.SkipTest("Base class")


    def assertNotEmpty(self, x):
        """
        Ensures that @x is not None and len(x) > 0
        """
        self.assertTrue(x is not None and len(x) > 0)


    def fullCycle(self, x, compress=False):
        """
        Tests de/serialization by running full cycle and comparing the result 
        to the original element.
        """
        b = self.serialize(x, compress)
        x2 = self.deserialize(b, compress)
        self.assertEqual(x, x2)


    def testSerializeNonEmpty(self, compress=False):
        """
        Tests that encoding an element delivers a non-empty list of bytes.
        """
        self.assertNotEmpty( self.serialize(self.randomElement(), compress) )


    def testSerializeNonEmptyCompressed(self):
        """
        Tests that encoding an element with compression delivers a non-empty 
        list of bytes.
        """
        self.testSerializeNonEmpty(compress=True)


    def testCompressed(self):
        """
        Tests that serializing with compression results in a shorter result than
        the uncompressed routine.
        """
        x = self.randomElement()
        b1 = self.serialize(x, False)
        b2 = self.serialize(x, True)

        self.assertNotEmpty(b1)
        self.assertNotEmpty(b2)
        self.assertTrue(len(b2) < len(b1))


    def testFullCycle(self, n=10, compress=False):
        func = lambda: self.fullCycle(self.randomElement(), compress)
        repeat(func, n)


    def testFullCycleCompressed(self):
        self.testFullCycle(compress=True)


    def testFullCycleEncoded(self, compress=False):
        """
        Tests full cycle serialization + b64 encoding.
        """
        # serialize and encode a random element
        x = self.randomElement()
        b = bytearray( self.serialize(x, compress) )
        encoded = base64.urlsafe_b64encode(b)

        # Decode the result and verify that the underlying bytes still match
        decodedBytes = base64.urlsafe_b64decode(encoded)
        self.assertEqual(b, decodedBytes)

        # Deserialize and compare against the original element
        x2 = self.deserialize(decodedBytes)
        self.assertEqual(x, x2)


    def testFullCycleEncodedCompressed(self, compress=False):
        """
        Tests full cycle serialization with compression and encoding.
        """
        self.testFullCycleEncoded(compress=True)


class G1SerializeTests(PbcSerialBase):
    def setUp(self):
        self.randomElement = randomG1
        self.serialize = serializeG1
        self.deserialize = deserializeG1


class G2SerializeTests(PbcSerialBase):
    def setUp(self):
        self.randomElement = randomG2
        self.serialize = serializeG2
        self.deserialize = deserializeG2


class GtSerializeTests(PbcSerialBase):
    def setUp(self):
        self.randomElement = randomGt
        self.serialize = serializeGt
        self.deserialize = deserializeGt


# Run!
if __name__ == '__main__':
    unittest.main()