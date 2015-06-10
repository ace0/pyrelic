#!/usr/bin/eval python

from testcommon import *
import unittest, random
from bi import *
from relic import *


class BigIntTests(unittest.TestCase):
    """
    Tests for the BigInt class and related module functions.
    """
    def testFromInt(self):
        """
        Test creating BigInts from Python int values.
        """
        for i in range(1000):
            b = BigInt(i)
            self.assertEqual(i, long(b))


    def testEquality(self):
        a = random.randrange(0, 2*256)
        b = BigInt(a)
        c = BigInt(a)

        self.assertEqual(b, c)
        self.assertTrue(b == c )

        self.assertEqual(c, b)
        self.assertTrue(c == b )

        self.assertFalse(b != c )
        self.assertFalse(c != b )

        self.assertTrue( b >= c )
        self.assertTrue( b <= c )

        self.assertTrue( c >= b )
        self.assertTrue( c <= b )

        self.assertFalse( b < c )
        self.assertFalse( b > c )


    def testGtLtNe(self):
        a = randomZ()
        b = a+a

        self.assertNotEqual(a, b)
        self.assertTrue( a != b )

        self.assertFalse( b == a )
        self.assertFalse( a == b )

        self.assertTrue( b > a )
        self.assertTrue( b >= a )

        self.assertFalse( b < a )
        self.assertFalse( b <= a )


    def testFromLong(self, bits=192):
        """
        Test creating BigInts from Python long values by going full circle.
        """
        def randomConv():
            i = random.getrandbits(bits)
            b = BigInt(i)
            self.assertEqual(i, long(b))
        repeat(randomConv)


    def testLongMult(self, n=1000):
        def randomMult():
            # 2 random BigInts
            a, b = (randomZ(bits=256), randomZ(bits=256))
            c = a*b

            # Repeat with Python longs and check
            x, y = (long(a), long(b))
            z = x * y 

            self.assertEqual(z, long(c)) 
        repeat(randomMult, n)

    def testRandom8bit(self):
        self._testRandomMax(8)

    def testRandom32bit(self):
        self._testRandomMax(32)

    def testRandom64bit(self):
        self._testRandomMax(64)

    def testRandom256bit(self):
        self._testRandomMax(256)

    def testRandom1k(self):
        self._testRandomMax(1024)

    def _testRandomMax(self, bits, iterations=1000):
        # Grab a series of random values and ensure they're not too large.
        maxValue = 2**bits - 1
        for _ in range(iterations):
            b = randomZ(bits=bits)
            l = long(b)
            self.assertTrue( l <= maxValue )


# Run!
if __name__ == '__main__':
    unittest.main()