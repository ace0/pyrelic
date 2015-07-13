#!/usr/bin/eval python

"""
Tests for arithmetic for G1, G2, and Gt elements.
"""

from testcommon import *
from pbc import *
from timeit import timeit
from unittest import TestCase, SkipTest
import unittest


class AdditiveGroupArithmetic(TestCase):
    """
    Tests G1/G2 arithmetic
    """
    def setUp(self):
        raise SkipTest("base class")


    def additionCommutes(self):
        P, Q = self.randomElement(), self.randomElement()
        R1 = P + Q
        R2 = Q + P
        self.assertNotEqual(P, Q)
        self.assertNotEqual(R1, Q)
        self.assertEqual(R1, R2)


    def additionAssociates(self):
        P, Q, R = self.randomElement(), self.randomElement(), self.randomElement()
        T1 = (P + Q) + R
        T2 = P + (Q + R)
        self.assertEqual(T1, T2)


    def additionDistributes(self):
        Q = self.randomElement()
        a, b = randomZ(), randomZ()
        c = a + b

        R1 = Q*a + Q*b
        R2 = Q*c

        self.assertNotEqual(Q, R1)
        self.assertEqual(R1, R2)


    def largeScalarMultiply(self):
        n = self.order
        Q = self.randomElement()
        a,b = randomZ(maximum=n), randomZ(maximum=n)
        c = a * b

        # Ensure our number is big enough for this test
        self.assertTrue(c > n)

        # Perform multiplication with two smaller numbers and one larger
        # number. They should give the same result and no segfaults.
        R1 = Q*a*b
        R2 = Q*c
        self.assertEqual(R1, R2)


    def testAdditionCommutes(self):
        repeat(self.additionCommutes, n=100)

    def testAdditionAssociates(self):
        repeat(self.additionAssociates, n=100)

    def testAdditionDistributive(self):
        repeat(self.additionDistributes, n=100)


    def testMultiplyReduces(self):
        Q = self.randomElement()
        a,b = randomZ(), randomZ()
        Qa = Q*a
        Qab = Qa*b
        c = a*b % self.order
        Qc = Q*c
        self.assertEqual(Qc, Qab)


    def testLargeScalarMultiply(self):
        repeat(self.largeScalarMultiply, n=1)


    def testMultiplyCommutes(self):
        """
        Test multiplication by testing commutativity.
        """
        g = self.randomElement()
        a = randomZ()
        b = randomZ()
        c = a*b

        h1 = (g*a)*b
        h2 = (g*b)*a
        h3 = g*c
        self.assertNotEqual(g, h1)
        self.assertEqual(h1, h2)
        self.assertEqual(h2, h3)


    def testInversion(self, n=100):
        """
        Tests G1 element inversion by multiplying computing inverses and 
        multiplying.
        """
        def randomInv():
            g = self.randomElement()
            gInv = g.inverse()
            h = g + gInv
            self.assertTrue(h == 0)
            self.assertTrue(h+g == g)
        repeat(randomInv, n)


class G1Tests(AdditiveGroupArithmetic):
    """
    Tests for G1Element arithmetic.
    """
    def setUp(self):
        self.randomElement = randomG1
        self.order = orderG1()


class G2Tests(AdditiveGroupArithmetic):
    """
    Tests for G2Element arithmetic.
    """
    def setUp(self):
        self.randomElement = randomG2
        self.order = orderG2()

    def testFastMultiplyG2Correct(self):
        """
        Tests that fast multiplication is correct by cross-checking with slow 
        multiplication.
        """
        p = randomG2()
        r = randomZ()
        q1 = p.mul_table(r)
        q2 = p.mul_basic(r)
        self.assertEqual(q1, q2)


    def testFastMultiplyG2Faster(self):
        """
        Ensures that fast multiplication is indeed faster than basic multiply.
        """
        p = randomG2()
        r = randomZ()

        fastTime = timeit(lambda:p.mul_table(r), number=100)
        basicTime = timeit(lambda:p.mul_basic(r), number=100)
        self.assertLess(fastTime, basicTime)


class GtTests(TestCase):
    """
    Tests for GtElement arithmetic
    """
    def testInverse(self):
        """
        Verifies that ~GtElement produces a multiplicative inverse.
        """
        def doInv():
            r = randomGt()
            rInv = ~r
            x = r * rInv
            self.assertTrue(x == 1)
        repeat(doInv, n=50)


    def testMultiplyCommutes(self):
        def test():    
            g, h = randomGt(), randomGt()
            r1 = g*h
            r2 = h*g
            self.assertNotEqual(g, r1)
            self.assertEqual(r1,r2)

        repeat(test, n=100)


    def testMultiplyAssociates(self):
        def test():
            f, g, h = randomGt(), randomGt(), randomGt()
            r1 = (f*g)*h
            r2 = f*(g*h)
            self.assertEqual(r1,r2)

        repeat(test, n=100)


    def testExpCommutes(self):
        def test():
            g = randomGt()
            a,b = randomZ(), randomZ()
            r1 = (g**a)**b
            r2 = (g**b)**a
            r3 = g**(a*b)
            c = (a*b) % orderGt()
            r4 = g**c
            self.assertEqual(r1, r2)
            self.assertEqual(r1, r3)
            self.assertEqual(r1, r4)

        repeat(test, n=100)


    def testExpDistributes(self):
        def test():
            g = randomGt()
            a,b = randomZ(), randomZ()
            r1 = (g**a)*(g**b)
            r2 = g**(a+b)
            self.assertEqual(r1, r2)

        repeat(test, n=100)


# Run!
if __name__ == '__main__':
    unittest.main()