"""
Access to the RELIC multiple precision integer type bn_t detailed in relic_bn.h
"""
from relic import librelic
from common import *
from ctypes import Structure, byref, sizeof, c_int, c_ulonglong

class BigInt(Structure):
    """
    Multiple precision integer used by RELIC.
    """
    BN_SIZE = 34
    POSITIVE_FLAG = c_int(0)
    NEGATIVE_FLAG = c_int(1)

    # This maps to the type bn_st in relic_bn.h
    _fields_ = [
            ("alloc", c_int), 
            ("used", c_int), 
            ("sign", c_int), 
            # NOTE: We've promoted the type to c_ulonglong and halfed the 
            #       size of BN_SIZE compared to the representation in 
            #       relic_bn.h because BN_MAGNI = DOUBLE, meaning each "digit"
            #       is a double-word.
            ("digits", c_ulonglong * (BN_SIZE/2)), 
        ]


    def __init__(self, x=None):
        """
        Initialize an empty BigInt or create one from a Python long value @x
        """
        if x is None:
            return

        if not isinstance(x, (int, long)):
            raise TypeError("BigInt can only be initialized from a Python long or int value.")

        # The number of bits in each "digit"
        bits = sizeof(c_ulonglong)*8

        # Set the bookkeeping fields
        self.alloc = 0
        self.used = 0
        self.sign = BigInt.POSITIVE_FLAG if x >= 0 else BigInt.NEGATIVE_FLAG

        # Grab and set the "digits" from the value x. Digits are arranged
        # little-endian.
        x = abs(x)
        while x > 0:
            self.digits[self.used] = x % (2**bits)
            self.used += 1
            x >>= bits


    def __add__(self, other):
        """
        Add @other integer type to this BigInt.
        """
        other = coerceBigInt(other)
        if not other:
            return NotImplemented

        result = BigInt()
        librelic.bn_add(byref(result), byref(self), byref(other))
        return result


    def __eq__(self, other):
        """
        Compares this BigInt against an integer type.
        """
        return compare(self, other) == EQUAL


    def __le__(self, other):
        """
        Compares this BigInt against an integer type.
        """
        return compare(self, other) in [LESS_THAN, EQUAL]


    def __lt__(self, other):
        """
        Compares this BigInt against an integer type.
        """
        return compare(self, other) == LESS_THAN


    def __ge__(self, other):
        """
        Compares this BigInt against an integer type.
        """
        return compare(self, other) in [GREATER_THAN, EQUAL]


    def __gt__(self, other):
        """
        Compares this BigInt against an integer type.
        """
        return compare(self, other) == GREATER_THAN


    def __ne__(self, other):
        """
        Compares this BigInt against an @other BigInt or long value.
        """
        return not self.__eq__(other)


    def __str__(self):
        """
        Retrieves a hexadecimal representation of this BigInt. 
        """
        return "BigInt<{}>".format(hexString(self.digits[:self.used]))


    def __mod__(self, other):
        """
        Computes self modulo other where other is either a python integer
        type of a BigInt.
        """
        other = coerceBigInt(other)
        if not other:
            return NotImplemented

        result = BigInt()
        librelic.bn_mod_abi(byref(result), byref(self), byref(other))
        return result


    def __mul__(self, other):
        """
        Computes self*other assuming other is also a BigInt.
        """
        other = coerceBigInt(other)
        if not other: 
            return NotImplemented
        result = BigInt()
        librelic.bn_mul_basic(byref(result), byref(self), byref(other))
        return result


    def __sub__(self, other):
        """
        Subtract @other BigInt from this BigInt.
        """
        other = coerceBigInt(other)
        if not other:
            return NotImplemented

        result = BigInt()
        librelic.bn_sub(byref(result), byref(self), byref(other))
        return result


    def __long__(self):
        """
        Convert this BigInt to a Python long value.
        """
        # Add up the digits from smallest index to largest as specified in
        # relic_bn.h
        # r:result, d:digit
        r = long(0)
        for i,d in enumerate(self.digits):
            r += d << (sizeof(c_ulonglong)*8*i)
        return r


def compare(a, b):
    """
    Compares BigInt @a against integer type @b. Returns LESS_THAN, 
    EQUAL, or GREATER_THAN.
    """
    assertType(a, BigInt)
    b = coerceBigInt(b)
    if not b:
        return NotImplemented

    return librelic.bn_cmp(byref(a), byref(b))


def assertScalarType(x):
    """
    Ensures that @x is of type, BigInt, long, or int. Raises NotImplementedError
    otherwise.
    """
    assertType(x, (BigInt, int, long))


def coerceBigInt(x):
    """
    Retrieves a BigInt from @x or returns None if @x is not a type that can be
    converted.
    """
    # BigInt's are easy.
    if isinstance(x, BigInt):
        return x

    # Convert ints and longs using the constructor
    elif isinstance(x, (long, int)):
        return BigInt(x)

    else:
        return None


def hashZ(*args):
    """
    Hash @args into a BigInt using a cryptographic hash function.
    """
    TAG = "TAG_RELIC_HASH_Z"
    MESSAGE = "MESSAGE_HASH_Z"

    # Combine the arguments into a canonical string representation.
    text = TAG.join([str(val) for val in args ] )

    # Hash the string using HMAC
    # b: byte string 
    b = hmac(text, MESSAGE)
    return BigInt(longFromString(b))


def inverse(x, p, errorOnFail=False):
    """
    Find the inverse of BigInt @x in a field of (prime) order @p.
    """
    # Check types
    assertType(x, BigInt)

    # There are a number of ways in RELIC to compute this inverse, but
    # for simplicity, we'll use the extended GCD algorithm because it 
    # involves less type conversions. On the initial development platform
    # Lehmer's algorithm was the most performant: we call it directly.
    gcd = BigInt()
    inv = BigInt()

    # bn_gcd_ext(c, d, e, a, b) computes: c = a*d + b*e
    # We take x=a. b=p, and expect: c = 1 = gcd(x,p), d = 1/x, and e is unused.
    librelic.bn_gcd_ext_lehme(byref(gcd), byref(inv), None, byref(x), byref(p))

    # Check that GCD == 1 
    if gcd != 1:
        if errorOnFail:
            raise Exception("Cannot find an inverse. gcd(x,p) == {}, but we need gcd(x,p) == 1 to find an inverse.".
                format(long(gcd)))
        else:
            return None

    return inv


def randomZ(maximum=None, bits=256):
    """
    Retrieve a random BigInt.
    @maximum: If specified, the value will be no larger than this modulus.
    @bits: If no maximum is specified, the value will have @bits.
    """
    result = BigInt()

    # Select a random number smaller than the maximum.
    if maximum:
        maximum = coerceBigInt(maximum)
        librelic.bn_rand_mod(byref(result), byref(maximum))

    # Otherwise, select a random BigInt of the appropriate size in bits.
    else:
        librelic.bn_rand_abi(byref(result), BigInt.POSITIVE_FLAG, c_int(bits))
    
    return result
