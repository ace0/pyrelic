
"""
Interface to the Barreto Naehrig 256-bit pairing-based elliptic curves 
(PBC) in the RELIC library.
"""
from relic import librelic
from ctypes import byref, c_int, c_ubyte
from ec import *
from ec import _getCachedValue, _equal, _serialize, _deserialize
from bi import *
from common import *


class G1Element(ec1Element):
    """
    An element (member) of the additive group G1.
    """
    _elementType = "G1 Element"


    def __add__(self, other):
        """
        Adds two G1 elements to produce another G1 element.
        """
        return _add(self, other, librelic.g1_add_abi)        


    def __eq__(self, other):
        """
        Compares two G1 elements. Also determines if the point is the identity
        when calling "self == 0".
        """
        return _equal(self, other, 0, librelic.g1_cmp_abi)


    def __mul__(self, other):
        """
        Multiplies this G1Element with a scalar of integer type.
        """
        # Always prefer the generator multiply routine when possible. It's
        # roughly 2x faster.
        if self is generatorG1():
            return _genMultiply(other, G1Element, orderG1(), 
                librelic.g1_mul_gen_abi)

        # Otherwise use the normal scalar multiply routine.
        return _scalarMultiply(self, other, orderG1(), librelic.g1_mul_abi)


    def inverse(self):
        """
        Retrieves the inverse of a G1 element.
        """
        result = G1Element()
        librelic.g1_neg_abi(byref(result), byref(self))
        return result


    def isIdentity(self):
        """
        Determines if this element is the identity element of G1 (also called O
        or the point at infinity).
        """
        return librelic.g1_is_infty_abi(byref(self)) == 1


    def normalize(self):
        """
        Normalizes this element.
        """
        librelic.g1_norm_abi(byref(self), byref(self))


class G2Element(ec2Element):
    """
    An element (member) of the additive group G2.
    """
    _elementType = "G2 Element"

    # Precomputation table for multiplication.
    _table = None

    def __add__(self, other):
        """
        Adds two G2 elements to produce another G2 element.
        """
        return _add(self, other, librelic.g2_add_abi)


    def __eq__(self, other):
        """
        Compares two G1 elements. Also determines if the point is infinity
        (additive identity) when calling "self == 0".
        """
        return _equal(self, other, 0, librelic.g2_cmp_abi)


    def __mul__(self, other):
        """
        Multiplies this G2Element with a BigInt or Python long value.
        """
        # Always prefer the generator multiply routine when possible. It's
        # roughly 2x faster.
        if self is generatorG2():
            return _genMultiply(other, G2Element, orderG2(),
                librelic.g2_mul_gen_abi)

        # Multiplication in G2 is so slow. On our development platform
        # it was 33% faster to build and use a precomputation table using the 
        # LWNAF algorithm than to use the default, basic, multiplication.
        return self.mul_table(other)


    def inverse(self):
        """
        Retrieves the inverse of a G1 element.
        """
        result = G2Element()
        librelic.g2_neg_abi(byref(result), byref(self))
        return result


    def isIdentity(self):
        """
        Determines if this element is the additive identity element of G2 
        (also called O or the point at infinity).
        """
        return librelic.g2_is_infty_abi(byref(self)) == 1


    def mul_basic(self, other):
        """
        Multiplies this G2Element with a BigInt or Python long value using the
        basic RELIC multiplication algorithm.
        """
        return _scalarMultiply(self, other, orderG2(), librelic.g2_mul_abi)


    def mul_table(self, other):
        """
        Fast multiplication using a the LWNAF precomputation table.
        """
        # Get a BigInt
        other = coerceBigInt(other)
        if not other:
            return NotImplemented
        other %= orderG2()

        # Building the precomputation table, if there is not one already.
        if not self._table:
            self._table = lwnafTable()
            librelic.ep2_mul_pre_lwnaf(byref(self._table), byref(self))


        result = G2Element()
        librelic.ep2_mul_fix_lwnaf(byref(result), byref(self._table), 
            byref(other))
        return result


    def normalize(self):
        """
        Normalizes this element.
        """
        librelic.g2_norm_abi(byref(self), byref(self))



class GtElement(ec12Element):
    """
    An element (member) of the multiplicative group Gt.
    """
    _elementType = "Gt Element"


    def __eq__(self, other):
        """
        Compares two Gt elements. Also determines if the point is the unity
        (multiplicative identity) element of Gt when calling "self == 1".
        """
        return _equal(self, other, 1, librelic.gt_cmp_abi)


    def __invert__(self):
        """
        Computes the inverse of an element in Gt.
        """
        result = GtElement()
        librelic.gt_inv_abi(byref(result), byref(self))
        return result


    def __mul__(self, other):
        """
        Multiplies two GtElements.
        """
        assertSameType(self, other)
        result = GtElement()
        librelic.gt_mul_abi(byref(result), byref(self), byref(other))
        return result


    def __pow__(self, exp):
        """
        Computes self^exp where @exp is an integer type.
        """
        exp = coerceBigInt(exp)
        if not exp:
            return NotImplemented

        # Shrink large exponents.
        exp %= orderGt()

        r = GtElement()
        librelic.gt_exp_abi(byref(r), byref(self), byref(exp))
        return r


    def normalize(self):
        """
        GtElements don't support normalization (apparently) in RELIC.
        """
        pass


    def isIdentity(self):
        """
        Determines if this element is the unit (multiplicative identity) of Gt.
        """
        return self.isUnity


    def isUnity(self):
        """
        Determines if this element is the unit (multiplicative identity) of Gt.
        """
        return librelic.gt_is_unity_abi(byref(self)) == 1


def _add(a, b, relicAdd):
    """
    Adds two elements @a,@b of the same type into @result using @relicAddFunc.
    """
    # Check types, create a result object of the same type, and call the relic
    # function.
    assertSameType(a,b)
    result = type(a)()
    relicAdd(byref(result), byref(a), byref(b))
    return result



def _scalarMultiply(P, a, n, relicScalarMult):
    """
    Performs scalar multiplication between point P \in G, scalar a \in Z, 
    using the function @relicScalarMult. @n is the order of the group G.
    """
    # Ensure the scalar is a BigInt
    a = coerceBigInt(a)
    if not a:
        return NotImplemented

    # Shrink large scalars.
    a %= n

    # Create a point to hold the result and multiply.
    result = type(P)()
    relicScalarMult(byref(result), byref(P), byref(a))
    return result


def _genMultiply(a, element, n, relicGenMultiplyFunc):
    """
    Multiplies scalar @a by the group generator using @relicGenMultiplyFunc
    and returns the result of type @element.
    """
    # Ensure the scalar is a BigInt
    a = coerceBigInt(a)
    if not a:
        return NotImplemented

    # Shrink large scalars.
    a %= n

    result = element()
    relicGenMultiplyFunc(byref(result), byref(a))
    return result


def deserializeG1(x, compressed=True):
    """
    Deserializes an array of bytes, @x, into a G1 element.
    """
    return _deserialize(x, G1Element, compressed, librelic.g1_read_bin_abi)


def deserializeG2(x, compressed=True):
    """
    Deserializes an array of bytes, @x, into a G2 element.
    """
    return _deserialize(x, G2Element, compressed, librelic.g2_read_bin_abi)


def deserializeGt(x, compressed=True):
    """
    Deserializes an array of bytes, @x, into a Gt element.
    """
    return _deserialize(x, GtElement, compressed, librelic.gt_read_bin_abi)


def generatorG1():
    """
    Retrieves the generator <P> = G1
    """
    return _getCachedValue(generatorG1, librelic.g1_get_gen_abi, G1Element)


def generatorG2():
    """
    Retrieves the generator <P> = G2
    """
    return _getCachedValue(generatorG2, librelic.g2_get_gen_abi, G2Element)


def generatorGt():
    """
    Retrieves the generator <g> = Gt
    """
    return _getCachedValue(generatorGt, librelic.gt_get_gen, GtElement)


# Initialize generator cached values to None
generatorG1.cached, generatorG2.cached, generatorGt.cached = None, None, None


def getBuffer(x):
    """
    Copy @x into a (modifiable) ctypes byte array
    """
    b = bytes(x)
    return (c_ubyte * len(b)).from_buffer_copy(bytes(x))



def _hash(x, elementType, relicHashFunc):
    """
    Hash an array of bytes, @x, using @relicHashFunc and returns the result
    of @elementType.
    """
    # Combine all inputs into a single bytearray
    barray = bytearray()
    map(barray.extend, bytes(x))

    # Create an element of the correct type to hold the hash result
    result = elementType()

    # Convert barray into a modifiable ctypes buffer, hash using the provided
    # function, and return the result.
    buf = getBuffer(barray)
    relicHashFunc(byref(result), byref(buf), sizeof(buf))
    return result


def hashG1(*args):
    """
    Hash an array of bytes, @x, onto the group G1. 
    @returns a G1Element.
    """
    return _hash(args, G1Element, librelic.g1_map_abi)


def hashG2(*x):
    """
    Hash an array of bytes, @x, onto the group G2.
    @returns a G2Element.
    """ 
    return _hash(x, G2Element, librelic.g2_map_abi)


def orderG1():
    """
    Retrieves the order (size) of group G1 as a BigInt.
    """
    return _getCachedValue(orderG1, librelic.g1_get_ord_abi, BigInt)


def orderG2():
    """
    Retrieves the order (size) of group G2 as a BigInt.
    """
    return _getCachedValue(orderG2, librelic.g2_get_ord_abi, BigInt)


def orderGt():
    """
    Retrieves the order (size) of group Gt as a BigInt.
    """
    return _getCachedValue(orderGt, librelic.gt_get_ord_abi, BigInt)


# Initialize cached values to None
orderG1.cached, orderG2.cached, orderGt.cached = None, None, None


def pair(p,q):
    """
    Computes the bilinear pairing e(p,q). @p must be a G1Element and @q must
    be a G2Element.
    @returns a GtElement
    """
    # Check types
    assertType(p, G1Element)
    assertType(q, G2Element)

    result = GtElement()
    librelic.pc_map_abi(byref(result), byref(p), byref(q))
    return result


def _random(elementType, relicRandomFunc):
    """
    Retrieves a random element of @elementType by calling @relicRandomFunc.
    """
    result = elementType()
    relicRandomFunc(byref(result))
    return result


def randomG1():
    """
    Select a random element from G1.
    """
    return _random(G1Element, librelic.g1_rand_abi)


def randomG2():
    """
    Select a random element from G2.
    """
    return _random(G2Element, librelic.g2_rand_abi)


def randomGt():
    """
    Select a random element from Gt.
    """
    return _random(GtElement, librelic.gt_rand)


def serializeG1(x, compress=True):
    """
    Converts G1 element @x into an array of bytes. If @compress is True, 
    the point will be compressed resulting in a much shorter string of bytes.
    """
    assertType(x, G1Element)
    return _serialize(x, compress, librelic.g1_size_bin_abi,
        librelic.g1_write_bin_abi)


def serializeG2(x, compress=True):
    """
    Converts G2 element @x into an array of bytes. If @compress is True, 
    the point will be compressed resulting in a much shorter string of bytes.
    """
    assertType(x, G2Element)
    return _serialize(x, compress, librelic.g2_size_bin_abi,
        librelic.g2_write_bin_abi)


def serializeGt(x, compress=True):
    """
    Converts Gt element @x into an array of bytes. If @compress is True, 
    the point will be compressed resulting in a much shorter string of bytes.
    """
    assertType(x, GtElement)
    return _serialize(x, compress, librelic.gt_size_bin_abi,
        librelic.gt_write_bin_abi)

