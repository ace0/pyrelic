
"""
Interface to the Barreto Naehrig 256-bit pairing-based elliptic curves 
(PBC) in the RELIC library.
"""
from relic import librelic
from ctypes import byref, c_int, c_ubyte
from ec import *
from bi import *
from common import *

# Cached constant values
ORDER_G1, ORDER_G2, ORDER_GT = (None, None, None)
GENERATOR_G1, GENERATOR_G2, GENERATOR_GT = (None, None, None)


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
        # Multiplication in G2 is so slow. Under our development implementation
        # it was 33% faster to build and use a precomputation table using the 
        # LWNAF algorithm than to use the default, basic, multiplication.
        return self.mul_fast(other)


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


    def mul_fast(self, other):
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


def _equal(a, b, identityLong, relicCompare):
    """
    Compares element @a to @b. If @b is @identityLong, returns 
    a.isIdentity(). Otherwise, normalize a and b and use the relicCompare
    function to test for equality.
    """
    # Check for an identity comparison.
    if isinstance(b, (long, int)) and b == identityLong:
        return a.isIdentity()

    # Verify type and fix normalization for a valid comparison.
    assertSameType(a, b)
    a.normalize()
    b.normalize()

    # Compare against another G2 element.
    return relicCompare(byref(a), byref(b)) == EQUAL


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

def _deserialize(x, element, compress, relicReadBinFunc):
    """
    Deserializes a bytearray @x, into an @element of the correct type,
    using the a relic read_bin function and the specified @compressed flag.
    This is the underlying implementation for deserialize G1, G2, and Gt.
    """
    # Convert the bytearray into an appropriately sized ctypes array of bytes
    b = (c_ubyte*len(x))(*bytearray(x))

    # The compression flag is an integer.
    flag = c_int(compress)

    # Deserialize using the function and the element provided.
    relicReadBinFunc(byref(element), byref(b), len(x), flag)


def deserializeG1(x, compressed=True):
    """
    Deserializes an array of bytes, @x, into a G1 element.
    """
    result = G1Element()
    _deserialize(x, result, compressed, librelic.g1_read_bin_abi)
    return result


def deserializeG2(x, compressed=True):
    """
    Deserializes an array of bytes, @x, into a G2 element.
    """
    result = G2Element()
    _deserialize(x, result, compressed, librelic.g2_read_bin_abi)
    return result


def deserializeGt(x, compressed=True):
    """
    Deserializes an array of bytes, @x, into a Gt element.
    """
    result = GtElement()
    _deserialize(x, result, compressed, librelic.gt_read_bin_abi)
    return result


def generatorG1():
    """
    Retrieves the generator <P> = G1
    """
    # If we don't have the generator, grab it and cache it.
    global GENERATOR_G1
    if not GENERATOR_G1:
        GENERATOR_G1 = G1Element()
        librelic.g1_get_gen_abi(byref(GENERATOR_G1))
    return GENERATOR_G1


def generatorGt():
    """
    Retrieves the generator <g> = Gt
    """
    # If we don't have the generator, grab it and cache it.
    global GENERATOR_GT
    if not GENERATOR_GT:
        GENERATOR_GT = GtElement()
        librelic.gt_get_gen(byref(GENERATOR_GT))
    return GENERATOR_GT


def getBuffer(x):
    """
    Copy @x into a (modifiable) ctypes byte array
    """
    b = bytes(x)
    return (c_ubyte * len(b)).from_buffer_copy(b)


def hashG1(x):
    """
    Hash an array of bytes, @x, onto the group G1. 
    @returns a G1Element.
    """
    # Call the map function and return the result.
    buf = getBuffer(x)
    result = G1Element()
    librelic.g1_map_abi(byref(result), byref(buf), sizeof(buf))
    return result


def hashG2(x):
    """
    Hash an array of bytes, @x, onto the group G2.
    @returns a G2Element.
    """ 
    # Call the map function and return the result.
    buf = getBuffer(x)
    result = G2Element()
    librelic.g2_map_abi(byref(result), byref(buf), sizeof(buf))
    return result


def orderG1():
    """
    Retrieves the order (size) of group G1 as a BigInt.
    """
    global ORDER_G1
    if not ORDER_G1:
        ORDER_G1 = BigInt()
        librelic.gt_get_ord_abi(byref(ORDER_G1))
    return ORDER_G1


def orderG2():
    """
    Retrieves the order (size) of group G2 as a BigInt.
    """
    global ORDER_G2
    if not ORDER_G2:
        ORDER_G2 = BigInt()
        librelic.g2_get_ord_abi(byref(ORDER_G2))
    return ORDER_G2


def orderGt():
    """
    Retrieves the order (size) of group Gt as a BigInt.
    """
    # Don't lookup the order of GT every time: cache on the first request.
    global ORDER_GT
    if not ORDER_GT:
        ORDER_GT = BigInt()
        librelic.gt_get_ord_abi(byref(ORDER_GT))
    return ORDER_GT


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


def randomG1():
    """
    Select a random element from G1.
    """
    result = G1Element()
    librelic.g1_rand_abi(byref(result))
    return result


def randomG2():
    """
    Select a random element from G2.
    """
    result = G2Element()
    librelic.g2_rand_abi(byref(result))
    return result


def randomGt():
    """
    Select a random element from Gt.
    """
    result = GtElement()
    librelic.gt_rand(byref(result))
    return result


def _serialize(element, compress, relicSizeBinFunc, relicWriteBinFunc):
    """
    Serializes an @element using the proper function @relicWriteBinFunc into
    a bytearray. @compress specifies whether the element should be compressed.
    @relicSizeBinFunc is used to determine the size of the serialized output.
    This is underlying implementation for serialize G1, G2, and Gt.
    """
    cFlag = c_int(compress)
    size = relicSizeBinFunc(byref(element), cFlag)

    # Make an array of the correct size. 
    binArray = (c_ubyte*size)()

    # Serialize
    relicWriteBinFunc(byref(binArray), size, byref(element), cFlag)
    return bytearray(binArray)


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

