"""
Interface to the elliptic curve types and functions in the RELIC library.
"""
from relic import librelic
from bi import *
from ctypes import Structure, byref, sizeof, c_int, c_ubyte, c_ulonglong
from common import *

class ecElementBase(Structure):
    """
    Common base class for ec1, ec2, ec12 elements.
    """
    _elementType = "EC Element (Base)"
    _str_degree_max = None


    def __ne__(self, other):
        """
        Computes a != b as: not a == b
        """
        return not self.__eq__(other)


    def __rmul__(self, other):
        """
        Multiplies two elements since multiplication of EC points is 
        commutative.
        """
        return self.__mul__(other)


    def __str__(self, includeNormal=True):
        """
        Retrieves a string representation of this element with coordinates
        as hexadecimal strings.
        """
        if includeNormal:
            n = "Normalized" if self.normalized else "Not Normalized"
            name = self._elementType + " " + n
        else:
            name = self._elementType


        # Convert each point to a string, but limit the number of degrees
        # if necessary.
        d = self._str_degree_max if self._str_degree_max else self._degree

        formattedPoints = [formatPoint(p, self.normalized) for p in self.points[:d] ]
        pointText = "\n\n".join(formattedPoints)
        return name + "\n" + pointText


COORD_LEN = 4
class ecPoint(Structure):
    """
    Common base class for working with RELIC elliptic curve points.
    """
    # The size, in bytes, of our base field
    BASE_FIELD_BYTES = 256/8

    # The length of each coordinate (in bytes) for the type fp_t 
    # under our specified configuration.
    COORD_LEN = BASE_FIELD_BYTES/sizeof(c_ulonglong)

    _fields_ = [
                # x,y,z are of type fp_(s)t which are simple byte arrays of a 
                # fixed length.
                ("x", c_ulonglong*COORD_LEN), 
                ("y", c_ulonglong*COORD_LEN),
                ("z", c_ulonglong*COORD_LEN)
            ]


class ec1Element(ecElementBase):
    """
    Elliptic curve point struct type is the underlying structure of a G1
    element.
    """
    _elementType = "EC1 Element"
    _degree = 1

    # This maps to the type ep_t in the relic_ep.h. It is typedef'd to the 
    # g1_t type.
    _fields_ = [
            ("points", ecPoint*_degree),
            ("normalized", c_int)
        ]

    def __add__(self, other):
        """
        Adds to EC elements.
        """
        assertSameType(self, other)
        return relicResult(librelic.ec_add_abi, ec1Element, self, other)


    def __mul__(self, k):
        """
        Computes kP where P is this element and k is an integer type.
        """
        # Perform multiplication and return the result
        return relicResult(librelic.ec_mul_abi, ec1Element, self,
            coerceBigInt(k))


    def __eq__(self, other):
        """
        Compares this EC point against another or the identity element 0.
        """
        return _equal(self, other, 0, librelic.ec_cmp_abi)


    def isIdentity(self):
        """
        Determines if this point is the additive identity 0 or the point at 
        infinity.
        """
        return librelic.ec_is_infty_abi(byref(self)) == 1


    def normalize(self):
        """
        There is no in-place normalization for EC elements.
        """
        relicResult(librelic.ec_norm_abi, None, self, self)


class ec2Element(ecElementBase):
    """
    Element of a qudratic extension field over an elliptic curve.
    """
    _elementType = "EC2 Element"
    _degree = 2

    # This maps to the type ep2_(s)t in the relic_ep.h. It is typedef'd to the 
    # g2_t type.
    _fields_ = [
            ("points", ecPoint*_degree),
            ("normalized", c_int)
        ]


class ec12Element(ecElementBase):
    """
    Element of a dodectic extension field over an elliptic curve.
    """
    _elementType = "EC12 Element"
    _degree = 12

    # The number of degrees we will actually use when generating a string
    _str_degree_max = 4

    # DEBUG: Reduce the printing degrees so the output is readable
    _str_degree_max = 1

    # This maps to the type fp12_(s)t in the relic_ep.h. It is typedef'd to the 
    # gt_t type.
    _fields_ = [
            ("points", ecPoint*_degree),
            ("normalized", c_int)
        ]

class lwnafTable(Structure):
    """
    LWNAF table for EC2 precomputation.
    """
    # In our configuration, this is 4x the size of an ec2 element:
    # relic_epx.h: EPX_TABLE_LWNAF
    SIZE = 4
    _fields_ = [ ("values", ec2Element*SIZE) ]


def relicResult(relicFunc, resultType, *args):
    """
    Calls @relicFunc with a list of @args that are passed by reference. If
    @resultType is set, a new object of this type is created, passed as the
    first argument, and returned by this function.
    """
    result = None

    # If there is a return type, it becomes the first parameter.
    if resultType is not None:
        result = resultType()
        args = (result,) + args

    # Pass all parameters byref
    params = [byref(x) for x in list(args)]

    # Call the function and return our result.
    relicFunc(*params)
    return result


def _deserialize(x, elementType, compress, relicReadBinFunc):
    """
    Deserializes a bytearray @x, into an @element of the correct type,
    using the a relic read_bin function and the specified @compressed flag.
    This is the underlying implementation for deserialize G1, G2, and Gt.
    """
    # Convert the bytearray into an appropriately sized ctypes array of bytes
    b = (c_ubyte*len(x))(*bytearray(x))

    # The compression flag is an integer.
    flag = c_int(compress)

    # Deserialize using the read function.
    result = elementType()
    relicReadBinFunc(byref(result), byref(b), len(x), flag)
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

    # Compare the elements using the relic function.
    return relicCompare(byref(a), byref(b)) == EQUAL


def _getCachedValue(obj, relicFunc, resultType):
    """
    Retrieves a value from obj.cached (if not None) or calls @relicFunc and 
    caches the result (of @resultType) int obj.cached.

    This is a common implementation for orderG1/G2/Gt and generatotG1/G2/Gt
    """
    # If the value has not been previously cached, fetch 
    if not obj.cached:
        obj.cached = resultType()
        relicFunc(byref(obj.cached))
    return obj.cached


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


def deserializeEc(x, compress=True):
    """
    Deserialize binary string @x into an EC element.
    """
    return _deserialize(x, ec1Element, compress, librelic.ec_read_bin_abi)


def formatPoint(point, affine):
    """
    Retrieves a string representation of @point
    """
    # Affine coordinates: (x,y)        
    if affine:
        fmt = "\tx:{}\n\ty:{}"
        coords = [point.x, point.y]

    # Projected coordinates: (x,y,z)
    else:
        fmt = "\tx:{}\n\ty:{}\n\tz:{}"
        coords = [point.x, point.y, point.z]

    coordText = map(hexString, coords)
    return fmt.format(*coordText)


def generatorEc():
    """
    Retrieves the generator <G> = ECGroup
    """
    return _getCachedValue(generatorEc, librelic.ec_curve_get_gen_abi, 
        ec1Element)

generatorEc.cached = None


def randomEcPoint():
    """
    Generates a random element from the ECGroup.
    """
    return relicResult(librelic.ec_rand_abi, ec1Element)


def serializeEc(P, compress=True):
    """
    Generates a compact binary version of this point.
    """
    return _serialize(P, compress, librelic.ec_size_bin_abi,
        librelic.ec_write_bin_abi)


def orderEc():
    """
    Retrieves the order of the elliptic curve group as a BigInt.
    """
    return _getCachedValue(orderEc, librelic.ec_curve_get_ord_abi, BigInt)

orderEc.cached = None