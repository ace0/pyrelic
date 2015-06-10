"""
Interface to the elliptic curve types and functions in the RELIC library.
"""
from relic import librelic
from ctypes import Structure, byref, sizeof, c_int, c_ulonglong
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

    # This maps to the type ep2_(s)t in the relic_ep.h. It is typedef'd to the 
    # g2_t type.
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