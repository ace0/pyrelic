"""
Common routines for Pythia pseudorandom function (PRF) protocols based on 
pairing based curves (BN-254).
"""
from pbc import *
import base64

def genKw(w,msk,z):
    """
    Generates key Kw using key-selector @w, master secret key @msk, and
    table value @z.
    @returns Kw as a BigInt.
    """
    # Hash inputs into a string of bytes
    b = hmac(msk, z + w, tag="TAG_PYTHIA_KW")

    # Convert the string into a long value (no larger than the order of Gt),
    # then return a BigInt value.
    return BigInt(longFromString(b) % long(orderGt()))


def wrap(x):
    """
    Wraps an element or integer type by serializing it and base64 encoding 
    the resulting bytes.
    """
    # Detect the type so we can call the proper serialization routine
    if isinstance(x, G1Element):
        return _wrap(x, serializeG1)

    elif isinstance(x, G2Element):
        return _wrap(x, serializeG2)

    elif isinstance(x, GtElement):
        return _wrap(x, serializeGt)

    elif isinstance(x, str):        
        return base64.urlsafe_b64encode(x)

    elif isinstance(x, (int, long, BigInt)):
        return hex(long(x))

    # All other items
    else:
        raise NotImplementedError("Cannot unwrap {}; only types {} supported".
            format(type(x), 
                [G1Element, G2Element, GtElement, int, long, BigInt]) )


# Individual unwrap functions
unwrapStr = lambda x: base64.urlsafe_b64decode(x)
unwrapG1 = lambda x: _unwrap(x, deserializeG1)
unwrapG2 = lambda x: _unwrap(x, deserializeG2)
unwrapGt = lambda x: _unwrap(x, deserializeGt)
unwrapLong = lambda x: long(x, 16)


def _wrap(x, serializeFunc, encodeFunc=base64.urlsafe_b64encode, compress=True):
    """
    Wraps an element @x by serializing and then encoding the resulting bytes.
    """
    return encodeFunc(serializeFunc(x, compress))


def _unwrap(x, deserializeFunc, decodeFunc=base64.urlsafe_b64decode, compress=True):
    """
    Unwraps an element @x by decoding and then deserializing
    """
    return deserializeFunc(decodeFunc(str(x)), compress)

