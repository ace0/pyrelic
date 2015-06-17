"""
An (unblinded) pseudorandom function protocol (PRF-P) with a zero-knowledge 
proof. Designed to work with Pythia API. For simplicity, this particular 
implementation uses G1 from the BN pairing-based curves, but any curve with 
sufficient security would also suffice.
"""
from pbc import *
from common import *
from vpop import genKw


def eval(w,t,m,msk,s):
    """
    Pythia server-side computation of intermediate PRF output.
    @w: ensemble key selector (e.g. webserver ID)
    @t: tweak (any string, e.g. user ID)
    @m: message (any string)
    @msk: Pythia server's master secret key
    @s: state value from Pythia server's key table
    @returns: (y, kw, dummy=None)
     where: y: intermediate result
            kw: secret key bound to w (needed for proof)
            beta: H(kw,t,m) (needed for proof)
    """
    # Verify types
    assertType(w, (str, int, long))
    assertType(t, (str, int, long))
    assertType(m, (str, int, long))

    # Construct the key
    kw = genKw(w,msk,s)

    # Conmpute y
    beta = hashG1(t, m)
    y = beta*kw
    return y,kw,beta


def prove(beta,kw,y):
    """
    Generate a zero-knowledge proof that DL(Q*kw) = DL(beta*kw) where
    <Q> = G1.
    """
    # Verify types
    assertScalarType(kw)
    assertType(beta, G1Element)
    assertType(y, G1Element)

    # Compute the proof.
    Q = generatorG1()
    p = Q*kw
    v = randomZ(orderG1())
    t1 = Q*v
    t2 = beta*v

    t1.normalize()
    t2.normalize()

    c = hashZ(Q,p,beta,y,t1,t2)
    u = (v-(c*kw)) % orderG1()
    return (p,c,u)


def verify(m, t, y, pi, errorOnFail=True):
    """
    Verifies a zero-knowledge proof.
    @errorOnFail: Raise an exception if the proof does not hold.
    """
    # Unpack the proof
    p,c,u = pi

    # Verify types
    assertType(m, str)
    assertType(t, str)
    assertType(y, G1Element)
    assertType(p, G1Element)
    assertScalarType(c)
    assertScalarType(u)

    # TODO: beta can be pre-computed while waiting for a server response.
    Q = generatorG1()
    beta = hashG1(t, m)

    # Recompute c'
    t1 = Q*u + p*c 
    t2 = beta*u + y*c

    t1.normalize()
    t2.normalize()

    cPrime = hashZ(Q,p,beta,y,t1,t2)

    # Check computed @c' against server's value @c
    if cPrime == c:
        return True

    if errorOnFail:
        raise Exception("zero-knowledge proof failed verification.")
    else:
        return False


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

    elif isinstance(x, (int, long, BigInt)):
        return hex(long(x))

    # All other items
    else:
        raise NotImplementedError("Cannot unwrap {}; only types {} supported".
            format(type(x), 
                [G1Element, G2Element, GtElement, int, long, BigInt]) )


# Individual unwrap functions
unwrapG1 = lambda x: _unwrap(x, deserializeG1)
unwrapG2 = lambda x: _unwrap(x, deserializeG2)
unwrapGt = lambda x: _unwrap(x, deserializeGt)
unwrapLong = lambda x: long(x, 16)

# Convenient unwrap shortcuts by variable name.
unwrapP = unwrapG1
unwrapY = unwrapGt
unwrapC = unwrapLong
unwrapU = unwrapLong


import base64 
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

