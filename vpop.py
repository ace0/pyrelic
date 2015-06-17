"""
Pythia's Verifiable, Partially-Oblivious Pseudorandom Function (POP) protocol 
constructed using the BN-256 pairing-based curves provided by the RELIC library.
Also includes serialization and encoding routines for elements that are commonly
transmitted.
"""
from pbc import *


def eval(w,t,x,msk,s):
    """
    Pythia server-side computation of intermediate PRF output.
    @w: ensemble key selector (e.g. webserver ID)
    @t: tweak (e.g. user ID)
    @x: blinded message (element of G1)
    @msk: Pythia server's master secret key
    @s: state value from Pythia server's key table
    @returns: (y, kw, tTile)
     where: y: intermediate result
            kw: secret key bound to w (needed for proof)
            tTilde: hashed tweak (needed for proof)
    """
    # Construct the key
    kw = genKw(w,msk,s)

    # Multiply x by kw (it's fastest this way), hash the tweak, and compute
    # the pairing.
    tTilde = hashG2(t)
    y = pair(x*kw, tTilde)
    return y,kw,tTilde


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


def prove(x,tTilde,kw,y):
    """
    Generate a zero-knowledge proof that DL(Q*kw) == DL(e(x,tTilde)^kw) where
    <Q> = G1.
    @x: Blinded message from client request.
    @tTilde: HG2(t), element of G2
    @kw: secret key derived from w
    @y: intermediate result from eval function. element of Gt
    """
    # Verify types
    assertType(x, G1Element)
    assertType(tTilde, G2Element)
    assertType(y, GtElement)

    # Compute the proof.
    beta = pair(x,tTilde)
    Q = generatorG1()
    p = Q*kw
    v = randomZ(orderGt())
    t1 = Q*v
    t2 = beta**v

    t1.normalize()

    c = hashZ(Q,p,beta,y,t1,t2)
    u = (v-(c*kw)) % orderGt()
    return (p,c,u)


def verify(x, t, y, pi, errorOnFail=True):
    """
    Verifies a zero-knowledge proof where p \in G1.
    @errorOnFail: Raise an exception if the proof does not hold.
    """
    # Unpack the proof
    p,c,u = pi

    # Verify types
    assertType(x, G1Element)
    assertType(y, GtElement)
    assertType(p, G1Element)
    assertScalarType(c)
    assertScalarType(u)

    # TODO: beta can be pre-computed while waiting for a server response.
    Q = generatorG1()
    beta = pair(x,hashG2(t))

    # Recompute c'
    t1 = Q*u + p*c 
    t2 = beta**u * y**c

    t1.normalize()

    cPrime = hashZ(Q,p,beta,y,t1,t2)

    # Check computed @c' against server's value @c
    if cPrime == c:
        return True

    if errorOnFail:
        raise Exception("zero-knowledge proof failed verification.")
    else:
        return False


def blind(m, hashfunc=hashG1):
    """
    Blinds an arbitrary string or byte array @m using an ephemeral key @r
    that can be used to deblind. Computes: x = H(x)^r
    @returns (1/r,x)
    """
    # Find r with a suitable inverse in Gt
    rInv = None
    while not rInv:
        r = randomZ()
        rInv = inverse(r, orderGt())

    return rInv, hashfunc(m) * r


def deblind(rInv,y):
    """
    Removes blinding using ephemeral key @rInv on (intermediate result) 
    @y \in Gt.
    """
    # Verify types, then deblind using the values provided.
    assertScalarType(rInv)
    assertType(y, GtElement)
    return y ** rInv


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

