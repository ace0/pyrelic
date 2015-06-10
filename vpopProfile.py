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
    kw = genKw(w,msk,s)

    # TODO: Return cached values for precomputation
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
    TAG_KW = "TAG_PYTHIA_KW"
    b = hmac(TAG_KW, msk, z + w)

    # Convert the string into a long value (no larger than the order of Gt),
    # then return a BigInt value.
    return BigInt(longFromString(b) % long(orderGt()))


def prove(x,tTilde,kw,y):
    return proveGt(x,tTilde,kw,y)

def verify(x, tTilde, y, pi, errorOnFail=True):
    return verifyGt(x, tTilde, y, pi, errorOnFail)

@profile
def proveGt(x,tTilde,kw,y):
    """
    Generate a zero-knowledge proof that DL(g^kw) == DL(e(x,t)^kw) where
    g,e(..) \in Gt.
    @return pi = (p,c,u)
    """
    # Verify types
    assertType(x, G1Element)
    assertType(tTilde, G2Element)

    # Compute the proof.
    beta = pair(x,tTilde)
    g = generatorGt()
    p = g**kw
    v = randomZ(orderGt())
    t1 = g**v
    t2 = beta**v

    c = hashZ(g,p,beta,y,t1,t2)
    u = (v- (c*kw)) % orderGt()
    return (p,c,u)

@profile
def proveG1(x,tTilde,kw,y):
    """
    Generate a zero-knowledge proof that DL(Q*kw) == DL(e(x,tTilde)^kw) where
    <Q> = G1.
    """
    # Verify types
    assertType(x, G1Element)
    assertType(tTilde, G2Element)

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

@profile
def verifyG1(x, tTilde, y, pi, errorOnFail=True):
    """
    Verifies a zero-knowledge proof where p \in G1.
    @errorOnFail: Raise an exception if the proof does not hold.
    """
    # Unpack the proof
    p,c,u = pi

    # Verify types
    assertType(x, G1Element)
    assertType(tTilde, G2Element)
    assertType(y, GtElement)
    assertType(p, G1Element)

    # TODO: beta can be pre-computed while waiting for a server response.
    Q = generatorG1()
    beta = pair(x,tTilde)

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

@profile
def verifyGt(x, tTilde, y, pi, errorOnFail=True):
    """
    Verifies a zero-knowledge proof. 
    @x: Blinded message, G1Element, x = HG1(m)*r
    @tTilde: hashed tweak, G2Element, t~ = HG2(t)
    @y: server response (intermediate result), GtElement
    @pi:  pi = (p, c, u), zero-knowledge proof from server, 
      p = g^kw, GtElement; c,u integer values
    @errorOnFail: Rasise an exception if the proof does not hold.
    """
    # Unpack the proof
    p,c,u = pi

    # Verify types
    assertType(x, G1Element)
    assertType(tTilde, G2Element)
    assertType(y, GtElement)
    assertType(p, GtElement)

    # TODO: This can be pre-computed while waiting for a server response.
    g = generatorGt()
    beta = pair(x,tTilde)

    # Recompute c'
    t1 = g**u * p**c 
    t2 = beta**u * y**c

    cPrime = hashZ(g,p,beta,y,t1,t2)

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
    Removes blinding using ephemeral key @r on (intermediate result) @y \in Gt.
    """
    # Find the multiplicative inverse of @r in Gt.
    return y ** rInv


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
    return deserializeFunc(decodeFunc(x), compress)

def _wrapG1(x):
    return _wrap(x, serializeG1)

def _unwrapG1(x):
    return _unwrap(x, deserializeG1)

def _wrapGt(x):
    return _wrap(x, serializeGt)

def _unwrapGt(x):
    return _unwrap(x, deserializeGt)

wrapX = _wrapG1
unwrapX = _unwrapG1
wrapY = _wrapGt
unwrapY = _unwrapGt

