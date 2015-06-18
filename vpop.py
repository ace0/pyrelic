"""
Pythia's Verifiable, Partially-Oblivious Pseudorandom Function (POP) protocol 
constructed using the BN-256 pairing-based curves provided by the RELIC library.
Also includes serialization and encoding routines for elements that are commonly
transmitted.
"""
from pbc import *
from prf import *

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


# Decode/deserialize elements by name
unwrapX = unwrapG1
unwrapY = unwrapGt
unwrapP = unwrapG1
unwrapC = unwrapLong
unwrapU = unwrapLong
