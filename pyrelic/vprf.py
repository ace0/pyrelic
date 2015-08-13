"""
An (unblinded) verifiable, pseudorandom function (V PRF) designed to work with 
Pythia API. For simplicity, this particular implementation uses G1 from the BN
pairing-based curves, but any elliptic curve with sufficient security would 
also suffice.
"""
from pbc import *
from common import *
from prf import *

def eval(w,t,x,msk,s):
    """
    Pythia server-side computation of intermediate PRF output.
    @w: ensemble key selector (any string, e.g. webserver ID)
    @t: tweak (any string, e.g. user ID)
    @x: message (any string)
    @msk: Pythia server's master secret key
    @s: state value from Pythia server's key table
    @returns: (y, kw, dummy=None)
     where: y: intermediate result
            kw: secret key bound to w (needed for proof)
            beta: H(kw,t,x) (needed for proof)
    """
    # Verify types
    assertType(w, (str, int, long))
    assertType(t, (str, int, long))
    assertType(x, (str, int, long))

    # Construct the key
    kw = genKw(w,msk,s)

    # Compute y
    beta = hashG1(t, x)
    y = beta*kw
    return y,kw,beta


def prove(x,beta,kw,y):
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


def verify(x, t, y, pi, errorOnFail=True):
    """
    Verifies a zero-knowledge proof.
    @errorOnFail: Raise an exception if the proof does not hold.
    """
    # Unpack the proof
    p,c,u = pi

    # Verify types
    assertType(x, str)
    assertType(t, str)
    assertType(y, G1Element)
    assertType(p, G1Element)
    assertScalarType(c)
    assertScalarType(u)

    # TODO: beta can be pre-computed while waiting for a server response.
    Q = generatorG1()
    beta = hashG1(t, x)

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


# Blind/deblind are more or less the identity function. Included for
# API compatibility with the other Pythia PRFs.
blind = lambda m: (None, m)

def deblind(r,x):
    return x

# unwrap (decode and deserialize) elements by name
unwrapY = unwrapG1
unwrapP = unwrapG1
unwrapC = unwrapLong
unwrapU = unwrapLong

# We don't do any decoding or deserialization of the message parameter x in
# this version of the protocol.
unwrapX = lambda x: x
