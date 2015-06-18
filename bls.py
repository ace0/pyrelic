"""
An (unblinded) pseudorandom function based on Boneh-Lynn-Shacham signatures 
designed for the Pythia API using BN254 pairing based curves.
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
            dummy: None (included only for compatibility with Pythia PRF API)
    """
    # Verify types
    assertType(w, (str, int, long))
    assertType(t, (str, int, long))
    assertType(x, (str, int, long))

    # Construct the key
    kw = genKw(w,msk,s)

    # Compute y
    y = hashG1(t, x)*kw
    return y,kw,None


def prove(x,t,kw,y):
    """
    Computes public key P*kw where <P> = G1. 
    x, t, and y are ignored. They are included only for API compatibility with 
    other Pythia PRF implementations.
    """
    # Verify the key type and compute the pubkey
    assertScalarType(kw)
    p = generatorG2() * kw
    return (p,None,None)


def verify(x, t, y, pi, errorOnFail=True):
    """
    Verifies a zero-knowledge proof.
    @errorOnFail: Raise an exception if the proof does not hold.
    """
    # Unpack the proof
    p,_,_ = pi

    # Verify types
    assertType(x, str)
    assertType(t, str)
    assertType(y, G1Element)
    assertType(p, G2Element)

    # TODO: beta can be pre-computed while waiting for a server response.
    beta = hashG1(t, x)

    # Compute q = e( H(t,m), P)**kw two ways
    q1 = pair(beta, p)
    q2 = pair(y, generatorG2())

    # The BLS signature is valid when q1 == q2
    if q1 == q2:
        return True

    if errorOnFail:
        raise Exception("BLS signature failed verification")
    else:
        return False


# Blind/deblind are more or less the identity function. Only included for
# API compatibility with the other Pythia PRFs.
blind = lambda m: (None, m)

def deblind (r,x): 
    return x

# unwrap (decode and deserialize) elements by name
unwrapY = unwrapG1
unwrapP = unwrapG2
unwrapC = lambda x: None
unwrapU = lambda x: None

# We don't do any decoding or deserialization of the message parameter x in
# this version of the protocol.
unwrapX = lambda x: x
