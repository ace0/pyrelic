"""
Elliptic curve Qu-Vanstone implicit certificate scheme.
"""
from relic import librelic
from ec import *
from bi import *
from common import *


def _exp(cert, idText):
    """
    Generates the exponent e by hashing @cert and @idText.
    """
    return hashZ(serializeEc(cert) + idText)


def sign(idText, request, caPrivkey):
    """
    A certificate authority (CA) generates an implicit certificate using 
    identity string @id, @request (certificate public key component), and 
    the CA's private key @caPrivkey.
    @returns (s, cert) where @r is the private key contribution and @cert is 
     the implicit certificate.
    """
    # Verify input types
    assertType(request, ec1Element)
    assertScalarType(caPrivkey)

    # Switch to new notation
    R = request
    d = caPrivkey
    G = generatorEc()
    N = orderEc()

    # TODO: use simultaneous mul to speed this up.
    # Random integer
    k = randomZ(N)
    P = R + k*G

    # Hash the identity string and implicit cert into an integer
    e = _exp(P, idText)

    # Compute the private key contribution
    r = (e*k + d) % N
    return (r, P)


def validate(idText, alpha, r, cert, caPubkey):
    """
    A server can validate an implicit certificate response using identity
    string @idText, private value @alpha (used to generate cert request),
    and the certificate response @r (private key component) and implicit
    @cert.
    @raises Exception if the certificate response is invalid.
    @returns (privkey, pubkey)
    """
    # Verify parameter types
    assertScalarType(alpha)
    assertScalarType(r)
    assertType(cert, ec1Element)
    assertType(caPubkey, ec1Element)

    G = generatorEc()

    # Compute the private key @s
    e = _exp(cert, idText)
    s = (e*alpha + r) % orderEc()

    # Compute the public key two ways: using the privkey and using the cert
    # (the way a client will compute it)
    # The easy way
    S1 = s*G

    # Using the cert
    S2 = e*cert + caPubkey

    # The two techniques should produce the same pubkey value -- raise an
    # exception if they don't match
    if S1 != S2:
        raise Exception("Implicit certification response failed validation")
    return s, S1


def recoverPubkey(idText, cert, caPubkey):
    """
    A client can recover the server's pubkey using the identity string @idText,
    server's implicit @cert, and the trusted @caPubkey.
    """
    # Verify types
    assertType(cert, ec1Element)
    assertType(caPubkey, ec1Element)

    # Compute the pubkey
    return _exp(cert, idText)*cert + caPubkey
