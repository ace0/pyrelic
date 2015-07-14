"""
Elliptic curve Qu-Vanstone implicit certificate scheme.
"""
from relic import librelic
from ec import *
from bi import *
from common import *
import hashlib


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
    assertType(caPrivkey, BigInt)
    R = request
    d = caPrivkey
    G = generatorEc()
    N = orderEc()

    # TODO: use simultaneous mul to speed this up.
    # Random integer
    k = randomZ(N)
    P = R + k*G

    # Hash the identity string into an integer
    # BUG: This needs to be H(cert(P) || idText)
    e = hashZ(idText)

    # Compute the private key contribution
    r = (e*k + d) % N
    return (r, cert)


def validate(idText, alpha, r, cert, caPubkey):
    """
    A server can validate an implicit certificate response using identity
    string @idText, private value @alpha (used to generate cert request),
    and the certificate response @r (private key component) and implicit
    @cert.
    @raises Exception if the certificate response is invalid.
    @returns (privkey, pubkey)
    """
    # TODO: Verify types
    G = generatorEc()

    # Compute the private key @s
    e = hashZ(idText, cert)
    s = e*alpha + r

    # Compute the public key two ways: using the privkey and using the cert
    # (the way a client will compute it)
    # The easy way
    S1 = s*G

    # Using the cert
    S2 = e*cert + caPubkey

    # Compare the results and raise an exception if they don't match
    if S1 != S2:
        raise Exception("Implicit certifcate response failed validation")
    return s, S1


def recoverPubkey(idText, cert, caPubkey):
    """
    A client can recover the server's pubkey using the identity string @idText,
    server's implicit @cert, and the trusted @caPubkey.
    """
    # Verify types
    assertType(cert, ec1Element)
    assertType(caPubkey, ec1Element)

    # Recompute the pubkey
    e = hashZ(idText, cert)
    S = e*cert + caPubkey
    return S



# LEFT OFF:
# Building implicit certs => need to write unit tests
# Need client implicit cert construction factored from the above
# Integrate ECQV-EDH into hopsocket and test it out
# Add AES-GCM crypto to payloads and we'll have a proper secure channel!    
