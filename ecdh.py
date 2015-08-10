"""
Server-authenticated elliptic curve Diffie-Hellman key agreement.
"""
from relic import librelic
from ec import *
from bi import *
from ctypes import byref
from common import *
import hashlib

hashalg = hashlib.sha256


def HASH(*args):
    """
    Combines each element of @args and runs them through the hashalg. EC
    elements are serialized.
    """
    def convert(x):
        if isinstance(x, ec1Element):
            return str(serializeEc(x))
        else:
            return str(x)

    instr = ''.join(map(convert, args))
    return hashalg(instr).digest()


def newKeyPair():
    """
    Generates a fresh, random elliptic curve private-public key pair.
    @returns (x, xG) where <G> = ECGroup.
    """
    x = randomZ(orderEc())
    xG = x * generatorEc()
    return x, xG


def sharedKeyServer(client, server, assocData):
    """
    Generates a shared key for the server.
    @client: must have the attribute: ePubkey
    @server: must have the attributes: ePrivkey, ltPrivkey
    @assocData: A string containg associated data to use when building the 
     shared secret key.
    """
    # Switch to compact notation
    X, y, s = client.ePubkey, server.ePrivkey, server.ltPrivkey

    # Verify types
    assertType(X, ec1Element)
    assertScalarType(y)
    assertScalarType(s)

    # Combine our parameters and generate the shared key.
    xy = X*y
    xs = X*s
    return genSharedKey(xy, xs, assocData)


def sharedKeyClient(client, server, assocData):
    """
    Generates a shared key for the client.
    @client: must have attribute ePrivkey
    @server: must have attributes ePrivkey, ltPrivkey
    @assocData: A string containg associated data to use when building the 
     shared secret key.
    """
    # Switch to compact notation
    x, Y, S  = client.ePrivkey, server.ePubkey, server.ltPubkey

    # Verify types
    assertScalarType(x)
    assertType(Y, ec1Element)
    assertType(S, ec1Element)

    xy = x*Y
    xs = x*S
    return genSharedKey(xy, xs, assocData)


def genSharedKey(xy, xs, assocData):
    """
    Generates a shared key from combined secrets @xy, @xs and @assocData.
    """
    return HASH(xy, xs, assocData)

