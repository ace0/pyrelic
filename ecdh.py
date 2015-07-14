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


def sharedKeyServer(eClientPubkey, eServerPrivkey, ltServerPrivkey, assocData):
    """
    Generates a shared key for the server.
    @eClientPubkey: Client's ephemeral DH share
    @eServerPrivkey: Server's ephemeral DH share
    @ltServerPrivkey: Serverls long-term private key
    @assocData: A string containg associated data to use when building the 
     shared secret key.
    """
    # Switch to compact and common notation
    X, y, s = eClientPubkey, eServerPrivkey, ltServerPrivkey
    xy = X*y
    xs = X*s
    return genSharedKey(xy, xs, assocData)


def sharedKeyClient(eClientPrivKey, eServerPubkey, ltServerPubkey, assocData):
    """
    Generates a shared key for the server.
    @eClientPubkey: Client's ephemeral DH share
    @eServerPubkey: Server's ephemeral DH share
    @ltServerPubkey: Server's long-term pubkey key
    @assocData: A string containg associated data to use when building the 
     shared secret key.
    """
    # Switch to compact and common notation
    x, Y, S  = eClientPrivKey, eServerPubkey, ltServerPubkey
    xy = x*Y
    xs = x*S
    return genSharedKey(xy, xs, assocData)


def genSharedKey(xy, xs, assocData):
    """
    Generates a shared key from combined secrets @xy, @xs and @assocData.
    """
    return HASH(xy, xs, assocData)

