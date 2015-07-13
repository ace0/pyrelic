"""
Server-authenticated elliptic curve Diffie-Hellman key agreement.
"""
from relic import librelic
from ec import *
from bi import *
from ctypes import byref
from common import *


def newKeyPair():
    """
    Generates a fresh, random elliptic curve private-public key pair.
    @returns (x, xG) where <G> = ECGroup.
    """
    x = randomZ(orderEc())
    xG = x * generatorEc()
    return x, xG

