# from vpopProfile import *
from vpop import *
from testcommon import *

# Arbitrary operands for our protocol
w = "Some super-secret ensemble key selector"
t = "Totally random and unpredictable tweak"
m = "This is a secret message"
msk = randomstr(n=64)
s = "Super secret table value"
hash_in = randomstr(n=64)

iterations = 10000

@profile
def primitives():
    """
    Perform primitive operations for profiling
    """
    z = randomZ(orderG1())

    # G1 operations
    P,Q = randomG1(),randomG1()
    R = generatorG1()
    g1Add = P + Q
    g1ScalarMultiply = z*P
    g1GeneratorMultiply = z*R
    g1Hash = hashG1(hash_in)

    # G2 operations
    P,Q = randomG2(),randomG2()
    R = generatorG2()
    g2Add = P + Q
    g2ScalarMultiply = z*P
    g2GeneratorMultiply = z*R
    g2hash = hashG2(hash_in)

    # Gt operations
    P = randomGt()
    Q = randomGt()
    gtMult = P * Q
    gtExp = P**z

    # Pairing
    x,y = (randomG1(), randomG2())
    R = pair(x,y)


@profile
def protoWithProof():
    """
    Run the full protocol including proof generation and verification.
    """
    r, x = blind(m)
    y,kw,tTilde = eval(w,t,x,msk,s)

    pi = prove(x, tTilde, kw, y)
    verify(x, t, y, pi, errorOnFail=True)

    z = deblind(r, y)


@profile
def proofMethods():
    """
    Run the full protocol including proof generation and verification.
    """
    r, x = blind(m)
    y,kw,tTilde = eval(w,t,x,msk,s)

    # Proof in Gt/Gt
    pi = proveGt(x, tTilde, kw, y)
    verifyGt(x, tTilde, y, pi, errorOnFail=True)

    # Proof in G1/Gt
    pi = proveG1(x, tTilde, kw, y)
    verifyG1(x, tTilde, y, pi, errorOnFail=True)

    z = deblind(r, y)


@profile
def protoProofGt():
    r, x = blind(m)
    y,kw,tTilde = eval(w,t,x,msk,s)
    pi = proveGt(x, tTilde, kw, y)
    verifyGt(x, tTilde, y, pi, errorOnFail=True)
    z = deblind(r, y)


@profile
def protoProofG1():
    r, x = blind(m)
    y,kw,tTilde = eval(w,t,x,msk,s)
    pi = proveG1(x, tTilde, kw, y)
    verifyG1(x, tTilde, y, pi, errorOnFail=True)
    z = deblind(r, y)


@profile
def proofMethods():
    """
    Run the full protocol including proof generation and verification.
    """
    r, x = blind(m)
    y,kw,tTilde = eval(w,t,x,msk,s)

    # Proof in Gt/Gt
    pi = proveGt(x, tTilde, kw, y)
    verifyGt(x, tTilde, y, pi, errorOnFail=True)

    # Proof in G1/Gt
    pi = proveG1(x, tTilde, kw, y)
    verifyG1(x, tTilde, y, pi, errorOnFail=True)

    z = deblind(r, y)


@profile   
def protoFast():
    """
    Runs the protocol but omits proof generation and verification.
    """
    r, x = blind(m)
    y,kw,tTilde = eval(w,t,x,msk,s)
    z = deblind(r, y)


def repeat(func, n=iterations):
    """
    Call @func @n times.
    """
    for _ in range(n):
        func()

# Run!
if __name__ == "__main__":
    repeat(primitives)
    # repeat(protoFast)
    # repeat(protoWithProof)
    # repeat(proofMethods)
    # repeat(protoProofG1)
    # repeat(protoProofGt)
