"""
Common routines
"""    
import binascii, hashlib
import hmac as HMAC

# RELIC comparison flags from relic_core.h
LESS_THAN = -1
EQUAL = 0
GREATER_THAN = 1
NOT_EQUAL = 2


def assertSameType(a, b):
    """
    Raises an exception if @b is not an instance of type(@a)
    """
    if not isinstance(b, type(a)):
        raise NotImplementedError("This operation is only supported for " \
            "elements of the same type. Instead found {} and {}".
                format(type(a), type(b)))


def assertType(var, *allowedTypes):
    """
    Asserts that a variable @var is of an @expectedType. Raises a TypeError
    if the assertion fails.
    """
    if not isinstance(var, *allowedTypes):
        raise NotImplementedError("This operation is only supported for {}. "\
            "Instead found {}".format(str(*allowedTypes), type(var)))


def dp(**kwargs):
    """
    Debugging print. Prints a list of labels and values, each on their
    own line.
    """
    for label,value in kwargs.iteritems():
            print "{0}\t{1}".format(label, value)


def hmac(key, message, tag=None, alg=hashlib.sha256):
    """
    Generates a hashed message authentication code (HMAC) by prepending the
    specified @tag string to a @message, then hashing with to HMAC 
    using a cryptographic @key and hashing @alg -orithm.
    """
    return HMAC.new(str(key), str(tag) + str(message), digestmod=alg).digest()


def hexString(values):
    """
    Generate a readable hexadecimal string from a list of binary @values.
    """
    # NOTE: abs(v) is used to discard leading minus sign (-)
    return " ".join([format(abs(v), 'X') for v in values])


def longFromString(x):
    """
    Convert arbitrary strings to long values.
    """
    return int(binascii.hexlify(x), 16)


