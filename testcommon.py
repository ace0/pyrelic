"""
Common testing routines
"""

import random, string

def randomstr(n=64):
    """
    Generate a random string of length @n.
    """
    pop = string.digits + string.lowercase + string.uppercase
    return ''.join(random.choice(pop) for _ in range(n))


def randomNoRepeat(func, n=100):
    """
    Grab @n elements using @func and ensure there are no duplicates 
    according to their string representations.
    """
    seen = set()
    for _ in range(n):
        g = str(func())

        # Ensure this element has been seen previously
        if g in seen:
            raise Exception("Unexpected duplicate: {}".format(g))

        seen.add(g)


def repeat(func, n=1000):
    """
    Call @func @n times.
    """
    for _ in range(n):
        func()
