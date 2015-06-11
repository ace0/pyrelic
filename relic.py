"""
Python interface to the RELIC cryptographic library.
"""
import atexit, ctypes, sys
from common import *

# NOTE: This module was designed, built, and tested assuming that the RELIC
#       C library was built on a 64-bit OSX platform. This module further
#       assumes the follow RELIC configuration settings
#
# ALLOC = AUTO
# WORD = 64
# BN_MAGNI = DOUBLE
# BN_SIZE = 18

# Known file extensions for dynamically-linked libraries (shared objects)
# on various OS's that we've tested and support.

# OSX
if sys.platform == "darwin":
    ext = "dylib"

# Linux
elif sys.platform.startswith("linux"):
    ext = "so"

# Windows - this has never been tested
elif sys.platform == "win32":
    ext = "dll"

else:
    raise Exception("Unsupported operating system: only OSX, Linux, and "\
        "Windows are currently supported.")


# Basename for compiled relic library
name = "librelic"
location = "./lib"

# Full path to librelic
path = "{}/{}.{}".format(location, name, ext)

# Load the relic library
librelic = ctypes.cdll.LoadLibrary(path)

# Initialize the RELIC core (memory allocation, error handling, and  
# other internal state)
if librelic.core_init() != 0:
    raise Exception("Could not initialize RELIC core")

# Set the pairing based curve (PC) parameters.
if librelic.pc_param_set_any_abi() != 0:
    raise Exception("Could not set curve parameters")


@atexit.register
def cleanup():
    """
    Relic library clean-up routine. Registered to be called on module exit.
    """
    librelic.core_clean()

