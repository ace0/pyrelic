"""
PIP setup script for the pyrelic package.
"""
from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()

description=\
  """pyrelic is a python module to interact with the RELIC cryptography library
  which performs high-performance elliptic curve cryptography and pairing-based
  elliptic curves. pyrelic also includes verifiable pseudorandom functions
  used in Pythia.
  """
description = ' '.join(description.split())

setup(name='pythia-pyrelic',
      version='1.0.1',
      description=description,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: MacOS',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX :: Linux',
          'Operating System :: Unix',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Topic :: Security', 
          'Topic :: Security :: Cryptography',
      ],
      url='https://github.com/ace0/pyrelic',
      author='Adam Everspaugh',
      author_email='ace@cs.wisc.edu',
      license='MIT',
      keywords='encryption, elliptic curve cryptography, pairing based cryptography, oblvious pseudorandom function, partially oblivious pseudorandom function',
      package_data= { 'pyrelic': ['lib/*'] },
      packages=['pyrelic'],
      zip_safe=False, 
    )
