#!/usr/bin/env python

from distutils.core import setup

version = open('version').read().strip()

setup(name='bencodetools',
      version=version,
      description=('C and Python libraries for manipulating and validating '
                   'bencoded data'),
      author='Heikki Orsila, Janne Kulmala',
      author_email='heikki.orsila@iki.fi, janne.t.kulmala@tut.fi',
      url='http://http://zakalwe.fi/~shd/foss/bencode-tools/',
      py_modules=['bencode', 'typevalidator'],
     )
