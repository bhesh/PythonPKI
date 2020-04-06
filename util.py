#!/usr/bin/python
#
# Random utility functions
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
from base64 import b64decode, b64encode
from textwrap import wrap
from asn1crypto import core as asn
from datetime import tzinfo, timedelta
import os, sys


def encodeDERFile(bitstr, file=sys.stdout):
    file.write(bitstr)


def encodePEMFile(bitstr, file=sys.stdout, header=str(), footer=str()):
    lines = [header] + wrap(b64encode(bitstr), width=64) + [footer]
    file.write('\n'.join(lines))


def decodeDERFile(filename):
    with open(filename, 'r') as f:
        return f.read()


def decodePEMFile(filename):
    b64_encoded = str()
    record = False
    with open(filename, 'r') as f:
        for line in f.readlines():
            if record and 'END' not in line:
                b64_encoded += line.strip()
            elif 'BEGIN' in line:
                record = True
            elif 'END' in line:
                record = False
    assert not record and len(b64_encoded) > 0, 'Invalid certificate file'
    return b64decode(b64_encoded)


def prettify(name, asn1obj, space=4, depth=0, file=sys.stdout):
    padding = ' '*space*depth

    # Parse the object if it hasn't been
    if isinstance(asn1obj, (asn.ParsableOctetString, asn.ParsableOctetBitString)):
        asn1obj = asn1obj.parsed

    # Set the name
    if len(name) > 0:
        name = str(name).rstrip('=') + '='
    else:
        name = type(asn1obj).__name__ + '='

    # Print based on object type/structure
    if isinstance(asn1obj, asn.Choice):
        prettify(name, asn1obj.chosen, space=space, depth=depth, file=file)
    elif isinstance(asn1obj, (asn.Sequence, asn.Set)):
        print(padding + name + '{', file=file)
        for k in asn1obj:
            prettify(k, asn1obj[k], space=space, depth=(depth + 1), file=file)
        print(padding + '}', file=file)
    elif isinstance(asn1obj, (asn.SequenceOf, asn.SetOf)):
        print(padding + name + '[', file=file)
        for item in asn1obj:
            prettify('', item, space=space, depth=(depth + 1), file=file)
        print(padding + ']', file=file)
    elif isinstance(asn1obj, asn.ObjectIdentifier):
        if asn1obj.dotted in asn1obj._map:
            print(padding + name + asn1obj._map[asn1obj.dotted], file=file)
        return padding + name + asn1obj.dotted
    elif isinstance(asn1obj, (asn.OctetBitString, asn.OctetString)):
        print(padding + name + asn1obj.native.encode('hex'), file=file)
    elif isinstance(asn1obj, (asn.Null, asn.Void)):
        print(padding + name + type(asn1obj).__name__, file=file)
    else:
        print(padding + name + str(asn1obj.native), file=file)


def generateNonceSecure(length=20):
    "Generates a nonce of length bytes"
    return os.urandom(length)

ZERO = timedelta(0)

class UTC(tzinfo):
  def utcoffset(self, dt):
    return ZERO
  def tzname(self, dt):
    return "UTC"
  def dst(self, dt):
    return ZERO
