#!/usr/bin/python
#
# Verify functions
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
from asn1crypto.algos import DSASignature
from crypto import hash
from crypto.rsa import verify as rsa_verify
from crypto.ecc.ecdsa import verify as _ecdsa_verify


def ecdsa_verify(h, sig, key):
    """
    Wrapper to crypto.ecc.ecdsa.verify to properly format the inputs

    h
        hash of the msg
    sig
        signature to verify
    key
        crypto.ecc.Key.Key object
    :return:
        True if the signature is valid
    """
    _ecSig = DSASignature().from_p1363(sig)
    _rVal = int(_ecSig['r'])
    _sVal = int(_ecSig['s'])
    return _ecdsa_verify(int(h.encode('hex'), 16), (_rVal, _sVal), key._pub)


def _verify_fail(*args, **kwargs):
    assert False, 'Algorithm not supported'


def _hash_void(msg):
    """Do not hash if the verify function does it"""
    return msg


def getHashByName(algo):
    return {
        'md5_rsa'      : _hash_void,
        'sha1_rsa'     : _hash_void,
        'sha224_rsa'   : _hash_void,
        'sha256_rsa'   : _hash_void,
        'sha384_rsa'   : _hash_void,
        'sha512_rsa'   : _hash_void,
        'md5_ecdsa'    : hash.md5,
        'sha1_ecdsa'   : hash.sha1,
        'sha224_ecdsa' : hash.sha224,
        'sha256_ecdsa' : hash.sha256,
        'sha384_ecdsa' : hash.sha384,
        'sha512_ecdsa' : hash.sha512,
    }.get(algo, _verify_fail)


def getVerifyByName(algo):
    return {
        'md5_rsa'      : rsa_verify,
        'sha1_rsa'     : rsa_verify,
        'sha224_rsa'   : rsa_verify,
        'sha256_rsa'   : rsa_verify,
        'sha384_rsa'   : rsa_verify,
        'sha512_rsa'   : rsa_verify,
        'md5_ecdsa'    : ecdsa_verify,
        'sha1_ecdsa'   : ecdsa_verify,
        'sha224_ecdsa' : ecdsa_verify,
        'sha256_ecdsa' : ecdsa_verify,
        'sha384_ecdsa' : ecdsa_verify,
        'sha512_ecdsa' : ecdsa_verify,
    }.get(algo, _verify_fail)


def verify(algo, msg, sig, key):
    """
    :return:
        True if signature is valid
    """
    h = getHashByName(algo)(msg)
    return getVerifyByName(algo)(h, sig, key)
