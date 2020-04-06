#!/usr/bin/python
#
# Hash function wrappers
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
import hashlib


def md5(msg):
    """
    :return:
        BitString of the hash
    """
    return hashlib.md5(msg).digest()


def sha1(msg):
    """
    :return:
        BitString of the hash
    """
    return hashlib.sha1(msg).digest()


def sha224(msg):
    """
    :return:
        BitString of the hash
    """
    return hashlib.sha224(msg).digest()


def sha256(msg):
    """
    :return:
        BitString of the hash
    """
    return hashlib.sha256(msg).digest()


def sha384(msg):
    """
    :return:
        BitString of the hash
    """
    return hashlib.sha384(msg).digest()


def sha512(msg):
    """
    :return:
        BitString of the hash
    """
    return hashlib.sha512(msg).digest()
