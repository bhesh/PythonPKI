#!/usr/bin/python
#
# Utilities for crypto functions
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
import random, math


def miller_rabin(n, k=40):
    """
    Tests for the likeliness of prime using the Miller-Rabin Primality Test
    The optimal number of rounds for this test is 40
    See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    for justification
    """
    if n in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37): return True
    if n < 2 or n % 2 == 0: return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    try:
        for _ in xrange(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in xrange(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else: return False
    except:
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else: return False
    return True


def generatePrime(bits=2048, rounds=40):
    """
    Securely generates a random n-bit number that is very likely to be prime.

    NOTE: This does NOT guarantee a prime number
    """
    r = random.SystemRandom()
    while True:
        test = r.randrange(2**(bits - 1) + 1, (2**bits) - 1, 2)
        if miller_rabin(test, k=40): return test


def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g == 1:
        return x % b


if __name__ == '__main__':
    print(generatePrime(bits=2048))
