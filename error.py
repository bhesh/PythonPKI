#!/usr/bin/python
#
# Errors
#
# @author Brian Hession
# @email hessionb@gmail.com
#

class Error(Exception):
    def __init__(self, msg=None):
        if not msg: msg = type(self).__name__
        super(Exception, self).__init__(msg)

class NotBeforeError(Error):
    def __init__(self):
        super(Error, self).__init__('Certificate is not yet valid')

class NotAfterError(Error):
    def __init__(self):
        super(Error, self).__init__('Certificate is expired')

class ThisUpdateError(Error):
    def __init__(self):
        super(Error, self).__init__('OCSP proof is not yet valid')

class NextUpdateError(Error):
    def __init__(self):
        super(Error, self).__init__('OCSP proof has expired')

class InvalidOCSPSignature(Error):
    def __init__(self):
        super(Error, self).__init__('OCSP signature is invalid')

class InvalidIssuerSignature(Error):
    def __init__(self):
        super(Error, self).__init__('Issuer signature is invalid')

class RevokedStatusError(Error):
    def __init__(self, reason):
        super(Error, self).__init__('Certificate is revoked - {}'.format(reason))

class UnknownStatusError(Error):
    def __init__(self):
        super(Error, self).__init__('Unknown certificate status')
