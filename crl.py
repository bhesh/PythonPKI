#!/usr/bin/python
#
# Functions for CRL encoded objects
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
import cert, datetime, error, sys, urllib2, util
from asn1crypto import crl
from crypto import hash
from verify import verify as verifycrl
from env import *


class RevokedCertificate(crl.RevokedCertificate):
    "Structure defining an ASN.1 Revoked Certificate entry"

    @staticmethod
    def fromBitString(cert):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return RevokedCertificate().load(cert)

    @staticmethod
    def fromPEMFile(certFile):
        return RevokedCertificate.fromBitString(util.decodePEMFile(certFile))

    @staticmethod
    def fromDERFile(certFile):
        return RevokedCertificate.fromBitString(util.decodeDERFile(certFile))

    def toBitString(self):
        return self.dump()

    def writeDERFile(self, file=sys.stdout):
        util.encodeDERFile(self.toBitString(), file=file)

    def writePEMFile(self, file=sys.stdout):
        util.encodePEMFile(self.toBitString(), file=file,
                header='-----BEGIN REVOKED CERTIFICATE-----',
                footer='-----END REVOKED CERTIFICATE-----')

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('RevokedCertificate', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        print('{}RevokedCertificate'.format(prefix), file=file)
        print('{}{}Serial:'.format(prefix, padding), '{:X}'.format(self.getSerial()), file=file)
        print('{}{}Date:'.format(prefix, padding), self.getDate(), file=file)
        print('{}{}Reason:'.format(prefix, padding), self.getReason(), file=file)

    def getIssuer(self):
        """
        :return:
            String representing the issuer
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in cert.parseNameObject(self.issuer_name)])

    def getSerial(self):
        """
        :return:
            Integer of the serial number
        """
        return self['user_certificate'].native

    def getDate(self):
        """
        :return:
            DateTime of the revocation date
        """
        return self['revocation_date'].native

    def getReason(self):
        """
        :return:
            String representing the reason of revocation
        """
        return self.crl_reason_value.native


class CertificateList(crl.CertificateList):
    "Structure defining an ASN.1 CRL"

    @staticmethod
    def fromBitString(cert):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return CertificateList().load(cert)

    @staticmethod
    def fromPEMFile(certFile):
        return CertificateList.fromBitString(util.decodePEMFile(certFile))

    @staticmethod
    def fromDERFile(certFile):
        return CertificateList.fromBitString(util.decodeDERFile(certFile))

    def toBitString(self):
        return self.dump()

    def writeDERFile(self, file=sys.stdout):
        util.encodeDERFile(self.toBitString(), file=file)

    def writePEMFile(self, file=sys.stdout):
        util.encodePEMFile(self.toBitString(), file=file,
                header='-----BEGIN X509 CRL-----',
                footer='-----END X509 CRL-----')

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('CertificateList', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        print('{}CertificateList'.format(prefix), file=file)
        print('{}{}SHA-256 Fingerprint:'.format(prefix, padding), self.getSha256().encode('hex'), file=file)
        print('{}{}Issuer:'.format(prefix, padding), self.getIssuer(), file=file)
        print('{}{}This Update:'.format(prefix, padding), self.getThisUpdate(), file=file)
        print('{}{}Next Update:'.format(prefix, padding), self.getNextUpdate(), file=file)
        try:
            self.isValid()
            print('{}{}Valid: True'.format(prefix, padding), file=file)
        except error.Error as e:
            print('{}{}Valid:'.format(prefix, padding), str(e), file=file)
        for rc in self.getRevokedCertificates(): rc.printCLI(prefix=prefix, space=space, file=file)

    def getMd5(self):
        return hash.md5(self.dump())

    def getSha1(self):
        return hash.sha1(self.dump())

    def getSha224(self):
        return hash.sha224(self.dump())

    def getSha256(self):
        return hash.sha256(self.dump())

    def getSha384(self):
        return hash.sha384(self.dump())

    def getSha512(self):
        return hash.sha512(self.dump())

    def getSignatureAlgorithm(self):
        """
        :return:
            None or String of the signature algorithm
        """
        _signedDigestAlgo = self['signature_algorithm']
        if not _signedDigestAlgo:
            return None
        _sigOid = _signedDigestAlgo['algorithm']
        if not _sigOid:
            return None
        return _sigOid.map(_sigOid.dotted).encode('utf8')

    def getSignature(self):
        """
        :return:
            BitString of the signature
        """
        return self.signature

    def getThisUpdate(self):
        """
        :return:
            DateTime of the This Update date
        """
        return self['tbs_cert_list']['this_update'].native

    def getNextUpdate(self):
        """
        :return:
            DateTime of the Next Update date
        """
        return self['tbs_cert_list']['next_update'].native

    def getIssuer(self):
        """
        :return:
            String representing the issuer
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in cert.parseNameObject(self.issuer)])

    def getRevokedCertificates(self):
        """
        :return:
            List of RevokedCertificate ASN.1 objects
        """
        certList = list()
        revList = self['tbs_cert_list']['revoked_certificates']
        if revList:
            for r in revList:
                certList.append(RevokedCertificate.fromBitString(r.dump()))
        return certList

    def isValid(self):
        """
        :return:
            True or an error
        """
        _now = datetime.datetime.now(util.UTC())
        _thisUpdate = self.getThisUpdate()
        _nextUpdate = self.getNextUpdate()
        if not _thisUpdate or _thisUpdate > _now:
            raise error.ThisUpdateError()
        if not _nextUpdate or _nextUpdate < _now:
            raise error.NextUpdateError()
        return True

    def verifySignature(self, issuer):
        """
        :return:
            True or an error
        """
        return verifySignature(issuer)

    def contains(self, certificate):
        """
        certificate
            Certificate ASN. object or serial number
        :return:
            True if the certificate is on the list
        """
        if isinstance(certificate, cert.Certificate):
            for rc in self.getRevokedCertificates():
                if rc.getIssuer() == certificate.getIssuer() and rc.getSerial() == certificate.getSerial():
                    return True
        elif isinstance(certificate, (int, long)):
            for rc in self.getRevokedCertificates():
                if rc.getSerial() == certificate:
                    return True
        return False


def verifySignature(certList, issuer):
    """
    :return:
        True if signature is valid. Error otherwise
    """
    _algo = certList.getSignatureAlgorithm()
    _sig = certList.getSignature()
    if not _algo or not _sig:
        raise error.InvalidIssuerSignature()
    _msg = certList['tbs_cert_list'].dump()
    _key = issuer.getPublicKey()
    try:
        if not bool(verifycrl(_algo, _msg, _sig, _key)):
            raise error.InvalidIssuerSignature()
    except VerificationError:
        raise error.InvalidIssuerSignature()
    return True


def downloadCRL(url, outFile=None, progressnotifier=None, blocksize=1024):
    """
    :return:
        CertificateList ASN.1 object
    """

    # Open HTTP connection
    headers = {
        'Accept' : 'application/pkix-crl',
        'User-Agent' : USER_AGENT
    }
    req = urllib2.Request(url, headers=headers)
    res = urllib2.urlopen(req, timeout=1)

    # Download in chunks
    totalBytes = int(res.info().getheader('Content-Length').strip())
    bytesRead = 0
    data = str()
    while bytesRead < totalBytes:

        # Read chunk
        bytesToRead = blocksize
        if totalBytes - bytesRead < bytesToRead:
            bytesToRead = totalBytes - bytesRead
        data += res.read(bytesToRead)
        bytesRead = len(data)

        # Update progress
        if progressnotifier: progressnotifier(bytesRead, totalBytes)

    # Write to file if specified
    if outFile:
        with open(outFile, 'w') as f:
            f.write(data)
    return CertificateList.fromBitString(data)

