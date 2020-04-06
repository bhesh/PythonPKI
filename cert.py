#!/usr/bin/python
#
# Functions for x509 encoded objects
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
import crypto.ecc.ecdsa, datetime, error, sys, util
from asn1crypto import x509
from crypto.rsa import PublicKey as RSAPublicKey
from crypto.rsa import VerificationError
from crypto.ecc.Key import Key as ECPublicKey
from verify import verify as verifycert


def parseNameType(field):
    return {
        'common_name': 'CN',
        'country_name': 'C',
        'locality_name': 'L',
        'state_or_province_name': 'ST',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
    }.get(field, field)


def parseNameObject(nameobj):
    name = list()
    for rdn in nameobj.chosen:
        for type_val in rdn:
            _field = parseNameType(type_val['type'].native)
            _value = type_val['value'].native
            name.append((_field, _value))
    return name


class Certificate(x509.Certificate):
    "Structure defining an ASN.1 Certificate"

    @staticmethod
    def fromBitString(cert):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return Certificate().load(cert)

    @staticmethod
    def fromPEMFile(certFile):
        return Certificate.fromBitString(util.decodePEMFile(certFile))

    @staticmethod
    def fromDERFile(certFile):
        return Certificate.fromBitString(util.decodeDERFile(certFile))

    def toBitString(self):
        return self.dump()

    def writeDERFile(self, file=sys.stdout):
        util.encodeDERFile(self.toBitString(), file=file)

    def writePEMFile(self, file=sys.stdout):
        util.encodePEMFile(self.toBitString(), file=file,
                header='-----BEGIN CERTIFICATE-----',
                footer='-----END CERTIFICATE-----')

    def getNameSha1(self):
        return self.subject.sha1

    def getNameSha256(self):
        return self.subject.sha256

    def getKeySha1(self):
        return self.public_key.sha1

    def getNameSha256(self):
        return self.subject.sha256

    def getSerial(self):
        return self.serial_number

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('Certificate', self, space=space, file=file)

    def getSubject(self):
        """
        :return:
            String representing the subject
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in parseNameObject(self.subject)])

    def getIssuer(self):
        """
        :return:
            String representing the issuer
        """
        return ', '.join(['{}={}'.format(a, b) for a, b in parseNameObject(self.issuer)])

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

    def getNotBefore(self):
        """
        :return:
            DateTime of the Not Before date
        """
        return self.not_valid_before

    def getNotAfter(self):
        """
        :return:
            DateTime of the Not After date
        """
        return self.not_valid_after

    def getPublicKeyAlgorithm(self):
        """
        :return:
            String containing the key algorithm
        """
        return self['tbs_certificate']['subject_public_key_info'].algorithm.encode('utf8')

    @staticmethod
    def _toRSAPublicKey(asn1obj):
        """
        asn1obj
            PublicKeyInfo ASN.1 object
        :return:
            crypto.rsa.PublicKey
        """
        _key = asn1obj['public_key'].parsed
        return RSAPublicKey(_key['modulus'].native, _key['public_exponent'].native)

    @staticmethod
    def _toECKey(asn1obj):
        """
        asn1obj
            PublicKeyInfo ASN.1 object
        :return:
            crypto.ecc.Key.Key
        """
        _algoParam = asn1obj['algorithm']['parameters'].native.encode('utf8')
        kbits = {
            'secp192r1' : 192,
            'secp224r1' : 224,
            'secp256r1' : 256,
            'secp384r1' : 384,
            'secp521r1' : 521,
        }.get(_algoParam, 0)
        assert kbits > 0, 'Algorithm not supported: {}'.format(_algoParam)
        x, y = asn1obj['public_key'].to_coords()
        pubKey = ECPublicKey((kbits, (x, y)))
        assert crypto.ecc.ecdsa.validate_public_key(pubKey._pub), 'Invalid public key'
        return pubKey

    def getPublicKey(self):
        """
        :return:
            crypto.rsa.PublicKey or crypto.ecc.Key.Key object
        """
        _key = self.public_key
        if self.getPublicKeyAlgorithm() == 'rsa':
            return Certificate._toRSAPublicKey(_key)
        elif self.getPublicKeyAlgorithm() == 'ec':
            return Certificate._toECKey(_key)
        assert False, 'Algorithm not supported'

    def isValid(self):
        """
        :return:
            True or an error
        """
        _now = datetime.datetime.now(util.UTC())
        _notBefore = self.getNotBefore()
        _notAfter = self.getNotAfter()
        if not _notBefore or _notBefore > _now:
            raise error.NotBeforeError()
        if not _notAfter or _notAfter < _now:
            raise error.NotAfterError()
        return True

    def verifySignature(self, issuer):
        """
        :return:
            True or an error
        """
        return verifySignature(self, issuer)


def verifySignature(certificate, issuer):
    """
    :return:
        True if signature is valid. Error otherwise
    """
    _algo = certificate.getSignatureAlgorithm()
    _sig = certificate.getSignature()
    if not _algo or not _sig:
        raise error.InvalidIssuerSignature()
    _msg = certificate['tbs_certificate'].dump()
    _key = issuer.getPublicKey()
    try:
        if not bool(verifycert(_algo, _msg, _sig, _key)):
            raise error.InvalidIssuerSignature()
    except VerificationError:
        raise error.InvalidIssuerSignature()
    return True


def loadCertificate(certFile, pem_fmt=False):
    if pem_fmt:
        return Certificate.fromPEMFile(certFile)
    else:
        return Certificate.fromDERFile(certFile)

