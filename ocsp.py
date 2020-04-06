#!/usr/bin/python
#
# Functions for x843 encoded objects
#
# @author Brian Hession
# @email hessionb@gmail.com
#

from __future__ import print_function
import cert, datetime, error, sys, urllib, urllib2, util
from base64 import b64encode
from asn1crypto import core, algos, ocsp, x509
from verify import verify as verifyocsp
from crypto.rsa import VerificationError
from env import *


class OCSPRequest(ocsp.OCSPRequest):

    @staticmethod
    def fromBitString(req):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return OCSPRequest().load(req)

    @staticmethod
    def fromPEMFile(reqFile):
        return OCSPRequest.fromBitString(util.fromPEMFile(reqFile))

    @staticmethod
    def fromDERFile(reqFile):
        return OCSPRequest.fromBitString(util.fromDERFile(reqFile))

    def toBitString(self):
        return self.dump()

    def writeDERFile(self, file=sys.stdout):
        util.encodeDERFile(self.toBitString(), file=file)

    def writePEMFile(self, file=sys.stdout):
        util.encodePEMFile(self.toBitString(), file=file,
                header='-----BEGIN OCSP REQUEST-----',
                footer='-----END OCSP REQUEST-----')

    def getRequests(self):
        """
        :return:
            The requests in the format:
                (issuer_name_hash, issuer_key_hash, serial_number)
        """
        requests = list()
        for req in self['tbs_request']['request_list']:
            _nameHash = req['req_cert']['issuer_name_hash'].native
            _keyHash = req['req_cert']['issuer_key_hash'].native
            _serial = req['req_cert']['serial_number'].native
            requests.append((_nameHash, _keyHash, _serial))
        return requests

    def getNonce(self):
        """
        :return:
            The nonce bitstring
        """
        if self.nonce_value:
            return self.nonce_value.native
        return None

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('OCSPRequest', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        print('{}Requests'.format(prefix), file=file)
        for req in self.getRequests():
            print('{}{}Issuer Name Hash:'.format(prefix, padding), req[0].encode('hex'), file=file)
            print('{}{}Issuer Key Hash:'.format(prefix, padding), req[1].encode('hex'), file=file)
            print('{}{}Serial Number: {:X}'.format(prefix, padding, req[2]), file=file)
            print('{}{}--'.format(prefix, padding), file=file)
        if self.getNonce():
            print('{}Nonce:'.format(prefix), self.getNonce().encode('hex'), file=file)


class OCSPRequestBuilder:
    "Structure for building an ASN.1 OCSPRequest object"

    def __init__(self):
        self.requestList = ocsp.Requests()
        self.requestExtns = None
        self.nonce = None

    def addRequest(self, cacert, serial):
        hashAlgo = algos.DigestAlgorithm()
        hashAlgo['algorithm'] = algos.DigestAlgorithmId(u'sha1')
        certId = ocsp.CertId()
        certId['hash_algorithm'] = hashAlgo
        certId['issuer_name_hash'] = cacert.getNameSha1()
        certId['issuer_key_hash'] = cacert.getKeySha1()
        certId['serial_number'] = core.Integer(serial)
        req = ocsp.Request()
        req['req_cert'] = certId
        self.requestList[len(self.requestList)] = req

    def generateNonce(self):
        if not self.requestExtns:
            self.requestExtns = ocsp.TBSRequestExtensions()
        if not self.nonce:
            self.nonce = util.generateNonceSecure(20)
            extn = ocsp.TBSRequestExtension()
            extn['extn_id'] = ocsp.TBSRequestExtensionId(u'nonce')
            extn['critical'] = True
            extn['extn_value'] = self.nonce
            self.requestExtns[len(self.requestExtns)] = extn
        return self.nonce

    def build(self):
        assert len(self.requestList) > 0, 'Must provide at least 1 request'
        tbsReq = ocsp.TBSRequest()
        tbsReq['request_list'] = self.requestList
        if self.requestExtns:
            tbsReq['request_extensions'] = self.requestExtns
        ocspReq = OCSPRequest()
        ocspReq['tbs_request'] = tbsReq
        return ocspReq


class Response(ocsp.SingleResponse):
    "Structure defining an ASN.1 OCSP `SingleResponse`"

    @staticmethod
    def fromBitString(res):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return Response().load(res)

    @staticmethod
    def fromPEMFile(resFile):
        assert False, 'This object cannot be read from PEM format'

    @staticmethod
    def fromDERFile(resFile):
        return Response.fromBitString(util.fromDERFile(resFile))

    def toBitString(self):
        return self.dump()

    def writeDERFile(self, file=sys.stdout):
        util.encodeDERFile(self.toBitString(), file=file)

    def writePEMFile(self, file=sys.stdout):
        assert False, 'This object cannot be written in PEM format'

    def getCertId(self):
        """
        :return:
            The CertId in the format:
                (issuer_name_hash, issuer_key_hash, serial_number)
        """
        certId = list()
        _nameHash = self['cert_id']['issuer_name_hash'].native
        _keyHash = self['cert_id']['issuer_key_hash'].native
        _serial = self['cert_id']['serial_number'].native
        return (_nameHash, _keyHash, _serial)

    def getCertStatus(self):
        """
        :return:
            good, revoked, or unknown
        """
        _status = self['cert_status'].chosen
        if isinstance(_status, ocsp.RevokedInfo):
            return 'revoked'
        return self['cert_status'].chosen.native

    def getRevokedInfo(self):
        """
        :return:
            None or the Revoked Info in the format:
                (DateTime of revocation, reason)
        """
        _status = self['cert_status'].chosen
        if not isinstance(_status, ocsp.RevokedInfo):
            return None
        _time = _status['revocation_time'].native
        _reason = _status['revocation_reason']
        if _reason.native:
            _reason = _reason.human_friendly
        else:
            _reason = None
        return (_time, _reason)

    def getThisUpdate(self):
        """
        :return:
            DateTime of the This Update time
        """
        return self['this_update'].native

    def getNextUpdate(self):
        """
        :return:
            DateTime of the Next Update time
        """
        return self['next_update'].native

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
        status = self.getCertStatus()
        if not status or status == 'unknown':
            raise error.UnknownStatusError()
        if status == 'revoked':
            raise error.RevokedStatusError(self.getRevokedInfo()[1])
        return True

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('OCSPSingleResponse', self, space=space, file=file)

    def printCLI(self, prefix='', space=4, file=sys.stdout):
        padding = ' '*space
        certId = self.getCertId()
        print('{}{}Issuer Name Hash:'.format(prefix, padding), certId[0].encode('hex'), file=file)
        print('{}{}Issuer Key Hash:'.format(prefix, padding), certId[1].encode('hex'), file=file)
        print('{}{}Serial Number: {:X}'.format(prefix, padding, certId[2]), file=file)
        print('{}{}Cert Status:'.format(prefix, padding), self.getCertStatus(), file=file)
        revokedInfo = self.getRevokedInfo()
        if revokedInfo:
            print('{}{}Revoked Info:'.format(prefix, padding), revokedInfo[0], '-', revokedInfo[1], file=file)
        print('{}{}This Update:'.format(prefix, padding), self.getThisUpdate(), file=file)
        print('{}{}Next Update:'.format(prefix, padding), self.getNextUpdate(), file=file)
        try:
            self.isValid()
            print('{}{}Valid: True'.format(prefix, padding), file=file)
        except error.Error as e:
            print('{}{}Valid:'.format(prefix, padding), str(e), file=file)
        print('{}{}--'.format(prefix, padding), file=file)


class OCSPResponse(ocsp.OCSPResponse):
    "Structure defining an ASN.1 OCSPResponse object"

    @staticmethod
    def fromBitString(res):
        "Converts the ASN.1 encoded bitstring into and ASN.1 object"
        return OCSPResponse().load(res)

    @staticmethod
    def fromPEMFile(resFile):
        return OCSPResponse.fromBitString(util.fromPEMFile(resFile))

    @staticmethod
    def fromDERFile(resFile):
        return OCSPResponse.fromBitString(util.fromDERFile(resFile))

    def toBitString(self):
        return self.dump()

    def writeDERFile(self, file=sys.stdout):
        util.encodeDERFile(self.toBitString(), file=file)

    def writePEMFile(self, file=sys.stdout):
        util.encodePEMFile(self.toBitString(), file=file,
                header='-----BEGIN OCSP RESPONSE-----',
                footer='-----END OCSP RESPONSE-----')

    def getStatus(self):
        """
        :return:
            'successful'
            'malformed_request'
            'internal_error'
            'try_later'
            'sign_required'
            'unauthorized'
        """
        return self['response_status'].native.encode('utf8')

    def getResponderId(self):
        """
        :return:
            String of the Responder ID
        """
        _choice = self.response_data['responder_id'].chosen
        if isinstance(_choice, x509.Name):
            return ', '.join(['{}={}'.format(a, b) for a, b in cert.parseNameObject(_choice)])
        else:
            return _choice.native.encode('hex')

    def getProducedAt(self):
        """
        :return:
            DateTime of the Produced At time
        """
        return self.response_data['produced_at'].native

    def getNonce(self):
        """
        :return:
            BitString of the nonce
        """
        if self.nonce_value:
            return self.nonce_value.native
        return None

    def getResponses(self):
        """
        :return:
            A list of Response()
        """
        responses = list()
        for res in self.response_data['responses']:
            responses.append(Response.load(res.dump()))
        return responses

    def getSigningCertificate(self):
        """
        :return:
            None or a List containing the OCSP Signing certificate chain
        """
        ret = list()
        _certchain = self.basic_ocsp_response['certs']
        if not _certchain:
            return None
        for c in _certchain:
            ret.append(cert.Certificate().load(c.dump()))
        if len(ret) == 0:
            return None
        return ret

    def getSignatureAlgorithm(self):
        """
        :return:
            None or a string of the signature algorithm
        """
        _signedDigestAlgo = self.basic_ocsp_response['signature_algorithm']
        if not _signedDigestAlgo:
            return None
        _sigOid = _signedDigestAlgo['algorithm']
        if not _sigOid:
            return None
        return _sigOid.map(_sigOid.dotted).encode('utf8')

    def getSignature(self):
        """
        :return:
            None or a BitString of the signature
        """
        _signature = self.basic_ocsp_response['signature']
        if not _signature:
            return None
        return _signature.native

    def isValid(self, filter=None):
        """
        :return:
            True or an error
        """
        for res in self.getResponses():
            certId = res.getCertId()
            if not filter or certId in filter:
                res.isValid()
        self.verifySignature()
        return True

    def verifySignature(self):
        """
        :return:
            None or the signing certificate
        """
        return verifySignature(self)

    def prettify(self, space=4, file=sys.stdout):
        util.prettify('OCSPResponse', self, space=space, file=file)

    def printCLI(self, filter=None, prefix='', space=4, file=sys.stdout, issuer=None):
        """
        filter
            list if certIDs: (issuer_name_hash, issuer_key_hash, serial)
        space
            indent space size (default: 4)
        file
            file to print to (default: stdout)
        """
        padding = ' '*space
        status = self.getStatus()
        print('{}Response Status:'.format(prefix), status, file=file)
        if status == 'successful':
            print('{}Responder ID:'.format(prefix), self.getResponderId(), file=file)
            print('{}Responses'.format(prefix), file=file)
            for res in self.getResponses():
                certId = res.getCertId()
                if not filter or certId in filter: res.printCLI(prefix=prefix, space=space, file=file)
            if self.getNonce():
                print('{}Nonce:'.format(prefix), self.getNonce().encode('hex'), file=file)

            # Signature
            print('{}Signature Algorithm:'.format(prefix), self.getSignatureAlgorithm(), file=file)
            try:
                signer = self.verifySignature()
                print('{}Signature Verify:'.format(prefix), bool(signer), '-', signer.getSubject(), file=file)
            except error.InvalidOCSPSignature as e:
                print('{}Signature Verify:'.format(prefix), str(e), file=file)

            # Signing certificate
            _certificates = self.getSigningCertificate()
            if not _certificates:
                return
            print('{}OCSP-Signing Certificate Chain'.format(prefix), file=file)
            for c in _certificates:
                print('{}{}Issuer:'.format(prefix, padding), c.getIssuer(), file=file)
                print('{}{}Subject:'.format(prefix, padding), c.getSubject(), file=file)
                print('{}{}Not Before:'.format(prefix, padding), c.getNotBefore(), file=file)
                print('{}{}Not After:'.format(prefix, padding), c.getNotAfter(), file=file)
                try:
                    c.isValid()
                    print('{}{}Valid: True'.format(prefix, padding), file=file)
                except error.Error as e:
                    print('{}{}Valid:'.format(prefix, padding), str(e), file=file)
                if issuer:
                    try:
                        c.verifySignature(issuer)
                        print('{}{}Signature Verify: True'.format(prefix, padding), file=file)
                    except error.InvalidIssuerSignature as e:
                        print('{}{}Signature Verify: False -'.format(prefix, padding), str(e), file=file)
                print('{}{}--'.format(prefix, padding), file=file)


def buildOCSPRequest(*reqs, **kwargs):
    """
    reqs
        (cert, serial), ...
    kwargs
        'nonce'
            True to generate a nonce
    :return:
        OCSPRequest object
    """
    ocspBuilder = OCSPRequestBuilder()
    for c, serial in reqs:
        ocspBuilder.addRequest(c, int(serial))
    if 'nonce' in kwargs and kwargs['nonce']:
        ocspBuilder.generateNonce()
    return ocspBuilder.build()


def ocspPostRequest(url, ocspReq, timeout=1):
    if url[-1] == '/': url = url[:-1]
    data = ocspReq
    if isinstance(ocspReq, OCSPRequest):
        data = ocspReq.toBitString()
    headers = {
        'Content-Type' : 'application/ocsp-request',
        'Accept' : 'application/ocsp-response',
        'User-Agent' : USER_AGENT
    }
    req = urllib2.Request(url, data=data, headers=headers)
    res = urllib2.urlopen(req, timeout=timeout)
    if res:
        return OCSPResponse.fromBitString(res.read())
    return None


def ocspGetRequest(url, ocspReq, timeout=1):
    if url[-1] == '/': url = url[:-1]
    data = ocspReq
    if isinstance(ocspReq, OCSPRequest):
        data = ocspReq.toBitString()
    headers = {
        'Accept' : 'application/ocsp-response',
        'User-Agent' : USER_AGENT
    }
    encoded = urllib.quote_plus(b64encode(data))
    req = urllib2.Request('{}/{}'.format(url, encoded), headers=headers)
    res = urllib2.urlopen(req, timeout=timeout)
    if res:
        return OCSPResponse.fromBitString(res.read())
    return None


def verifySignature(ocspRes):
    """
    :return:
        The signing certificate or an error
    """
    _algo = ocspRes.getSignatureAlgorithm()
    _sig = ocspRes.getSignature()
    if not _algo or not _sig:
        raise error.InvalidOCSPSignature()
    _msg = ocspRes.basic_ocsp_response['tbs_response_data'].dump()
    _certificates = ocspRes.getSigningCertificate()
    if not _certificates:
        raise error.InvalidOCSPSignature()
    for c in _certificates:
        _key = c.getPublicKey()
        try:
            if bool(verifyocsp(_algo, _msg, _sig, _key)):
                return c
        except VerificationError:
            pass
    raise error.InvalidOCSPSignature()

