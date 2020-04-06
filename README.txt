# Python PKI Library

A Python library for PKI stuff. Currently focused on X.509 and X.843 (OCSP).

## Included

Included is asn1crypto, ecc, and rsa Python libraries.

## Known Bugs

* Does not verify which site the HID VA response comes from. The Responder ID 
  is a hash. To differentiate the origin site, one has to look at the signing 
  certificate instead.
* Elliptic Curve (EC) functionality fails. This is either an issue with 
  parsing the key from the ASN.1 object or the current implementation of EC 
  verification is incorrect. I'm inclined to the latter--perhaps the p-values 
  implemented by NSA is non-standard (unlikely)?
* Some CAs fail to load when saved in PEM format. The reason is still 
  unknown.

## License

Copyright 2020 Brian Hession

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
