# php timestamping authority
## Description
TSA (Timestamp authority) RFC3161 server with pure php.<br />
<br />
### Tested with:
* Adobe reader
* OpenSSL
* JSignPdf
* Xolido Sign
* signtool (work with /t and /tr option)
* Sign GUI
* pdf sign and seal

## Requirements
php 5+ with openssl

## Installation
Just copy to html directory.
set client request to your address with slash at end (optional, depend on your web server configuration)
eg: http://localhost/PHP-Timestamp-Authority-Server/

## Configurations
configuration setting are in tsa.cfg file.

```cfg
signercert = <filename> #pem format (cert and pkey) of tsa signer certificate filename. Put in ./certs directory.
hashalgorithm  = <alg> #tsa signature hash algorithm (md2, md4, md5, sha1, sha256, sha384, sha512, ripemd160 etc)
policy = <oid> #tsa policy in oid number.
```
mysql database not yet implemented.
