# Introduction

This library allows adding SAML Service Provider (SP) support to your PHP web
application.

**NOTE**: because this library contains its own minimal implemention of 
"XML Signature Verification" it **really** requires an audit before it can be 
used in production! See [Resources](#resources).

# Why

- simpleSAMLphp is the "swiss army knife", we want only SAML 2.0, and only SP 
  functionality and no extensive list of features/dependencies;
- we want to support "at runtime" `AuthnContext` switches, i.e. upgrade to a
  higher LoA with MFA;
- mod_auth_mellon depends on Apache;
- small code base, no dependencies, easy to audit;

# Features

- Only SAML SP functionality
- Only HTTP-Redirect binding for sending `AuthnRequest` to IdP
- Only HTTP-POST binding for receiving `Assertion` from IdP
- Only supports RSA with SHA256 for verifying signatures
- Supports signed `samlp:Response` and/or signed `saml:Assertion`
- Allow specifying `AuthnContextClassRef` and `ForceAuthn` as part of 
  Authentication Request
- Validates XML schema(s)
- Tested with IdPs:
  - simpleSAMLphp
  - OpenConext
  - FrkoIdP
- Currently ~900 NCLOC

# X.509

    $ openssl req \
        -nodes \
        -subj "/CN=SAML SP" \
        -x509 \
        -sha256 \
        -newkey rsa:3072 \
        -keyout "sp.key" \
        -out "sp.crt" \
        -days 3600

# TODO 
 
- verify response status code
- add mdui/contact/etc to metadata
- Better Exceptions / Error handling
- also write unit tests for `handleResponse()` and `handleLogout()`
- add `<SessionIndex>` to `LogoutRequest`
- make sure `RelayState` returned is the exact value we sent?

# Nice To Have

- handle `NameID` value for `eduPersonTargetedId` properly (?)
- SLO (respond to unsolicited LogoutRequest from IdPs)
- support encrypted Assertions (saml2int)
  - rsa-oaep-mgf1p
  - aes-256-gcm

# simpleSAMLphp as IdP

In `metadata/saml20-sp-remote.php` for the SP:

    'validate.authnrequest' => true,
    'saml20.sign.assertion' => true,
    'sign.logout' => true,
    'validate.logout' => true,

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
* https://www.cs.auckland.ac.nz/~pgut001/pubs/xmlsec.txt
