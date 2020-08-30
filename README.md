**Summary**: Secure SAML Service Provider

**Description**: Secure SAML Service Provider with a focus on saml2int 
compatibility and easy integration in PHP applications.

**License**: MIT

# Introduction

A SAML Service Provider (SP) with an easy API to use SAML authentication from
your existing PHP applications.

**NOTE**: this project did NOT receive a comprehensive security audit yet!

**NOTE**: do NOT use it in production until there is a 1.0 release!

# Why

There are various options for integrating SAML in your PHP application. 
However, most are either (very) complicated, include too many (useless) 
features, have hard requirements on [Apache](https://httpd.apache.org/) and are 
not easy to package for server operating systems like CentOS/Fedora and/or 
Debian.

We only need SAML SP support, so there is no need to include any IdP features, 
or other (obsolete) authentication protocols.

In addition, we only implement what is actually used "in the field" *and* that 
which is secure. So you won't find SHA1 support or insecure encryption.

# Features

- Only SAML SP functionality
- Only HTTP-Redirect for sending `AuthnRequest`, `LogoutRequest` to IdP
- Only HTTP-Redirect binding for receiving `LogoutResponse` from IdP
- Only HTTP-POST binding for receiving `Response` from IdP
- Always signs `AuthnRequest`
- Always signs `LogoutRequest`
- Supports signed `samlp:Response` and/or signed 
  `samlp:Response/saml:Assertion`
- Supports multiple IdP certificates for key rollover
- Allow specifying `AuthnContextClassRef` as part of the `AuthnRequest`
- Serializes `eduPersonTargetedID` as `idpEntityId!spEntityId!persistentId` 
  (like Shibboleth);
- Only supports `urn:oid` SAML attributes from a list of allowed attributes, 
  ignores the rest
- Verify "scope" of attributes based on `<shibmd:Scope>` metadata element when
  the IdP metadata contains this element
    - Silently removes the attribute (value) when scope does not match
- Converts `urn:oid` attribute names to "friendly" names for use by 
  applications
- Supports automated metadata retrieval/update with XML schema / signature 
  verification, see [METADATA](METADATA.md)
- Validates XML schema(s) when processing XML protocol messages
- Tested with IdPs:
    - [simpleSAMLphp](https://simplesamlphp.org/)
    - [OpenConext](https://openconext.org/)
    - [FrkoIdP](https://github.com/fkooman/php-saml-idp/)
    - [AD FS](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services)
    - [Shibboleth IdP](https://www.shibboleth.net/products/identity-provider/)
- Simple built-in WAYF when more than 1 IdP is configured for the SP
- Support external discovery services implementing 
  [Identity Provider Discovery Service Protocol and Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.html)
- Currently ~3500 SLOC

## SAML V2.0 Deployment Profile for Federation Interoperability 

We _do_ aim to eventually support everything as mentioned in 
[SAML V2.0 Deployment Profile for Federation Interoperability](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

### Cryptographic Algorithms

| Type                 | Algorithm(s)                                          | Supported | 
| -------------------- | ----------------------------------------------------- | --------- |
| Digest               | `http://www.w3.org/2001/04/xmlenc#sha256`             | Yes       |
| Signature            | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`   | Yes       |
|                      | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` | No        |
| Block Encryption     | `http://www.w3.org/2009/xmlenc11#aes128-gcm`          | Yes       |
|                      | `http://www.w3.org/2009/xmlenc11#aes256-gcm`          | Yes       |
| Key Transport        | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`     | Yes       |
| Key Transport Digest | `http://www.w3.org/2000/09/xmldsig#sha1`              | Yes       |

# Requirements

- PHP >= 5.4
    - For encryption (`<EncryptedAssertion>`) support, PHP >= 7.1
- `php-openssl`
- See `composer.json` for additional dependencies

# Installation

See [INSTALL](INSTALL.md) for manual installation.

In the near future we'll provide supported CentOS/Fedora and Debian/Ubuntu 
packages.

Currently we have CentOS/Fedora packages in 
[COPR](https://copr.fedorainfracloud.org/coprs/fkooman/php-saml-sp/).

# Source Code Layout

The `src/` directory contains the SAML SP implementation library. The directory
`src/Web` contains everything related to the built-in web interface providing 
the landing page and WAYF. The `src/Api` directory contains everything related
to the API to use from your PHP application.

# Development

Run [composer](https://getcomposer.org/) to install the dependencies:

    $ /path/to/composer install

Use the following command to create self-signed certificates for use with the
SP library. It will be used for signing the `<AuthnRequest>` and 
`<LogoutRequest>`. Another set will be used for decryption of 
`<EncryptedAssertion>`.

    $ cd keys
    $ ./generate_keys.sh

Now copy the configuration template:

    $ cp config/config.php.example config/config.php

Disable the `Secure` session cookie parameter by setting the `secureCookie` key 
to `false` in `config/config.php`.

A neat IdP to use for testing is 
`https://x509idp.moonshot.utr.surfcloud.nl/metadata`. There's no need to register
your SP with that IdP. Put the metadata in `config/metadata`:

    $ mkdir config/metadata
    $ curl -L -o config/metadata/x509idp.moonshot.utr.surfcloud.nl.xml https://x509idp.moonshot.utr.surfcloud.nl/metadata

Run the application using PHP's built-in web server:

    $ php -S localhost:8082 -t web

With your browser you can go to 
[http://localhost:8082/](http://localhost:8082) and take it from there!

# IdP Configuration

In case you want to add / configure your IdP to use with this software, make 
sure:

- the IdP uses the HTTP-Redirect binding for receiving the `AuthnRequest`;
- the IdP uses the HTTP-POST binding to provide the `samlp:Response` to the SP;
- the IdP signs the `saml:Assertion` and/or the `samlp:Response`;
- the IdP (optionally) encrypts the `saml:Assertion`;
- the IdP verifies the signature on the `samlp:AuthnRequest`;
- the IdP verifies the signature on the `samlp:LogoutRequest`;
- the IdP signs the `samlp:LogoutResponse`.

Some of these requirements are also exposed through the SP metadata.

## simpleSAMLphp

In your simpleSAMLphp's `metadata/saml20-sp-remote.php` file, configure this 
for this SP:

    'validate.authnrequest' => true,
    'sign.logout' => true,
    'validate.logout' => true,

# API 

You can integrate your application using the `SamlAuth()` class. See the 
`example/` directory for a working example.

# Tests

In order to run the included test suite:

    $ vendor/bin/phpunit

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
* https://www.cs.auckland.ac.nz/~pgut001/pubs/xmlsec.txt
