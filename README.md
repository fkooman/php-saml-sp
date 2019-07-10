# Introduction

This library allows adding SAML Service Provider (SP) support to your PHP web
application and interface with SAML Identity Providers (IdPs).

**NOTE**: this library did NOT receive a security audit. Do **NOT** use it in
production until there is a 1.0 release!

# Why

I wanted to have a minimal implementation of a SAML SP library. Existing (PHP) 
software either has a much larger scope, or tries to conform fully to the SAML 
specification. This library only tries to implement the minimum amount to work 
with real world deployed IdPs, and be secure at all times.

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
- No dependency on `robrichards/xmlseclibs`
- Serializes `eduPersonTargetedID` as `idpEntityId!spEntityId!persistentId` 
  like Shibboleth;
- Verify "scope" of attributes based on `<shibmd:Scope>` metadata element iff
  metadata contains this element
- Validates XML schema(s) when processing XML protocol messages
- Tested with IdPs:
  - [simpleSAMLphp](https://simplesamlphp.org/)
  - [OpenConext](https://openconext.org/)
  - [FrkoIdP](https://github.com/fkooman/php-saml-idp/)
  - [AD FS](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services)
  - [Shibboleth IdP](https://www.shibboleth.net/products/identity-provider/)
- Currently ~1400 NCLOC

# Requirements

- PHP >= 5.4
- `php-openssl`
- See `composer.json` for other dependencies

# Crypto

This library only supports algorithms that are not currently broken and easy to
implement. There is no choice, only the below algorithms are supported.

## Signatures

- Digest: `http://www.w3.org/2001/04/xmlenc#sha256`
- Signature: `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`

# X.509

Use the following command to create a self-signed certificate for use with the
SP library.

    $ openssl req \
        -nodes \
        -subj "/CN=SAML SP" \
        -x509 \
        -sha256 \
        -newkey rsa:3072 \
        -keyout "sp.key" \
        -out "sp.crt" \
        -days 3650

# Example

An example is provided in the `example/` directory. In order run it:

    $ /path/to/composer install
    $ php -S localhost:8081 -t example

The example performs authentication and shows the attributes received from the 
IdP. It also supports logout at the IdP if supported by the IdP.

With your browser you can go to 
[http://localhost:8081/](http://localhost:8081/). The example will redirect 
immediately to the IdP. The metadata of the SP can be found at this URL: 
`http://localhost:8081/metadata`

# IdP Configuration

Make sure:

- the IdP signs the `saml:Assertion` and/or the `samlp:Response`;
- the IdP verifies the signature on the `samlp:AuthnRequest`;
- the IdP verifies the signature on the `samlp:LogoutRequest`;
- the IdP signs the `samlp:LogoutResponse`.

## simpleSAMLphp

In your simpleSAMLphp's `metadata/saml20-sp-remote.php` file, configure this 
for this SP library:

    'validate.authnrequest' => true,
    'sign.logout' => true,
    'validate.logout' => true,

# Tests

In order to run the tests:

    $ /path/to/composer install
    $ vendor/bin/phpunit

# Browser Session

You MUST secure your PHP cookie/session settings. See 
[this](https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions) 
resource.

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
* https://www.cs.auckland.ac.nz/~pgut001/pubs/xmlsec.txt
