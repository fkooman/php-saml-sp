# Introduction

This library allows adding SAML Service Provider (SP) support to your PHP web
application and interface with SAML Identity Providers (IdPs).

**NOTE**: this library did NOT receive a security audit. Do **NOT** use it in
production until there is a 1.0 release!

# Why

I wanted to have a minimal implementation of a SAML SP library with only 
_signature_ verification, no encryption. Exiting (PHP) software either has a 
much larger scope, or tries to conform fully to the SAML specification. This 
library only tries to implement the minimum amount to work with real world 
deployed IdPs and be secure at all times.

# Features

- Only SAML SP functionality
- Only HTTP-Redirect for sending `AuthnRequest`, `LogoutRequest` to IdP
- Only HTTP-Redirect binding for receiving `LogoutResponse` from IdP
- Only HTTP-POST binding for receiving `Response` from IdP
- Only supports RSA with SHA256 for signing/verifying signatures
- Always signs `AuthnRequest`
- Always signs `LogoutRequest`
- Supports signed `samlp:Response` and/or signed 
  `samlp:Response/saml:Assertion`
- Allow specifying `AuthnContextClassRef` as part of the `AuthnRequest`
- No dependency on `robrichards/xmlseclibs`
- Serializes `eduPersonTargetedId` as `idpEntityId!spEntityId!persistentId` 
  like Shibboleth;
- Validates XML schema(s) when processing XML protocol messages
- Tested with IdPs:
  - [simpleSAMLphp](https://simplesamlphp.org/)
  - [OpenConext](https://openconext.org/)
  - [FrkoIdP](https://github.com/fkooman/php-saml-idp/)
  - [AD FS](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services)
- Currently ~1000 NCLOC

# X.509

Use the following command to create a self-signed certificate for use with the
SP library.

    $ openssl req \
        -nodes \
        -subj "/CN=SAML SP" \
        -x509 \
        -sha256 \
        -newkey rsa:2048 \
        -keyout "sp.key" \
        -out "sp.crt" \
        -days 1800

# Example

Two examples are provided in the `example/` directory. In order test them:

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
- the IdP does NOT encrypt the `saml:Assertion`, i.e. it MUST NOT send a 
  `saml:EncryptedAssertion`;
- the IdP verifies the signature on the `samlp:AuthnRequest`;
- the IdP verifies the signature on the `samlp:LogoutRequest`;
- the IdP signs the `samlp:LogoutResponse`.

## simpleSAMLphp

In your simpleSAMLphp's `metadata/saml20-sp-remote.php` file, configure this 
for this SP library:

    'validate.authnrequest' => true,
    'saml20.sign.assertion' => true,
    'sign.logout' => true,
    'validate.logout' => true,

# Tests

In order to run the tests:

    $ /path/to/composer install
    $ vendor/bin/phpunit

# XML Schema Validation

Source of XSD files in `src/schema`:

    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd
    $ curl -O https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd
    $ curl -O https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/cs01/xsd/sstc-saml-metadata-ui-v1.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0.xsd

All occurrences of `schemaLocation` in the XSD files were modified to point to
the local files instead of the remote resources.

For the "sstc-saml-metadata-algsupport-v1.0" schema we needed to add this to
the schema file to make the validation work:

    <import namespace="urn:oasis:names:tc:SAML:2.0:metadata"
    schemaLocation="saml-schema-metadata-2.0.xsd"/>

We used "schema hardening" in `saml-schema-protocol-2.0.xsd` to enforce that 
there is at most one `saml:Assertion` in the `samlp:Response`.

# Browser Session

You MUST secure your PHP cookie/session settings. See 
[this](https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions) 
resource.

# Resources

* https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
* https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
* https://arxiv.org/pdf/1401.7483v1.pdf
* https://www.cs.auckland.ac.nz/~pgut001/pubs/xmlsec.txt
