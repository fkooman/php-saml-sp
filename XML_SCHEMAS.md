# XML Schema Validation

Source of XSD files in `src/schema`:

    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd
    $ curl -O https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd
    $ curl -O https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/cs01/xsd/sstc-saml-metadata-ui-v1.0.xsd
    $ curl -O https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0.xsd
    $ curl -O https://www.w3.org/2001/03/xml.xsd
    $ curl -O https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/schema/saml-subject-id-attr-v1.0.xsd

    $ curl -O https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation.xsd
    $ curl -O https://docs.oasis-open.org/wsfed/authorization/v1.2/os/ws-authorization.xsd
    $ curl -O https://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2.xsd
    $ curl -O https://www.w3.org/2006/03/addressing/ws-addr.xsd
    $ curl -O https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd
    $ curl -O https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd
    $ curl -O https://schemas.xmlsoap.org/ws/2004/09/mex/MetadataExchange.xsd

All occurrences of `schemaLocation` in the XSD files were modified to point to
the local files instead of the remote resources.

For the `sstc-saml-metadata-algsupport-v1.0.xsd` and 
`saml-subject-id-attr-v1.0.xsd` schema we needed to add this to the schema file 
to make the validation work:

    <import namespace="urn:oasis:names:tc:SAML:2.0:metadata"
    schemaLocation="saml-schema-metadata-2.0.xsd"/>

We used "schema hardening" in `saml-schema-protocol-2.0.xsd` to enforce that 
there is at most one `saml:Assertion` or `saml:EncryptedAssertion` in the 
`samlp:Response`.
