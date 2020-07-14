# TODO

## Before 1.0

### Features

- include DomNode/Element in error message so we know where the problem is in
  the XML
- implement automatic metadata refresh and verify it using its XML
  signature
  - mostly done now, only need to consider `validUntil` or "caching" info in 
    metadata on *when* to refresh exactly instead of forcing it every hour...

### Fixes / Security Audit

- input validation on ALL (public) methods
- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- do we need to make sure the transforms are exactly as we expect them to be 
  [1]?

## After 1.0

- some IdPs also rollover the metadata signing keys (ADFS) it seems, so we have
  to extract any new certificates found in the metadata and put them in the 
  "trust store" as well
- implementing caching for eduGAIN purpose with 2k+ IdPs
- validate schema of outgoing SAML messages (`AuthnRequest`, `LogoutRequest`, `Metadata`)?
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- Implement a way to have multiple SP certificates
  - key rollover?
- add tests for `src/Web` and `src/Api` classes
- make IdpInfo also support multi-language display names so we can use those
  in the WAYF as well instead of just English (also requires a language 
  mapping function, i.e. if language is `en-US` we should prefer `en` and not
  `de` for instance
- expose requested attributes through SP metadata
- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
- Improve SLO?
  - Implement unsolicited `Response`, "IdP initiated"
  - Receive unsolicited `LogoutRequest` from IdPs

## Notes

```
<ds:Transforms>
    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
```
