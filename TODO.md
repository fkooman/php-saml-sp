# TODO

## 0.5

- make sure the transforms are exactly as we expect them to be

```
<ds:Transforms>
    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
```

- expose requested attributes through SP metadata
- make IdpInfo also support multi-language display names so we can use those
  in the WAYF as well instead of just English (also requires a language 
  mapping function, i.e. if language is `en-US` we should prefer `en` and not
  `de` for instance
- add tests for `src/Web` and `src/Api` classes
- include DomNode/Element in error message so we know where the problem is in
  the XML
- think about implementing caching for eduGAIN purpose with 2k+ IdPs

## 1.0

- input validation on ALL (public) methods
- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Validate schema of outgoing SAML messages (`AuthnRequest`, `LogoutRequest`, `Metadata`)?
- implement automatic metadata refresh (somehow) and verify it using its XML
  signature
- Expose `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?
- Implement a way to have multiple certificates
  - key rollover?
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- support verifying SAML metadata from ADFS servers?

## 2.0

- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
- Improve SLO?
  - Implement unsolicited `Response`, "IdP initiated"
  - Receive unsolicited `LogoutRequest` from IdPs
