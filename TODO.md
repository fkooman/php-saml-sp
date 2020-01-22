# TODO

## 0.3

- add tests for `src/Web` and `src/Api` classes
- only start session when needed, e.g. not for the metadata endpoint

## 1.0

- multi language support, `Tpl` is already there, so should be easy! We only
  need a language changer and a cookie for storing the language choice
- think about implementing caching for eduGAIN purpose with 2k+ IdPs
- input validation on ALL (public) methods
- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Validate schema of outgoing SAML messages (`AuthnRequest`, `LogoutRequest`, `Metadata`)?
- implement automatic metadata refresh (somehow) and verify it using its XML
  signature
- Expose `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?
- Implement a way to have multiple certificates
  - 1 for signing, 1 for encryption, 1 for signed metadata?
  - key rollover
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)

## 2.0

- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
- Improve SLO?
  - Implement unsolicited `Response`, "IdP initiated"
  - Receive unsolicited `LogoutRequest` from IdPs
