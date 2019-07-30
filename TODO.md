# TODO

## 0.2

- make sure all session keys are deleted after they are no longer needed
- figure out how long the user is allowed to be authenticated, store this in
  the assertion and verify this time is not yet expired when calling 
  `SP::getAssertion()` and `SP::hasAssertion()`
 
## 1.0

- input validation on ALL (public) methods
- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Validate schema of outgoing SAML messages (`AuthnRequest`, `LogoutRequest`, `Metadata`)?

## 2.0

- implement automatic metadata refresh (somehow) and verify it using its XML
  signature
- allow IdP-first login
- Expose `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?
- Implement a way to have multiple certificates
  - 1 for signing, 1 for encryption, 1 for signed metadata?
  - key rollover
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
- Improve SLO?
  - Implement unsolicited `Response`, "IdP initiated"
  - Receive unsolicited `LogoutRequest` from IdPs
