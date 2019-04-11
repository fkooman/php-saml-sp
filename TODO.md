# TODO
 
## 1.0

### Open Issues

- make absolutely sure we verify the assertion with the right public key as to
  avoid allowing one IdP to pretend to be another IdP
- Do we also need to check `/samlp:Response/saml:Assertion/saml:Conditions/@NotOnOrAfter`?
- Validate schema of outgoing SAML messages (`AuthnRequest`, `LogoutRequest`, `Metadata`)?
- Validate `RelayState` on return from IdP?
- check `xenc:EncryptedKey` `@Recipient`?
- if we receive attributes not in the `urn:oid` format we don't apply any 
  processing to them, e.g. for the `eduPersonTargetedID` et al.

## 1.1

- implement SHA-256 digest for OAEP in PHP, see `oaep` branch
- Expose `AuthenticatingAuthority` as well, next to `AuthnContextClassRef`?
- Implement a way to have multiple certificates
  - 1 for signing, 1 for encryption, 1 for signed metadata?
  - key rollover
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)

# 2.0

- remove PHP 5 support
  - only support PHP >= 7.2 (CentOS 8, Debian 10)
  - remove libsodium (no longer needed as PHP >= 7.1 supports AES-256-GCM as 
    well see `php71` branch
- Improve SLO?
  - Implement unsolicited `Response`, "IdP initiated"
  - Receive unsolicited `LogoutRequest` from IdPs
