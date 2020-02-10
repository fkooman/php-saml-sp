# ChangeLog

## 0.3.0 (...)
- small API update for `XmlIdpInfoSource` now taking array in contructor to
  allow specifying multiple metdata files 
- initial support for "Web", i.e. run fkooman/saml-sp as an app on your server
  next to the application(s) you want to use SAML authentication with
- support `<EncryptedAssertion>` with AES-256-GCM

## 0.2.2 (2019-08-06)
- do not throw error when attribute `saml:AuthnStatement/@SessionNotOnOrAfter`
  is missing, it is optional

## 0.2.1 (2019-08-05)
- more robust handling of QueryParameters

## 0.2.0 (2019-07-31)
- use encoded random value as `RelayState` instead of the `ReturnTo` URL to 
  avoid creating a `RelayState` that exceeds 80 bytes which is not allowed 
  according to SAML specification and enforced by (some?) Shibboleth IdPs
- break API where SP consumers have to use the return values of `SP::login`, 
  `SP::logout`, `SP::handleResponse` and `SP::handleLogoutResponse` instead of 
  using `RelayState` as the "return to" URL
- implement `SP::hasAssertion()` that returns `bool`, `SP::getAssertion()` will
  always return `Assertion` or throw an `SPException`
- create an attribute mapping from `urn:oid` attributes to "friendly" 
  names so applications can use the friendly name instead of only the `urn:oid` 
  variant
- verify "Subject Identifier Attributes" and `schacHomeOrganization` scopes as 
  well
- cleanup session variable handling, store objects in the session instead of 
  a bunch of variables
- only support "known" attributes in their `urn:oid` variant, ignore the rest
- remove all encryption support, better no encryption than insecure encryption

## 0.1.1 (2019-04-23)
- add some additional documentation to the code
- make the code more robust
- use 256 bits random instead of 128

## 0.1.0 (2019-03-15)
- initial release
