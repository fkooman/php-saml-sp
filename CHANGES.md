# ChangeLog

## 0.5.2 (2020-07-28)
- show warning on index page when `ext-sodium` is not available
- fix typo in warning for missing encryption support
- update translation
- update `fkooman/secookie`

## 0.5.1 (2020-07-22)
- add the `--force` flag to `php-saml-sp-update-metadata` to be able to force
  metadata retrieval no matter `cacheDuration` in the existing metadata
- make method `MetadataSource::importMetadata` private
- drop `paragonie/constant_time_encoding` dependency and instead use 
  `ext-sodium` functions for constant time encoding
- implement metadata `cacheDuration` support for dynamic metadata to check for 
  new metadata periodically (default is `PT6H`)
- `validUntil` is now only used to reject dynamic metadata, not for 
  determining when to refresh metadata
- follow metadata request redirects
- make sure response code for metadata downloads is `200` before processing
  metadata

## 0.5.0 (2020-07-17)
- implement auto metadata refresh with `metadataList` configuration option 
  specifying the URL and certificate(s) to validate it (issue #8)
- support validating XML metadata signature
- only validate XML schema when importing it, not every time when using it
- metadata files in config/metadata are always trusted (no schema check, no 
  signature validation)
- (**SECURITY**) make sure IdP is allowed to authenticate, previously it was 
  possible to authenticate with an IdP in the metadata, but not explicitly 
  listed under `idpList`
- make it possible to accept _all_ IdPs from metadata without explicitly 
  allowing them by not setting the `idpList` configuration option. An 
  `idpList` with no items, i.e. empty array, does allow NO IdPs
- implement rudimentary logging to _syslog_
- add script to verify metadata XML schema and signature 
  (`php-saml-sp-validate-metadata`)
- ignore non-RSA keys in IdP metadata
- much more helpful error messages in case something is missing/going wrong 
  when parsing XML documents (issue #7)
- major rewrite of XML document handling, no longer expose `DOMDocument` and 
  `DOMXPath`, introduce more helper methods with strict type checks
- remove all XML XPath "evaluate" queries
- make XML signature validation / decryption more robust
- add new line when fetching SP metadata (issue #2)
- better check for empty strings by first calling `trim()` on the string value
- lots of fixes with the help of `vimeo/psalm`, `phpstan/phpstan` and 
  `phan/phan`

## 0.4.2 (2020-07-06)
- support validating ADFS metadata (ws-federation)

## 0.4.1 (2020-06-29)
- implement `<samlp:Scoping>` for `<samlp:AuthnRequest>` to tell a SAML proxy
  which IdP behind the proxy should be used for authentication, thus skipping 
  the WAYF
- support eduMember `isMemberOf` attribute

## 0.4.0 (2020-05-25)
- use `/login` endpoint instead of `/wayf` (issue #4)
- support `ReturnTo` as a query parameter on `/login` (issue #5)
- support `AuthnContextClassRef` as a query parameter on `/login`
- support `IdP` as a query parameter on `/login`
- add (optional) `AuthOptions` parameter to the `SamlAuth` methods for getting
  and verifying the assertion instead of having to do this manually

## 0.3.3 (2020-05-23)
- update `nl-NL` translation files

## 0.3.2 (2020-05-23)
- implement JS search for WAYF (only if browser has JS enabled)
- update bootstrap-reboot CSS
- cleanup language handling / template

## 0.3.1 (2020-02-23)
- use `autofocus` element on the previously selected IdP in the WAYF, so enter
  can be used to continue to that IdP immediately
- translate language code to human readable language for display in UI

## 0.3.0 (2020-02-12)
- small API update for `XmlIdpInfoSource` now taking array in contructor to
  allow specifying multiple metadata files 
- initial support for "Web", i.e. run fkooman/saml-sp as an app on your server
  next to the application(s) you want to use SAML authentication with
- support `<EncryptedAssertion>` with AES-256-GCM on PHP >= 7.1
- update (C)
- source formatting
- `IdpInfo` supports "DisplayName"
- `SpInfo` supports "DisplayName"
- `SpInfo` can now enforce `<EncryptedAssertion>` from IdP(s)
- SP Metadata now exposes "DisplayName" and supported encryption algorithms

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
