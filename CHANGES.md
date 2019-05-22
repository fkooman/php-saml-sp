# ChangeLog

## 0.2.0 (...)
- **API CHANGE**: use encoded random value as `RelayState` instead of the 
  "return to" URL to avoid creating a `RelayState` that exceeds 80 bytes which 
  is not allowed according to SAML specification and enforced by (some?) 
  Shibboleth IdPs
- create an attribute mapping from `urn:oid` attributes to "friendly" 
  names

## 0.1.1 (2019-04-23)
- add some additional documentation to the code
- make the code more robust
- use 256 bits random instead of 128

## 0.1.0 (2019-03-15)
- initial release
