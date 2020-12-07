# TODO

## 2.0

- implementing (SQLite?) caching for eduGAIN purpose with 2k+ IdPs
- validate schema of outgoing SAML messages (`AuthnRequest`, `LogoutRequest`, `Metadata`)?
- `ForceAuthn` in `AuthnRequest` (is anyone actually using this?)
- Implement a way to have multiple SP certificates
    - key rollover?
- add tests for `src/Web` and `src/Api` classes
- make IdpInfo also support multi-language display names so we can use those
  in the WAYF as well instead of just English (also requires a language 
  mapping function, i.e. if language is `en-US` we should prefer `en` and not
  `de` for instance
- expose requested attributes through SP metadata?
- remove PHP 5 support
    - only support PHP >= 7.2 (CentOS 8, Debian 10)
- Improve SLO?
    - Implement unsolicited `Response`, "IdP initiated"
    - Receive unsolicited `LogoutRequest` from IdPs
