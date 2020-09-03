# API

**NOTE**: in the future, part of this file will be replaced with automatically
generated API documentation directly from the source code...

You can integrate your application using the `SamlAuth()` class. See the 
`example/` directory for a working example. The rest of this document will 
tell you what other options you have.

Three classes are relevant: `SamlAuth` (`src/Api/SamlAuth.php`), `AuthOptions` 
(`src/Api/AuthOptions.php`) and `Assertion` (`src/Assertion.php`). You can take
a look at them if you'd like.

## AuthOptions

You can configure the SAML authentication flow by initializing the 
`AuthOptions` object and setting some parameters. The following methods are 
defined in `AuthOptions`. All of them are *OPTIONAL*:

* `public function withReturnTo($returnTo)`: if you want to return to a 
  specific URL after the authentication is complete. By default you will return 
  to the URL where you started the authentication from;
* `public function withAuthnContextClassRef(array $authnContextClassRef)`: if 
  you want to request a certain 
  [Authentication Context](https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf), 
  e.g. for Two Factor authentication;
* `public function withIdp($idpEntityId)`: if you want to send the browser to a 
  specific IdP (by its `entityID` directly instead of showing the "WAYF" in 
  case there are multiple IdPs linked to this SP;
* `public function withScopingIdpList(array $scopingIdpList)`: if your SP is
  behind a proxy server and you want to restrict, or select the IdP(s) the user 
  is allowed to choose in the proxy IdP selector.
  
### Example

    use fkooman\SAML\SP\Api\AuthOptions;
    
    $authOptions = AuthOptions::init()
        ->withReturnTo('https://sp.example.org/account')
        ->withAuthnContextClassRef(['urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken'])
        ->withIdP('https://proxy.example.com/saml')
        ->withScopingIdpList(
            ['https://idp.example.org/saml', 'https://idp.example.com/saml']
        );

## SamlAuth

You can use the following API from your applications.

**NOTE** we will probably revisit the exposed calls before the 1.0 release. For
example the `SamlAuth::getAndVerifyAssertion` method should probably not be 
`public`... In case you are using `AuthOptions` they need to be specified at 
every call as well...this is not great!

* `public function getLoginURL(AuthOptions $authOptions = null)`: get the URL 
  you need in order to trigger user authentication;
* `public function getAssertion(AuthOptions $authOptions = null)`: get the SAML 
  assertion object in case the user is already authenticated;
* `public function isAuthenticated(AuthOptions $authOptions = null)`: figure 
  out whether the user was (successfully) authenticated already;
* `public function getAndVerifyAssertion(AuthOptions $authOptions = null)`: get 
  the SAML assertion when the user was successfully authenticated, or `null` 
  otherwise.

### Example

    use fkooman\SAML\SP\Api\AuthOptions;
    use fkooman\SAML\SP\Api\SamlAuth;
    
    $authOptions = AuthOptions::init();
    $samlAuth = new SamlAuth();
    if (!$samlAuth->isAuthenticated($authOptions)) {
        \header('Location: '.$samlAuth->getLoginURL($authOptions));
        exit(0);
    }
    
    $samlAssertion = $samlAuth->getAssertion($authOptions);
    echo \htmlentities($samlAssertion->getIssuer());
    if (null !== $nameId = $samlAssertion->getNameId()) {
        echo \htmlentities($nameId->toXml());
    }
    foreach ($samlAssertion->getAttributes() as $k => $v) {
        echo $k.': '.\implode(',', $v);
    }
    
## Assertion

The `getAssertion` returns an `Assertion` object, which has the following 
methods that can be used to get more information about the authenticated 
session:

* `public function getIssuer()`: get the issuer of the SAML assertion;
* `public function getNameId()`: get the `NameID` object, see `src/NameID.php`;
* `public function getAuthnInstant()`: get the moment the authentication took 
  place;
* `public function getSessionNotOnOrAfter()`: get the time until which the 
  assertion is valid;
* `public function getAuthnContext()`: get the authentication context (see 
  `AuthOptions` above that was actually granted;
* `public function getAuthenticatingAuthority()`: get the authenticating IdP, 
  in case a SAML proxy was used;
* `public function getAttributes()`: get a list of attributes received from the
  IdP. This is an `array` with the attribute name as "key" and the attribute 
  value(s) as an `array` of `string`.
