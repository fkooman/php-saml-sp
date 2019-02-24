<?php

/*
 * Copyright (c) 2019 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\SAML\SP\Tests;

use DateTime;
use fkooman\SAML\SP\Assertion;
use fkooman\SAML\SP\PrivateKey;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\Signer;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;
use fkooman\SAML\SP\XmlIdpInfoSource;
use PHPUnit\Framework\TestCase;

class SPTest extends TestCase
{
    /** @var \fkooman\SAML\SP\SP */
    private $sp;

    public function setUp()
    {
        $this->sp = new SP(
            new SpInfo(
                'http://localhost:8081/metadata',
                'http://localhost:8081/acs',
                'http://localhost:8081/slo',
                PrivateKey::fromFile(__DIR__.'/data/sp.key'),
                PublicKey::fromFile(__DIR__.'/data/sp.crt')
            ),
            new XmlIdpInfoSource(__DIR__.'/data/metadata/localhost.xml')
        );
        $this->sp->setDateTime(new DateTime('2018-01-01 08:00:00'));
        $this->sp->setSession(new TestSession());
        $this->sp->setRandom(new TestRandom());
    }

    public function testSimple()
    {
        $session = new TestSession();
        $this->sp->setSession($session);

        $ssoUrl = $this->sp->login(
            'http://localhost:8080/metadata.php',
            'http://localhost:8080/app'
        );

        $samlRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/sso.php" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="http://localhost:8081/acs">
  <saml:Issuer>http://localhost:8081/metadata</saml:Issuer>
</samlp:AuthnRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, PrivateKey::fromFile(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
        $this->assertSame('http://localhost:8080/metadata.php', $session->get('_fkooman_saml_sp_auth_idp'));
        $this->assertSame('_30313233343536373839616263646566', $session->get('_fkooman_saml_sp_auth_id'));
        $this->assertSame([], $session->get('_fkooman_saml_sp_auth_acr'));
    }

    public function testAuthnContextClassRef()
    {
        $ssoUrl = $this->sp->login(
            'http://localhost:8080/metadata.php',
            'http://localhost:8080/app',
            ['urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken']
        );

        $samlRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/sso.php" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="http://localhost:8081/acs">
  <saml:Issuer>http://localhost:8081/metadata</saml:Issuer>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, PrivateKey::fromFile(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
    }

    public function testMetadata()
    {
        $metadataResponse = <<< EOF
<md:EntityDescriptor validUntil="2018-01-02T20:00:00Z" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="http://localhost:8081/metadata">
  <md:Extensions>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod MinKeySize="2048" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIEBTCCAm2gAwIBAgIUS7YFVomn/lUz/H0CEm8RL1UxNpowDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHU0FNTCBTUDAeFw0xOTAxMDcxODU5MTNaFw0yODExMTUxODU5MTNaMBIxEDAOBgNVBAMMB1NBTUwgU1AwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDydCL4AJfuaOesEcLb+WUiQx0HXs42yyXl/ZIWpg7NaASFFRZC096gnW06sDq2TLIpCdcKt8qd5WBxll4RXN/CoPC1nnHW6AzGPC3zVQne7unJuPSG8Ka1OzXBt9tA+NyQd0h/U5yIVUrtK0svNGtjZ8pOZ76Dm/STIV5mq3HZQ7RfJtMPfagcDY72Eu+FNQaQ72YQFKlg6tm3mqduGdIuMATfVv4my4EHDkux8PV+AbtZcnwq4YlrbgeQ73CnA8LCw0WG8yHblzd8eKwdBuE53tthvu44qEvtx49nrvP0o6KfGG7Qn7tDzaXkmxz23L4GsXdON9jc9yu/BUYYYtUwB7shW42q2RJHWOel5L/GEXGesn4C5DMUG62I4+RDxUIwtoHjz5Fh4BC32uZvPBnIIphXXoDqCqGN9ruzLD1wBlj5UwTr7ves0+aYUwv7lOq1TY5ljA5PkBz3mVQjWMgWaruGdLgJsC3OsRmidUN+/XtXvBHFCeBkvURoOBl95UcCAwEAAaNTMFEwHQYDVR0OBBYEFAdw5e4frADj6CRyrRT1ojo+9ojOMB8GA1UdIwQYMBaAFAdw5e4frADj6CRyrRT1ojo+9ojOMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggGBAHN1ZOlG7gEZYrxjCWTITiP2eCMMb5+bCpi3D69tCtRE1Tz4vEDlHrdepqQo7TVrCYoQiUg1KnGDBMXxY/L/MGKJbgeP+9o8cNpP+1scF5Sac6K/jRAlzso//eSUJkReYynUHjLaIsmhyQ8UOEfUHQmpgAGlSHNcTT9lUpwyphQs4HcIgTYXT1sZVb09/7gEeaKdAfXQ5BEyLU3RYaQUzkyvHYywo1gSKOSjB2UfqCt2+nJzztQzZzmDePDVRWyxfQNHN/Y4PUxIKi/8hxBB3497A5FNsI7gq1j5dBzbPpv+G17sBix7QkoiMy5n2degHhLfSFX1I6+I1lMIEtqR+uI9civOtRo9D90L8uydACoLY4CqslouwCsHuJU39h1HEES8FaXYS7nrthVShNJ8pOk5SPshl637FxlLGWfuFZR1Ot20WtVgXZFwq9ZgRrAnO7PLgbXadocn4skHHbigVWHdwjZIv1rjOVcewY/W/w93mgh5CZikrQQ2PTmUPn6Raw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8081/slo"/>
    <md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/acs"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
EOF;

        $this->assertSame(
            $metadataResponse,
            $this->sp->metadata()
        );
    }

    public function testHandleResponse()
    {
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP.xml');

        $session = new TestSession();
        $session->set('_fkooman_saml_sp_auth_idp', 'http://localhost:8080/metadata.php');
        $session->set('_fkooman_saml_sp_auth_id', '_2483d0b8847ccaa5edf203dad685f860');
        $session->set('_fkooman_saml_sp_auth_acr', []);
        $this->sp->setSession($session);
        $this->sp->setDateTime(new DateTime('2019-02-23T17:01:21Z'));
        $this->sp->handleResponse(\base64_encode($samlResponse));
        $samlAssertion = $session->get('_fkooman_saml_sp_auth_assertion');
        $this->assertSame('http://localhost:8080/metadata.php', $samlAssertion->getIssuer());
        $this->assertSame('<saml:NameID SPNameQualifier="http://localhost:8081/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">bGFxwg50lVJbZsA2OHcqchfJ5HCDuxcFYBPxUi_dumo</saml:NameID>', $samlAssertion->getNameId());
        $this->assertSame(
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => [
                    'foo',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'foo',
                    'bar',
                    'baz',
                    'urn:example:LC-admin',
                    'urn:example:admin',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    /**
     * @expectedException \fkooman\SAML\SP\Exception\ResponseException
     * @expectedExceptionMessage expected AuthnContext containing any of [urn:x-example:bar], got "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
     */
    public function testHandleResponseWrongAuthnContext()
    {
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP.xml');

        $session = new TestSession();
        $session->set('_fkooman_saml_sp_auth_idp', 'http://localhost:8080/metadata.php');
        $session->set('_fkooman_saml_sp_auth_id', '_2483d0b8847ccaa5edf203dad685f860');
        $session->set('_fkooman_saml_sp_auth_acr', ['urn:x-example:bar']);
        $this->sp->setSession($session);
        $this->sp->setDateTime(new DateTime('2019-02-23T17:01:21Z'));
        $this->sp->handleResponse(\base64_encode($samlResponse));
    }

    public function testLogout()
    {
        $testSession = new TestSession();
        $samlAssertion = new Assertion(
            'http://localhost:8080/metadata.php',
            '<saml:NameID SPNameQualifier="http://localhost:8081/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID>',
            new DateTime('2019-01-02T20:05:33Z'),
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => [
                    'foo',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'foo',
                    'bar',
                    'baz',
                ],
            ]
        );
        $testSession->set('_fkooman_saml_sp_auth_assertion', $samlAssertion);
        $this->sp->setSession($testSession);
        $sloUrl = $this->sp->logout(
            'http://localhost:8080/app'
        );

        $logoutRequest = <<< EOF
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/slo.php">
  <saml:Issuer>http://localhost:8081/metadata</saml:Issuer>
  <saml:NameID SPNameQualifier="http://localhost:8081/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID></samlp:LogoutRequest>
EOF;

        $relayState = 'http://localhost:8080/app';
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($logoutRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );

        $signatureQuery = \http_build_query(['Signature' => Signer::signRedirect($httpQuery, PrivateKey::fromFile(__DIR__.'/data/sp.key'))]);
        $this->assertSame(\sprintf('http://localhost:8080/slo.php?%s&%s', $httpQuery, $signatureQuery), $sloUrl);
    }

    public function testHandleLogoutResponse()
    {
        $logoutResponse = \file_get_contents(__DIR__.'/data/assertion/LogoutResponse.xml');
        $session = new TestSession();
        $session->set('_fkooman_saml_sp_auth_logout_id', '_9ac5774131771c2dff4e152c4ef31369');
        $session->set('_fkooman_saml_sp_auth_logout_idp', 'http://localhost:8080/metadata.php');
        $this->sp->setSession($session);

        $this->sp->handleLogoutResponse(\base64_encode(\gzdeflate($logoutResponse)), 'http://localhost:8081/', 'rp/pDrK7fK/FSflLxhj+jvSkj/EnLHJ+sOWTXRYwHWpHxA1SbRgxFlgNORAYGJgLHSVd/zL9eFiYVgfNlGznZVWIo/CBJK6RyV2/vNmyBh9XcMCVIajiAZ/OK6Q+NoH3AhGeJ4D9i8l+CJFFijMSqMBXPVxuajxVG80gxcnNWDtHTF5hi3/aHf10PsT5lG12IMHLwwwFNKIUIRROnUclqFuhDGwusb2qi5PCNlrn07Azl1vkFGuTDDjpXpH9K6sfZ5hx9aJ11X1YK2VKvsEnfMh6D/ZD34xlAC+VibTlggkDuldjvGtyUNM3qKgSAwQ7oir3CAReCg4YwHo82hHdg0BlNsIe8sScvFoR9GYM9YRoFQXiIbIFkpKYHR8EWduMqu5vaPko9T9f7YAmcjSkE9U4ilXD/82kfXQPtM5Bl+Ei/ZvbBDSHTLf45hnn5HsL6ze0/Hun6Yk6eCenDFdLVo1FG2UeJ7ogMbA6RqXxJKiM+ZyZuXmisLoPFSivO5TZ');

        $this->assertFalse($session->has('_fkooman_saml_sp_auth_logout_id'));
        $this->assertFalse($session->has('_fkooman_saml_sp_auth_logout_idp'));
    }

//    public function testLogoutResponseAdfs()
//    {
//SAMLResponse: fVLLbsMgEPwVi7uNX0ls5Fiqkkuk9NJEPfRSEbw0ljAgL0T5/GK7OUSqcmSZ2XlAg3xQlh3Nj/HuA9AajRAd9lvyXUPBhZR5fLmUXVzWso6rTSnidRimaSZkUdQk+oQRe6O3JE9SEh0QPRw0Oq5dGKVZHadZnFXnrGKrgmWbZFWmXyTaA7peczczr85ZZJTerE6cv0OXaHDUXm08mYvRUrjzwSqg0iuVhAuKypBoN3mddPyomeHYI9N8AGROsNPb+5EFS0wsIOY1WhC97KELNvUj6tlMSWVd5aUsZLqWuchWIkt5xS9QrTnwjQiE+6A0srmr13J2NM4Io0jbzF2MC/U1iSPCOHVB2qmLUIXEvyYeyXknkQbUrReA1I0eXUMXhbZZ3vDkuPP4fNqZDqJPrjy8doAzmp28COuRRLRt6PNW+t9HaX8B

//RelayState: https://vpn.tuxed.net/php-saml-sp/example/full.php

//Signature: pI58/1WP+XoSYL02mKehsQJQzD3YFReFtuURm4ppqT8iMUbvjXEe6EK78hRs69ScZAJJAzDznzi4WzTAfKlHXS2i/AUWFKaE7O930viStr0SBb7VHpdmHlnoQNKjNmZTZnCbwXlpU6ccKpspToc1F/02Jxk/oniyoyqX5amViQgI7CwjKGghLlfgJZQV2+cTye1C7ZdBTOIv7k8YfqASLq4pkZrvqGhFJRj9yfNx1Oqd+MCqg/bIIcyM9sMUrsG0gZkwnq0aJaxr1vGhJJo5U8tKGLHhsuDXHGgj9BMs5St7RBjgTPulztw/pRRCFts4eu/q+yWZZ4G3Zz1V8Kd3rA==

//SigAlg: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256

//        'https://vpn.tuxed.net/php-saml-sp/example/full.php/slo?SAMLResponse=fVJNb4MgGP4rhjsCzg8k1mRpLybdZW122GVhiquJAvGFpj9%2fqOuhydIj8Dzv8%2fFSgZxGK47mx3j3rsAaDSpqDjv0VfZJm5VZgTuav%2bC0y76x5KzDnKYyZXlOS9qh6EPNMBi9Q0lMUdQAeNVocFK7cEVZiSnDjJ8ZFykVjMWcZp8oOihwg5ZuZV6csyAIuVodO39TXayVI%2fZi8WIOgyXqJic7KtL7cYzDA4HRoGi%2feF10%2fKyFkTCA0HJSIFwrTq9vRxEsiXYDCa%2fBqnboBxVMN%2foe9WxCUpbKss9KJlnGeV8UvEwL2tMkkV3B81Si6DaNGsTa1XM5OxtnWjOiulq7mDfqc5IEUPPSBaqXLkIVPfw1cU8uux5IQF2HVgFxswdXkU2hrrYdnpx0Hh5Pe9Op6EOOXj13ACtanHwbxgOKSF2Rx6nkv49S%2fwI%3d&RelayState=https%3a%2f%2fvpn.tuxed.net%2fphp-saml-sp%2fexample%2ffull.php&Signature=U%2fhsM3x89%2f%2bFdjzLLgdS43EvtOM%2byblt9fBYvw%2bB3gWWuWpaPTUeZzYGQDC4xbWwG6PpVFaHs5RV3oA5daClC7GJpJSEyMrRIsWJlK8T5W3D%2foYDDAbtsjmzeprb3zn2kZVU1Fgk2SL2lg%2b8xHk%2fi4SjxNuF2DaEPmS%2fHlvNuXMd%2bDREGhgVuUdFEaPgU9%2bTWtFuH4KtgyEQ%2b%2bG02NPXy1EWZWuB7Djso1cdOK3SxjW5y%2fzYPXBSjMksUpxMCQZl4Z9bufavIq50GAoMl2syiN5vW%2fKIxtVzSQ0RKJVg16%2fvs8vgIibZdqQOBNj8RMYBR0cekWD%2fYwz5SxlLVEfKmA%3d%3d&SigAlg=http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256'

//    }
}
