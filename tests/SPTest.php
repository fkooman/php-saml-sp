<?php

/*
 * Copyright (c) 2019-2020 François Kooman <fkooman@tuxed.net>
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
use DOMDocument;
use fkooman\SAML\SP\Assertion;
use fkooman\SAML\SP\AuthnRequestState;
use fkooman\SAML\SP\Crypto;
use fkooman\SAML\SP\CryptoKeys;
use fkooman\SAML\SP\Exception\ResponseException;
use fkooman\SAML\SP\LogoutRequestState;
use fkooman\SAML\SP\MetadataSource;
use fkooman\SAML\SP\NameId;
use fkooman\SAML\SP\PrivateKey;
use fkooman\SAML\SP\SpInfo;
use PHPUnit\Framework\TestCase;

class SPTest extends TestCase
{
    /** @var \fkooman\SAML\SP\SP */
    private $sp;

    public function setUp(): void
    {
        $spInfo = new SpInfo(
            'http://localhost:8081/metadata',
            CryptoKeys::load(__DIR__.'/data'),
            'http://localhost:8081/acs',
            false,
            ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
        );
        $spInfo->setSloUrl('http://localhost:8081/slo');
        $this->sp = new TestSP(
            $spInfo,
            new MetadataSource(new NullLogger(), __DIR__.'/data/metadata', \sys_get_temp_dir()),
            new TestSession()
        );
        $this->sp->setDateTime(new DateTime('2018-01-01 08:00:00'));
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

        $relayState = \base64_encode('1234_relay_state_5678');
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => \base64_encode(Crypto::sign($httpQuery, PrivateKey::fromFile(__DIR__.'/data/signing.key')))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);

        $authnRequestState = \unserialize($session->get(TestSP::SESSION_KEY_PREFIX.''.$relayState));
        $this->assertSame('http://localhost:8080/metadata.php', $authnRequestState->getIdpEntityId());
        $this->assertSame('_30313233343536373839616263646566', $authnRequestState->getRequestId());
        $this->assertSame([], $authnRequestState->getAuthnContextClassRef());
        $this->assertSame('http://localhost:8080/app', $authnRequestState->getReturnTo());
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

        $relayState = \base64_encode('1234_relay_state_5678');
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => \base64_encode(Crypto::sign($httpQuery, PrivateKey::fromFile(__DIR__.'/data/signing.key')))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
    }

    public function testScopingIdPList()
    {
        $ssoUrl = $this->sp->login(
            'http://localhost:8080/metadata.php',
            'http://localhost:8080/app',
            [],
            ['https://idp.tuxed.net/metadata']
        );

        $samlRequest = <<< EOF
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2018-01-01T08:00:00Z" Destination="http://localhost:8080/sso.php" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="http://localhost:8081/acs">
  <saml:Issuer>http://localhost:8081/metadata</saml:Issuer>
  <samlp:Scoping>
    <samlp:IDPList>
      <samlp:IDPEntry ProviderID="https://idp.tuxed.net/metadata"/>
    </samlp:IDPList>
  </samlp:Scoping>
</samlp:AuthnRequest>
EOF;

        $relayState = \base64_encode('1234_relay_state_5678');
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($samlRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );
        $signatureQuery = \http_build_query(['Signature' => \base64_encode(Crypto::sign($httpQuery, PrivateKey::fromFile(__DIR__.'/data/signing.key')))]);
        $this->assertSame(\sprintf('http://localhost:8080/sso.php?%s&%s', $httpQuery, $signatureQuery), $ssoUrl);
    }

    public function testMetadata()
    {
        $metadataWithEncryptionSupportResponse = <<< EOF
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="http://localhost:8081/metadata">
  <md:Extensions>
    <mdui:UIInfo>
      <mdui:DisplayName xml:lang="en-US">My SP</mdui:DisplayName>
      <mdui:DisplayName xml:lang="nl-NL">Mijn SP</mdui:DisplayName>
    </mdui:UIInfo>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod MinKeySize="2048" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIEBTCCAm2gAwIBAgIUS7YFVomn/lUz/H0CEm8RL1UxNpowDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHU0FNTCBTUDAeFw0xOTAxMDcxODU5MTNaFw0yODExMTUxODU5MTNaMBIxEDAOBgNVBAMMB1NBTUwgU1AwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDydCL4AJfuaOesEcLb+WUiQx0HXs42yyXl/ZIWpg7NaASFFRZC096gnW06sDq2TLIpCdcKt8qd5WBxll4RXN/CoPC1nnHW6AzGPC3zVQne7unJuPSG8Ka1OzXBt9tA+NyQd0h/U5yIVUrtK0svNGtjZ8pOZ76Dm/STIV5mq3HZQ7RfJtMPfagcDY72Eu+FNQaQ72YQFKlg6tm3mqduGdIuMATfVv4my4EHDkux8PV+AbtZcnwq4YlrbgeQ73CnA8LCw0WG8yHblzd8eKwdBuE53tthvu44qEvtx49nrvP0o6KfGG7Qn7tDzaXkmxz23L4GsXdON9jc9yu/BUYYYtUwB7shW42q2RJHWOel5L/GEXGesn4C5DMUG62I4+RDxUIwtoHjz5Fh4BC32uZvPBnIIphXXoDqCqGN9ruzLD1wBlj5UwTr7ves0+aYUwv7lOq1TY5ljA5PkBz3mVQjWMgWaruGdLgJsC3OsRmidUN+/XtXvBHFCeBkvURoOBl95UcCAwEAAaNTMFEwHQYDVR0OBBYEFAdw5e4frADj6CRyrRT1ojo+9ojOMB8GA1UdIwQYMBaAFAdw5e4frADj6CRyrRT1ojo+9ojOMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggGBAHN1ZOlG7gEZYrxjCWTITiP2eCMMb5+bCpi3D69tCtRE1Tz4vEDlHrdepqQo7TVrCYoQiUg1KnGDBMXxY/L/MGKJbgeP+9o8cNpP+1scF5Sac6K/jRAlzso//eSUJkReYynUHjLaIsmhyQ8UOEfUHQmpgAGlSHNcTT9lUpwyphQs4HcIgTYXT1sZVb09/7gEeaKdAfXQ5BEyLU3RYaQUzkyvHYywo1gSKOSjB2UfqCt2+nJzztQzZzmDePDVRWyxfQNHN/Y4PUxIKi/8hxBB3497A5FNsI7gq1j5dBzbPpv+G17sBix7QkoiMy5n2degHhLfSFX1I6+I1lMIEtqR+uI9civOtRo9D90L8uydACoLY4CqslouwCsHuJU39h1HEES8FaXYS7nrthVShNJ8pOk5SPshl637FxlLGWfuFZR1Ot20WtVgXZFwq9ZgRrAnO7PLgbXadocn4skHHbigVWHdwjZIv1rjOVcewY/W/w93mgh5CZikrQQ2PTmUPn6Raw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIEBTCCAm2gAwIBAgIUS7YFVomn/lUz/H0CEm8RL1UxNpowDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHU0FNTCBTUDAeFw0xOTAxMDcxODU5MTNaFw0yODExMTUxODU5MTNaMBIxEDAOBgNVBAMMB1NBTUwgU1AwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDydCL4AJfuaOesEcLb+WUiQx0HXs42yyXl/ZIWpg7NaASFFRZC096gnW06sDq2TLIpCdcKt8qd5WBxll4RXN/CoPC1nnHW6AzGPC3zVQne7unJuPSG8Ka1OzXBt9tA+NyQd0h/U5yIVUrtK0svNGtjZ8pOZ76Dm/STIV5mq3HZQ7RfJtMPfagcDY72Eu+FNQaQ72YQFKlg6tm3mqduGdIuMATfVv4my4EHDkux8PV+AbtZcnwq4YlrbgeQ73CnA8LCw0WG8yHblzd8eKwdBuE53tthvu44qEvtx49nrvP0o6KfGG7Qn7tDzaXkmxz23L4GsXdON9jc9yu/BUYYYtUwB7shW42q2RJHWOel5L/GEXGesn4C5DMUG62I4+RDxUIwtoHjz5Fh4BC32uZvPBnIIphXXoDqCqGN9ruzLD1wBlj5UwTr7ves0+aYUwv7lOq1TY5ljA5PkBz3mVQjWMgWaruGdLgJsC3OsRmidUN+/XtXvBHFCeBkvURoOBl95UcCAwEAAaNTMFEwHQYDVR0OBBYEFAdw5e4frADj6CRyrRT1ojo+9ojOMB8GA1UdIwQYMBaAFAdw5e4frADj6CRyrRT1ojo+9ojOMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggGBAHN1ZOlG7gEZYrxjCWTITiP2eCMMb5+bCpi3D69tCtRE1Tz4vEDlHrdepqQo7TVrCYoQiUg1KnGDBMXxY/L/MGKJbgeP+9o8cNpP+1scF5Sac6K/jRAlzso//eSUJkReYynUHjLaIsmhyQ8UOEfUHQmpgAGlSHNcTT9lUpwyphQs4HcIgTYXT1sZVb09/7gEeaKdAfXQ5BEyLU3RYaQUzkyvHYywo1gSKOSjB2UfqCt2+nJzztQzZzmDePDVRWyxfQNHN/Y4PUxIKi/8hxBB3497A5FNsI7gq1j5dBzbPpv+G17sBix7QkoiMy5n2degHhLfSFX1I6+I1lMIEtqR+uI9civOtRo9D90L8uydACoLY4CqslouwCsHuJU39h1HEES8FaXYS7nrthVShNJ8pOk5SPshl637FxlLGWfuFZR1Ot20WtVgXZFwq9ZgRrAnO7PLgbXadocn4skHHbigVWHdwjZIv1rjOVcewY/W/w93mgh5CZikrQQ2PTmUPn6Raw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8081/slo"/>
    <md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/acs"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
EOF;

        $metadataWithoutEncryptionSupportResponse = <<< EOF
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="http://localhost:8081/metadata">
  <md:Extensions>
    <mdui:UIInfo>
      <mdui:DisplayName xml:lang="en-US">My SP</mdui:DisplayName>
      <mdui:DisplayName xml:lang="nl-NL">Mijn SP</mdui:DisplayName>
    </mdui:UIInfo>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod MinKeySize="2048" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
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

        if (Crypto::hasDecryptionSupport()) {
            $this->assertSame(
                $metadataWithEncryptionSupportResponse,
                $this->sp->metadata()
            );
        }

        if (!Crypto::hasDecryptionSupport()) {
            $this->assertSame(
                $metadataWithoutEncryptionSupportResponse,
                $this->sp->metadata()
            );
        }
    }

    public function testHandleResponse()
    {
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP.xml');

        $session = new TestSession();
        $authnRequestState = new AuthnRequestState('_2483d0b8847ccaa5edf203dad685f860', 'http://localhost:8080/metadata.php', [], [], 'http://localhost:8080/return_to');
        $session->set(TestSP::SESSION_KEY_PREFIX.'1234_relay_state_5678', \serialize($authnRequestState));
        $this->sp->setSession($session);
        $this->sp->setDateTime(new DateTime('2019-02-23T17:01:21Z'));
        $returnTo = $this->sp->handleResponse(
            \base64_encode($samlResponse),
            '1234_relay_state_5678'
        );
        $this->assertSame('http://localhost:8080/return_to', $returnTo);
        $samlAssertion = \unserialize($session->get(TestSP::SESSION_KEY_PREFIX.'assertion'));
        $this->assertSame('http://localhost:8080/metadata.php', $samlAssertion->getIssuer());
        $this->assertSame('<saml:NameID SPNameQualifier="http://localhost:8081/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">bGFxwg50lVJbZsA2OHcqchfJ5HCDuxcFYBPxUi_dumo</saml:NameID>', $samlAssertion->getNameId()->toXML());
        $this->assertSame(
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => [
                    'foo',
                ],
                'uid' => [
                    'foo',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'foo',
                    'bar',
                    'baz',
                    'urn:example:LC-admin',
                    'urn:example:admin',
                ],
                'eduPersonEntitlement' => [
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

    public function testHandleResponseWrongAuthnContext()
    {
        try {
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP.xml');

            $session = new TestSession();
            $authnRequestState = new AuthnRequestState('_2483d0b8847ccaa5edf203dad685f860', 'http://localhost:8080/metadata.php', ['urn:x-example:bar'], [], 'return_to');
            $session->set(TestSP::SESSION_KEY_PREFIX.''.\base64_encode('1234_relay_state_5678'), \serialize($authnRequestState));
            $this->sp->setSession($session);
            $this->sp->setDateTime(new DateTime('2019-02-23T17:01:21Z'));
            $this->sp->handleResponse(
                \base64_encode($samlResponse),
                \base64_encode('1234_relay_state_5678')
            );
            $this->fail();
        } catch (ResponseException $e) {
            $this->assertSame('expected AuthnContext containing any of [urn:x-example:bar], got "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"', $e->getMessage());
        }
    }

    public function testLogout()
    {
        $testSession = new TestSession();

        $domDocument = new DOMDocument();
        $domDocument->loadXML('<NameID SPNameQualifier="http://localhost:8081/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</NameID>');
        $nameId = new NameId('', 'http://localhost:8081/metadata', $domDocument->documentElement);

        $samlAssertion = new Assertion(
            'http://localhost:8080/metadata.php',
            new DateTime('2019-01-02T20:05:33Z'),
            new DateTime('2019-01-03T04:05:33Z'),
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            null,
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
        $samlAssertion->setNameId($nameId);

        $testSession->set(TestSP::SESSION_KEY_PREFIX.'assertion', \serialize($samlAssertion));
        $this->sp->setSession($testSession);
        $this->sp->setDateTime(new DateTime('2019-01-03T03:05:33Z'));
        $sloUrl = $this->sp->logout(
            'http://localhost:8080/app'
        );

        $logoutRequest = <<< EOF
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_30313233343536373839616263646566" Version="2.0" IssueInstant="2019-01-03T03:05:33Z" Destination="http://localhost:8080/slo.php">
  <saml:Issuer>http://localhost:8081/metadata</saml:Issuer>
  <saml:NameID SPNameQualifier="http://localhost:8081/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">LtrfxjC6GOQ5pywYueOfXJDwfhQ7dZ4t9k3yGEB1WhY</saml:NameID></samlp:LogoutRequest>
EOF;

        $relayState = \base64_encode('1234_relay_state_5678');
        $httpQuery = \http_build_query(
            [
                'SAMLRequest' => \base64_encode(\gzdeflate($logoutRequest)),
                'RelayState' => $relayState,
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ]
        );

        $signatureQuery = \http_build_query(['Signature' => \base64_encode(Crypto::sign($httpQuery, PrivateKey::fromFile(__DIR__.'/data/signing.key')))]);
        $this->assertSame(\sprintf('http://localhost:8080/slo.php?%s&%s', $httpQuery, $signatureQuery), $sloUrl);
    }

    public function testHandleLogoutResponse()
    {
        $logoutResponse = \file_get_contents(__DIR__.'/data/assertion/LogoutResponse.xml');
        $session = new TestSession();
        $logoutRequestState = new LogoutRequestState('_32d79225e7f53ecddead60c5096347070d4ce0521ee7d734d6a7b1cc1d666d32', 'http://localhost:8080/metadata', 'http://localhost:8081/');
        $session->set(TestSP::SESSION_KEY_PREFIX.'+/M7/sd8CgDR7BXVpw2lqgsalw54taH0E2eYa2RrZcI=', \serialize($logoutRequestState));
        $this->sp->setSession($session);

        $queryString = \http_build_query(
            [
                'SAMLResponse' => \base64_encode(\gzdeflate($logoutResponse)),
                'RelayState' => '+/M7/sd8CgDR7BXVpw2lqgsalw54taH0E2eYa2RrZcI=',
                'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                'Signature' => 'MNvAlJmSRH0PpRNpVLt4/diLRhi7LjV986I0ZL+VXMSxsEnd197D7H/xG4EpdpiA4n+BWPyPIhlvq3xCjcr1SI3UJ53NKYyOfTUq62c+Cz6ZmSmq3ttpw5VvSf8slUd/jfNs7NfdT80V7mo992DZjzE8DBoTzUS+ByrJCfkhiPrpjc2TwiL4X6XZ80DD51k4tdQyDVbgBCnw/AlIljzhodIzg+PQp89LkAXx+4wbsxy1pqltxOhZ2toE91SPzuVYPKJQXlFVLqaGPegU+9yJCtf676KNoJ19lxtKXigBZzEouJ72p/Tsxsa+gQI47YadTOP9a3KQSE1IHYeFYzg/EsbU5RqhLPYyFksSEY+a4VNenoIWbC7X3UMj8BTMrmtE+dqQgaJ/RhhCr+lwbtNCOqJ2l9h8bc5Nrq8ycgM6l0iR+h4AFpIYl3XdPcebNu90Sn8LNFQu+30vf9QT21VFQQmo2yKnYBUwyPbW8WgTVX+/JihlpnGjuRadY7efcHEK',
            ]
        );
        $returnTo = $this->sp->handleLogoutResponse($queryString);
        $this->assertSame('http://localhost:8081/', $returnTo);
        $this->assertNull($session->get(TestSP::SESSION_KEY_PREFIX.'+/M7/sd8CgDR7BXVpw2lqgsalw54taH0E2eYa2RrZcI='));
    }
}
