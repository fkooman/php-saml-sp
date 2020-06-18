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
use fkooman\SAML\SP\Crypto;
use fkooman\SAML\SP\CryptoKeys;
use fkooman\SAML\SP\Exception\CryptoException;
use fkooman\SAML\SP\Exception\ResponseException;
use fkooman\SAML\SP\IdpInfo;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\Response;
use fkooman\SAML\SP\SpInfo;
use PHPUnit\Framework\TestCase;

class ResponseTest extends TestCase
{
    public function testFrkoIdP()
    {
        $response = new Response(new DateTime('2019-02-23T17:01:21Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'http://localhost:8081/metadata',
                CryptoKeys::load(__DIR__.'/data/certs'),
                'http://localhost:8081/acs',
                false,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/FrkoIdP.crt')], []),
            $samlResponse,
            '_2483d0b8847ccaa5edf203dad685f860',
            [],
            []
        );
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
        $this->assertNull($samlAssertion->getAuthenticatingAuthority());
    }

    public function testSURFconext()
    {
        $response = new Response(new DateTime('2019-01-02T21:58:23Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/SURFconext.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'https://labrat.eduvpn.nl/saml',
                CryptoKeys::load(__DIR__.'/data/certs'),
                'https://labrat.eduvpn.nl/saml/postResponse',
                false,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('https://idp.surfnet.nl', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/SURFconext.crt')], []),
            $samlResponse,
            '_928BA2C80BB10E7BA8F2C4504E0EB20B',
            [],
            []
        );
        $this->assertSame(
            [
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:eduvpn-admin',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test1',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test3',
                ],
                'eduPersonEntitlement' => [
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:eduvpn-admin',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test1',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test3',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.10' => [
                    'https://idp.surfnet.nl!https://labrat.eduvpn.nl/saml!c7ab9096f240ea83747f351c6fcb17d1f57f56f2',
                ],
                'eduPersonTargetedID' => [
                    'https://idp.surfnet.nl!https://labrat.eduvpn.nl/saml!c7ab9096f240ea83747f351c6fcb17d1f57f56f2',
                ],
            ],
            $samlAssertion->getAttributes()
        );
        $this->assertSame('https://idp.surfnet.nl', $samlAssertion->getAuthenticatingAuthority());
    }

    public function testMismatchAuthenticatingAuthority()
    {
        try {
            $response = new Response(new DateTime('2019-01-02T21:58:23Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/SURFconext.xml');
            $samlAssertion = $response->verify(
                new SpInfo(
                    'https://labrat.eduvpn.nl/saml',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'https://labrat.eduvpn.nl/saml/postResponse',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('https://idp.surfnet.nl', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/SURFconext.crt')], []),
                $samlResponse,
                '_928BA2C80BB10E7BA8F2C4504E0EB20B',
                [],
                ['https://foo.example.org', 'https://bar.example.org']
            );
            $this->fail();
        } catch (ResponseException $e) {
            $this->assertSame('expected AuthenticatingAuthority containing any of [https://foo.example.org,https://bar.example.org], got "https://idp.surfnet.nl"', $e->getMessage());
        }
    }

    //  XXX we do not support "raw" attributes yet, only in urn:oid format
//    public function testSimpleSamlPhp()
//    {
//        $response = new Response(new DateTime('2019-01-02T22:19:20Z'));
//        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/simpleSAMLphp.xml');
//        $samlAssertion = $response->verify(
//            new SpInfo(
//                'https://vpn.tuxed.net/simplesaml/module.php/saml/sp/metadata.php/default-sp',
//                CryptoKeys::load(__DIR__.'/data/certs'),
//                'https://vpn.tuxed.net/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
//                false
//            ),
//            new IdpInfo('https://vpn.tuxed.net/simplesaml/saml2/idp/metadata.php', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/simpleSAMLphp.crt')], []),
//            $samlResponse,
//            '_b354c4367b3e379f940145868f28987e9520b1fb0b',
//            []
//        );
//        $this->assertSame(
//            [
//                'uid' => [
//                    'test',
//                ],
//                'eduPersonAffiliation' => [
//                    'member',
//                    'student',
//                ],
//            ],
//            $samlAssertion->getAttributes()
//        );
//    }

    public function testInvalidDigest()
    {
        try {
            $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP_invalid_digest.xml');
            $response->verify(
                new SpInfo(
                    'http://localhost:8081/metadata',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'http://localhost:8081/acs',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/FrkoIdP.crt')], []),
                $samlResponse,
                '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
                [],
                []
            );
            $this->fail();
        } catch (CryptoException $e) {
            $this->assertSame('unexpected digest', $e->getMessage());
        }
    }

    public function testWrongCertificate()
    {
        try {
            $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP.xml');
            $response->verify(
                new SpInfo(
                    'http://localhost:8081/metadata',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'http://localhost:8081/acs',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/simpleSAMLphp.crt')], []),
                $samlResponse,
                '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
                [],
                []
            );
            $this->fail();
        } catch (CryptoException $e) {
            $this->assertSame('unable to verify signature', $e->getMessage());
        }
    }

    public function testWrongSignature()
    {
        try {
            $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP_invalid_signature.xml');
            $response->verify(
                new SpInfo(
                    'http://localhost:8081/metadata',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'http://localhost:8081/acs',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/FrkoIdP.crt')], []),
                $samlResponse,
                '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
                [],
                []
            );
            $this->fail();
        } catch (CryptoException $e) {
            $this->assertSame('unable to verify signature', $e->getMessage());
        }
    }

    public function testNotSigned()
    {
        try {
            $response = new Response(new DateTime('2019-01-02T20:05:33Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/FrkoIdP_not_signed.xml');
            $response->verify(
                new SpInfo(
                    'http://localhost:8081/metadata',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'http://localhost:8081/acs',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/FrkoIdP.crt')], []),
                $samlResponse,
                '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
                [],
                []
            );
            $this->fail();
        } catch (ResponseException $e) {
            $this->assertSame('samlp:Response and/or saml:Assertion MUST be signed', $e->getMessage());
        }
    }

    public function testSha1()
    {
        try {
            $response = new Response(new DateTime('2019-01-16T23:47:31Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/x509idp.moonshot.utr.surfcloud.nl.xml');
            $response->verify(
                new SpInfo(
                    'http://localhost:8081/metadata',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'http://localhost:8081/acs',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('https://x509idp.moonshot.utr.surfcloud.nl/metadata', 'Test', 'https://x509idp.moonshot.utr.surfcloud.nl/sso', null, [PublicKey::fromFile(__DIR__.'/data/certs/x509idp.moonshot.utr.surfcloud.nl.crt')], []),
                $samlResponse,
                '_3c35f56a7156b0805fbccb717cc15194',
                [],
                []
            );
            $this->fail();
        } catch (CryptoException $e) {
            $this->assertSame('only digest method "http://www.w3.org/2001/04/xmlenc#sha256" is supported', $e->getMessage());
        }
    }

    //  XXX we do not support "raw" attributes yet, only in urn:oid format
//    public function testAdfs()
//    {
//        $response = new Response(new DateTime('2019-01-18T10:32:06Z'));
//        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/adfs_idp_response.xml');
//        $samlAssertion = $response->verify(
//            new SpInfo(
//                'https://vpn.tuxed.net/php-saml-sp/example/full.php/metadata',
//                CryptoKeys::load(__DIR__.'/data/certs'),
//                'https://vpn.tuxed.net/php-saml-sp/example/full.php/acs',
//                false
//            ),
//            new IdpInfo('http://fs.tuxed.example/adfs/services/trust', 'SSO', null, [PublicKey::fromFile(__DIR__.'/data/certs/adfs_idp_response.crt')], []),
//            $samlResponse,
//            '_cf4383b97e07821f6b9a07e57b3d4557',
//            []
//        );
//        $this->assertSame(
//            [
//                'http://schemas.xmlsoap.org/claims/CommonName' => [
//                    'François Kooman',
//                ],
//            ],
//            $samlAssertion->getAttributes()
//        );
//        $this->assertSame('<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">WrlwOmM5zcufWzakxkurPqQnZtvlDoxJt6kwJvf950M=</saml:NameID>', $samlAssertion->getNameId()->toXML());
//    }

    public function testErrorResponse()
    {
        try {
            $response = new Response(new DateTime('2019-01-16T23:47:31Z'));
            $samlResponse = \file_get_contents(__DIR__.'/data/assertion/SURFsecureID_error.xml');
            $response->verify(
                new SpInfo(
                    'https://kluitje.eduvpn.nl/saml',
                    CryptoKeys::load(__DIR__.'/data/certs'),
                    'https://kluitje.eduvpn.nl/portal/_saml/acs',
                    false,
                    ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
                ),
                new IdpInfo('https://sa-gw.test.surfconext.nl/authentication/metadata', 'Test', 'SSO', null, [PublicKey::fromFile(__DIR__.'/data/certs/SURFsecureID.crt')], []),
                $samlResponse,
                '_6a31edbaec0922414f9a96e5fdb5493e',
                [],
                []
            );
            $this->fail();
        } catch (ResponseException $e) {
            $this->assertSame('urn:oasis:names:tc:SAML:2.0:status:Responder (urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext)', $e->getMessage());
        }
    }

    public function testMissingSessionNotOnOrAfter()
    {
        $response = new Response(new DateTime('2019-08-05T15:00:00Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/SURFsecureID_no_SessionNotOnOrAfter.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'https://demo.eduvpn.nl/saml',
                CryptoKeys::load(__DIR__.'/data/certs'),
                'https://demo.eduvpn.nl/portal/_saml/acs',
                false,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('https://sa-gw.surfconext.nl/authentication/metadata', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/SURFsecureID_production.crt')], []),
            $samlResponse,
            '_715f3d18c77d3a0b37a1ad4386b3351851e8876a4d35a57aaee38f33f46edb17',
            [],
            []
        );
        $this->assertSame(
            '2019-08-05T23:00:00+00:00',
            $samlAssertion->getSessionNotOnOrAfter()->format(DateTime::ATOM)
        );
    }

    public function testEPPNScopeMatch()
    {
        // ePPN scope does not match IdP scope
        $response = new Response(new DateTime('2019-03-14T14:01:22Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/ePPN_scope_mismatch.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'http://localhost:8081/metadata',
                CryptoKeys::load(__DIR__.'/data/certs'),
                'http://localhost:8081/acs',
                false,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/FrkoIdP.crt')], ['example.com']),
            $samlResponse,
            '_d22979c597d8d8956b8d5b2f2bdae9bf',
            [],
            []
        );
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
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => [
                    'foo@example.com',
                ],
                'eduPersonPrincipalName' => [
                    'foo@example.com',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    public function testEPPNScopeMismatch()
    {
        // ePPN scope does not match IdP scope
        $response = new Response(new DateTime('2019-03-14T14:01:22Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/ePPN_scope_mismatch.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'http://localhost:8081/metadata',
                CryptoKeys::load(__DIR__.'/data/certs'),
                'http://localhost:8081/acs',
                false,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(__DIR__.'/data/certs/FrkoIdP.crt')], ['example.org']),
            $samlResponse,
            '_d22979c597d8d8956b8d5b2f2bdae9bf',
            [],
            []
        );
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
                // NOTE: the ePPN is not there because it does NOT match the
                // expected scope of @example.org
//                'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => [
//                    'foo@example.com',
//                ]
            ],
            $samlAssertion->getAttributes()
        );
    }

    public function testShibIdPEnc()
    {
        if (!Crypto::hasDecryptionSupport()) {
            $this->markTestSkipped();

            return;
        }

        $response = new Response(new DateTime('2019-02-28T14:00:08.163Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion/ShibIdpEnc.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'https://vpn.tuxed.net/vpn-user-portal/_saml/metadata',
                CryptoKeys::load(__DIR__.'/data/certs2'),
                'https://vpn.tuxed.net/vpn-user-portal/_saml/acs',
                true,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('https://testidp3-dev.aai.dfn.de/idp/shibboleth', 'Test', 'SSO', null, [PublicKey::fromFile(__DIR__.'/data/certs/shib_idp.crt')], []),
            $samlResponse,
            '_075f2ff7575c50efaead79a1c2a1805c',
            [],
            []
        );
        $this->assertSame(
            [
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.10' => [
                    'https://testidp3-dev.aai.dfn.de/idp/shibboleth!https://vpn.tuxed.net/vpn-user-portal/_saml/metadata!KYzsRqRzQY5qp+bv9T8bHA/AvsI=',
                ],
                'eduPersonTargetedID' => [
                    'https://testidp3-dev.aai.dfn.de/idp/shibboleth!https://vpn.tuxed.net/vpn-user-portal/_saml/metadata!KYzsRqRzQY5qp+bv9T8bHA/AvsI=',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }
}
