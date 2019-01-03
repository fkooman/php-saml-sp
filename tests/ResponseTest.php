<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
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
use fkooman\SAML\SP\IdPInfo;
use fkooman\SAML\SP\Response;
use PHPUnit\Framework\TestCase;

class ResponseTest extends TestCase
{
    /** @var \fkooman\SAML\SP\Response */
    private $response;

    public function setUp()
    {
        $this->response = new Response(
            \dirname(__DIR__).'/schema'
        );
    }

    public function testAssertion()
    {
        $this->response->setDateTime(new DateTime('2019-01-02T20:05:33Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/assertion.xml');
        $samlAssertion = $this->response->verify(
            $samlResponse,
            '_6f4ccd6d1ced9e0f5ac6333893c64a2010487d289044b6bb4497b716ebc0a067',
            'http://localhost:8081/acs.php',
            new IdPInfo('http://localhost:8080/metadata.php', 'http://localhost:8080/sso.php', \file_get_contents(__DIR__.'/data/server.crt'))
        );
        $this->assertSame(
            [
                'urn:oid:0.9.2342.19200300.100.1.1' => [
                    'foo',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'foo',
                    'bar',
                    'baz',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    public function testSURFconext()
    {
        $this->response->setDateTime(new DateTime('2019-01-02T21:58:23Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/SURFconext.xml');
        $samlAssertion = $this->response->verify(
            $samlResponse,
            '_928BA2C80BB10E7BA8F2C4504E0EB20B',
            'https://labrat.eduvpn.nl/saml/postResponse',
            new IdPInfo('https://idp.surfnet.nl', 'http://localhost:8080/sso.php', \file_get_contents(__DIR__.'/data/SURFconext.crt'))
        );
        $this->assertSame(
            [
                'urn:mace:dir:attribute-def:eduPersonEntitlement' => [
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:eduvpn-admin',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test1',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test3',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => [
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:eduvpn-admin',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test1',
                    'urn:mace:surfnet.nl:surfconext.nl:surfnet.nl:eduvpn:x-test3',
                ],
                'urn:mace:dir:attribute-def:eduPersonTargetedID' => [
                    'c7ab9096f240ea83747f351c6fcb17d1f57f56f2',
                ],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.10' => [
                    'c7ab9096f240ea83747f351c6fcb17d1f57f56f2',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }

    public function testSimpleSamlPhp()
    {
        $this->response->setDateTime(new DateTime('2019-01-02T22:19:20Z'));
        $samlResponse = \file_get_contents(__DIR__.'/data/simpleSAMLphp.xml');
        $samlAssertion = $this->response->verify(
            $samlResponse,
            '_b354c4367b3e379f940145868f28987e9520b1fb0b',
            'https://vpn.tuxed.net/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            new IdPInfo('https://vpn.tuxed.net/simplesaml/saml2/idp/metadata.php', 'http://localhost:8080/sso.php', \file_get_contents(__DIR__.'/data/simpleSAMLphp.crt'))
        );
        $this->assertSame(
            [
                'uid' => [
                    'test',
                ],
                'eduPersonAffiliation' => [
                    'member',
                    'student',
                ],
            ],
            $samlAssertion->getAttributes()
        );
    }
}
