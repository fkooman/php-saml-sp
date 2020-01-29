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

use fkooman\SAML\SP\IdpInfo;
use fkooman\SAML\SP\PrivateKey;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\Response;
use fkooman\SAML\SP\SpInfo;

class ResponseBench
{
    /**
     * @Revs(1000)
     * @Iterations(5)
     *
     * @return void
     */
    public function benchHandleResponse()
    {
        $response = new Response(new DateTime('2019-02-23T17:04:21Z'));
        $samlResponse = \file_get_contents(\dirname(__DIR__).'/tests/data/assertion/FrkoIdP.xml');
        $samlAssertion = $response->verify(
            new SpInfo(
                'http://localhost:8081/metadata',
                PrivateKey::fromFile(\dirname(__DIR__).'/tests/data/certs/sp.key'),
                PublicKey::fromFile(\dirname(__DIR__).'/tests/data/certs/sp.crt'),
                'http://localhost:8081/acs',
                false,
                ['en-US' => 'My SP', 'nl-NL' => 'Mijn SP']
            ),
            new IdpInfo('http://localhost:8080/metadata.php', 'Test', 'http://localhost:8080/sso.php', null, [PublicKey::fromFile(\dirname(__DIR__).'/tests/data/certs/FrkoIdP.crt')], []),
            $samlResponse,
            '_2483d0b8847ccaa5edf203dad685f860',
            []
        );
    }
}
