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

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\SAML\SP\PrivateKey;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;
use fkooman\SAML\SP\XmlIdpInfoSource;

try {
    \session_start();

    $idpInfoSource = new XmlIdpInfoSource(__DIR__.'/x509idp.moonshot.utr.surfcloud.nl.xml');
    $idpEntityId = 'https://x509idp.moonshot.utr.surfcloud.nl/metadata';
    //$idpInfoSource = new XmlIdpInfoSource(__DIR__.'/localhost.xml');
    //$idpEntityId = 'http://localhost:8080/metadata';
    $relayState = 'http://localhost:8081/';

    // configure the SP
    $spInfo = new SpInfo(
        'http://localhost:8081/metadata',
        PrivateKey::fromFile('sp.key'), // used to sign AuthnRequest /
                                        // LogoutRequest
        PublicKey::fromFile('sp.crt'),
        'http://localhost:8081/acs'
    );
    // we also want to support logout in the example
    $spInfo->setSloUrl('http://localhost:8081/slo');

    $sp = new SP($spInfo, $idpInfoSource);

    $pathInfo = \array_key_exists('PATH_INFO', $_SERVER) ? $_SERVER['PATH_INFO'] : '/';
    $requestMethod = $_SERVER['REQUEST_METHOD'];

    switch ($pathInfo) {
        // landing page
        case '/':
            if (false === $samlAssertion = $sp->getAssertion()) {
                // not logged in, redirect to IdP
                \http_response_code(302);
                \header(\sprintf('Location: %s', $sp->login($idpEntityId, $relayState)));
            } else {
                echo '<pre>';
                echo 'Issuer      : '.$samlAssertion->getIssuer().PHP_EOL;
                if (null !== $nameId = $samlAssertion->getNameId()) {
                    echo 'NameID      : '.\htmlentities($nameId->toXml()).PHP_EOL;
                }
                echo 'AuthnTime   : '.$samlAssertion->getAuthnInstant()->format(DateTime::ATOM).PHP_EOL;
                echo 'AuthnContext: '.$samlAssertion->getAuthnContext().PHP_EOL;
                foreach ($samlAssertion->getAttributes() as $k => $v) {
                    echo $k.': '.\implode(',', $v).PHP_EOL;
                }
                echo '<a href="logout"><button>Logout</button></a>';
            }
            break;

        // user triggered logout
        case '/logout':
            \http_response_code(302);
            \header(\sprintf('Location: %s', $sp->logout($relayState)));
            break;

        // callback from IdP containing the "SAMLResponse"
        case '/acs':
            if ('POST' === $requestMethod) {
                // listen only for POST HTTP request
                $returnTo = $sp->handleResponse($_POST);
                \http_response_code(302);
                \header(\sprintf('Location: %s', $returnTo));
            } else {
                \http_response_code(405);
                echo '[405] only POST allowed on ACS';
            }
            break;

        // exposes the SP metadata for IdP consumption
        case '/metadata':
            \header('Content-Type: application/samlmetadata+xml');
            echo $sp->metadata();
            break;

        // callback from IdP containing the "LogoutResponse"
        case '/slo':
            // we need the "raw" query string to be able to verify the
            // signatures...
            $returnTo = $sp->handleLogoutResponse($_SERVER['QUERY_STRING']);
            \http_response_code(302);
            \header(\sprintf('Location: %s', $returnTo));
            break;

        default:
            \http_response_code(404);
            echo '[404] page not found';
    }
} catch (Exception $e) {
    echo 'Error: '.$e->getMessage().PHP_EOL;
}
