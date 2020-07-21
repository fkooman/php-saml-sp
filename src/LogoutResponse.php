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

namespace fkooman\SAML\SP;

use fkooman\SAML\SP\Exception\ResponseException;

class LogoutResponse
{
    /**
     * @param string $expectedInResponseTo
     * @param string $expectedSloUrl
     *
     * @throws \fkooman\SAML\SP\Exception\ResponseException
     *
     * @return void
     */
    public function verify(QueryParameters $queryParameters, $expectedInResponseTo, $expectedSloUrl, IdpInfo $idpInfo)
    {
        $queryString = self::prepareQueryString($queryParameters);
        Crypto::verify($queryString, Utils::decodeBase64($queryParameters->requireQueryParameter('Signature')), $idpInfo->getPublicKeys());

        if (false === $inflatedProtocolMessage = \gzinflate(Utils::decodeBase64($queryParameters->requireQueryParameter('SAMLResponse')))) {
            throw new ResponseException('unable to "inflate" SAMLResponse');
        }

        $logoutResponseDocument = XmlDocument::fromProtocolMessage($inflatedProtocolMessage);

        $logoutIssuer = $logoutResponseDocument->requireOneDomElementTextContent('/samlp:LogoutResponse/saml:Issuer');
        if ($logoutIssuer !== $idpInfo->getEntityId()) {
            throw new ResponseException('unexpected Issuer');
        }

        $logoutResponseInResponseTo = $logoutResponseDocument->requireOneDomAttrValue('/samlp:LogoutResponse/@InResponseTo');
        if ($expectedInResponseTo !== $logoutResponseInResponseTo) {
            throw new ResponseException('unexpected InResponseTo');
        }

        $logoutResponseDestination = $logoutResponseDocument->requireOneDomAttrValue('/samlp:LogoutResponse/@Destination');
        if ($expectedSloUrl !== $logoutResponseDestination) {
            throw new ResponseException('unexpected Destination');
        }

        // handle samlp:Status
        $statusCode = $logoutResponseDocument->requireOneDomAttrValue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value');
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode) {
            throw new ResponseException($statusCode);
        }
    }

    /**
     * @return string
     */
    private static function prepareQueryString(QueryParameters $queryParameters)
    {
        $samlResponse = $queryParameters->requireQueryParameter('SAMLResponse', true);
        $relayState = $queryParameters->optionalQueryParameter('RelayState', true);
        $sigAlg = $queryParameters->requireQueryParameter('SigAlg', true);
        if (null === $relayState) {
            return \sprintf('SAMLResponse=%s&SigAlg=%s', $samlResponse, $sigAlg);
        }

        return \sprintf('SAMLResponse=%s&RelayState=%s&SigAlg=%s', $samlResponse, $relayState, $sigAlg);
    }
}
