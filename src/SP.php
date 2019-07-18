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

namespace fkooman\SAML\SP;

use DateTime;
use fkooman\SAML\SP\Exception\SpException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;

/**
 * The main controlling class for the SP.
 */
class SP
{
    /** @var SpInfo */
    private $spInfo;

    /** @var IdpInfoSourceInterface */
    private $idpInfoSource;

    /** @var \DateTime */
    private $dateTime;

    /** @var SessionInterface */
    private $session;

    /** @var RandomInterface */
    private $random;

    /** @var Template */
    private $tpl;

    public function __construct(SpInfo $spInfo, IdpInfoSourceInterface $idpInfoSource)
    {
        $this->spInfo = $spInfo;
        $this->idpInfoSource = $idpInfoSource;
        $this->dateTime = new DateTime();
        $this->session = new PhpSession();
        $this->random = new Random();
        $this->tpl = new Template(__DIR__.'/tpl');
    }

    /**
     * @return SpInfo
     */
    public function getSpInfo()
    {
        return $this->spInfo;
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param SessionInterface $session
     *
     * @return void
     */
    public function setSession(SessionInterface $session)
    {
        $this->session = $session;
    }

    /**
     * @param RandomInterface $random
     *
     * @return void
     */
    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    /**
     * Prepare and retrieve the login URL.
     *
     * @param string        $idpEntityId
     * @param string        $returnTo
     * @param array<string> $authnContextClassRef
     *
     * @throws \fkooman\SAML\SP\Exception\SpException
     *
     * @return string
     */
    public function login($idpEntityId, $returnTo, array $authnContextClassRef = [])
    {
        $requestId = \sprintf('_%s', Hex::encode($this->random->requestId()));
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }
        $ssoUrl = $idpInfo->getSsoUrl();

        $authnRequest = $this->tpl->render(
            'AuthnRequest',
            [
                'ID' => $requestId,
                'IssueInstant' => $this->dateTime->format('Y-m-d\TH:i:s\Z'),
                'Destination' => $ssoUrl,
                'AssertionConsumerServiceURL' => $this->spInfo->getAcsUrl(),
                'Issuer' => $this->spInfo->getEntityId(),
                'AuthnContextClassRef' => $authnContextClassRef,
            ]
        );

        $relayState = Base64::encode($this->random->relayState());
        $authnRequestState = new AuthnRequestState($requestId, $idpEntityId, $authnContextClassRef, $returnTo);
        $this->session->set($relayState, \serialize($authnRequestState));

        return self::prepareRequestUrl($ssoUrl, $authnRequest, $relayState, $this->spInfo->getPrivateKey());
    }

    /**
     * Handle the SAML response message received from the IdP.
     *
     * @param string $samlResponse
     * @param string $relayState
     *
     * @throws \fkooman\SAML\SP\Exception\SpException
     *
     * @return string
     */
    public function handleResponse($samlResponse, $relayState)
    {
        $authnRequestState = \unserialize($this->session->take($relayState));
        if (!($authnRequestState instanceof AuthnRequestState)) {
            throw new \RuntimeException('Wat XXX');
        }

        $idpEntityId = $authnRequestState->getIdpEntityId();
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }

        /** @var array<string> */
        $authnContextClassRef = $authnRequestState->getAuthnContextClassRef();

        $response = new Response($this->dateTime);
        $samlAssertion = $response->verify(
            $this->spInfo,
            $idpInfo,
            Base64::decode($samlResponse),
            $authnRequestState->getRequestId(),
            $authnContextClassRef
        );

        $this->session->set('_fkooman_saml_sp_assertion', \serialize($samlAssertion));

        return $authnRequestState->getReturnTo();
    }

    /**
     * Prepare and retrieve the logout URL.
     *
     * NOTE: the IdP may not support "SLO", in that case the provided
     * "returnTo" is returned directly (after local logout).
     *
     * @param string $returnTo
     *
     * @throws \fkooman\SAML\SP\Exception\SpException
     *
     * @return string
     */
    public function logout($returnTo)
    {
        if (!$this->hasAssertion()) {
            return $returnTo;
        }
        $samlAssertion = $this->getAssertion();
        $idpEntityId = $samlAssertion->getIssuer();
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }
        // delete the assertion, so we are no longer authenticated
        $this->session->delete('_fkooman_saml_sp_assertion');

        if (null === $samlAssertion->getNameId()) {
            // IdP's assertion does NOT have a NameID, so we cannot construct a
            // LogoutRequest
            return $returnTo;
        }
        $idpSloUrl = $idpInfo->getSloUrl();
        if (null === $idpSloUrl) {
            // IdP does not support logout, nothing we can do about it
            return $returnTo;
        }
        if (null === $this->spInfo->getSloUrl()) {
            // SP does not support logout, do not redirect to IdP
            return $returnTo;
        }

        $requestId = \sprintf('_%s', Hex::encode($this->random->requestId()));
        $logoutRequest = $this->tpl->render(
            'LogoutRequest',
            [
                'ID' => $requestId,
                'IssueInstant' => $this->dateTime->format('Y-m-d\TH:i:s\Z'),
                'Destination' => $idpSloUrl,
                'Issuer' => $this->spInfo->getEntityId(),
                'NameID' => $samlAssertion->getNameId(),
            ]
        );

        $relayState = Base64::encode($this->random->relayState());
        $logoutRequestState = new LogoutRequestState($requestId, $idpEntityId, $returnTo);
        $this->session->set($relayState, \serialize($logoutRequestState));

        return self::prepareRequestUrl($idpSloUrl, $logoutRequest, $relayState, $this->spInfo->getPrivateKey());
    }

    /**
     * @param string $queryString
     *
     * @throws \fkooman\SAML\SP\Exception\SpException
     *
     * @return string
     */
    public function handleLogoutResponse($queryString)
    {
        if (null === $spSloUrl = $this->spInfo->getSloUrl()) {
            throw new SpException('SP does not support SLO');
        }

        $queryParameters = new QueryParameters($queryString);
        $relayState = $queryParameters->requireQueryParameter('RelayState');

        $logoutRequestState = \unserialize($this->session->take($relayState));
        if (!($logoutRequestState instanceof LogoutRequestState)) {
            throw new \RuntimeException('Wat XXX');
        }

        $idpEntityId = $logoutRequestState->getIdpEntityId();
        if (false === $idpInfo = $this->idpInfoSource->get($idpEntityId)) {
            throw new SpException(\sprintf('IdP "%s" not registered', $idpEntityId));
        }

        $logoutResponse = new LogoutResponse();
        $logoutResponse->verify(
            $queryParameters,
            $logoutRequestState->getRequestId(),
            $spSloUrl,
            $idpInfo
        );

        return $logoutRequestState->getReturnTo();
    }

    /**
     * @return bool
     */
    public function hasAssertion()
    {
        return $this->session->has('_fkooman_saml_sp_assertion');
    }

    /**
     * @return Assertion
     */
    public function getAssertion()
    {
        if (!$this->hasAssertion()) {
            throw new SPException('no assertion available');
        }

        $samlAssertion = \unserialize($this->session->get('_fkooman_saml_sp_assertion'));
        if (!($samlAssertion instanceof Assertion)) {
            throw new \RuntimeException('Wat XXX');
        }

        return $samlAssertion;
    }

    /**
     * @return string
     */
    public function metadata()
    {
        return $this->tpl->render(
            'Metadata',
            [
                'spInfo' => $this->spInfo,
            ]
        );
    }

    /**
     * @param string     $requestUrl
     * @param string     $requestXml
     * @param string     $relayState
     * @param PrivateKey $privateKey
     *
     * @return string
     */
    private static function prepareRequestUrl($requestUrl, $requestXml, $relayState, PrivateKey $privateKey)
    {
        if (false === $deflatedXml = \gzdeflate($requestXml)) {
            throw new SPException('unable to "deflate" the XML');
        }

        $httpQueryParameters = [
            'SAMLRequest' => Base64::encode($deflatedXml),
            'RelayState' => $relayState,
            'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        ];

        // add the Signature key/value to the HTTP query
        $httpQueryParameters['Signature'] = Base64::encode(
            Crypto::sign(
                \http_build_query($httpQueryParameters),
                $privateKey
            )
        );

        return \sprintf(
            '%s%s%s',
            $requestUrl,
            false === \strpos($requestUrl, '?') ? '?' : '&',
            \http_build_query($httpQueryParameters)
        );
    }
}
