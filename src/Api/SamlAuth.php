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

namespace fkooman\SAML\SP\Api;

use DateTime;
use fkooman\SAML\SP\Api\Exception\AuthException;
use fkooman\SAML\SP\Assertion;
use fkooman\SAML\SP\SeSession;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\Web\Config;
use fkooman\SAML\SP\Web\Request;

class SamlAuth
{
    /** @var \fkooman\SAML\SP\Web\Config */
    private $config;

    /** @var \fkooman\SAML\SP\Web\Request */
    private $request;

    /** @var \fkooman\SAML\SP\SessionInterface */
    private $session;

    /** @var \DateTime */
    private $dateTime;

    public function __construct()
    {
        $this->config = Config::fromFile(\dirname(\dirname(__DIR__)).'/config/config.php');
        $this->request = new Request($_SERVER, $_GET, $_POST);
        $this->session = new SeSession($this->config->getSecureCookie());
        $this->dateTime = new DateTime();
    }

    /**
     * @return string
     */
    public function getLoginURL(AuthOptions $authOptions = null)
    {
        return $this->request->getOrigin().$this->config->getSpPath().'/login?'.$this->prepareQueryParameters($authOptions);
    }

    /**
     * @return \fkooman\SAML\SP\Assertion
     */
    public function getAssertion(AuthOptions $authOptions = null)
    {
        if (null === $samlAssertion = $this->getAndVerifyAssertion($authOptions)) {
            throw new AuthException('not authenticated');
        }

        return $samlAssertion;
    }

    /**
     * @return bool
     */
    public function isAuthenticated(AuthOptions $authOptions = null)
    {
        return null !== $this->getAndVerifyAssertion($authOptions);
    }

    /**
     * @return \fkooman\SAML\SP\Assertion|null
     */
    public function getAndVerifyAssertion(AuthOptions $authOptions = null)
    {
        if (null === $assertionStr = $this->session->get(SP::SESSION_KEY_PREFIX.'assertion')) {
            $this->terminateSession();

            return null;
        }
        $samlAssertion = \unserialize($assertionStr);
        if (!($samlAssertion instanceof Assertion)) {
            // we are unable to unserialize the Assertion
            $this->terminateSession();

            return null;
        }

        // make sure the SAML session is still valid
        $sessionNotOnOrAfter = $samlAssertion->getSessionNotOnOrAfter();
        if ($sessionNotOnOrAfter <= $this->dateTime) {
            $this->terminateSession();

            return null;
        }

        if (null !== $authOptions) {
            $this->verifyAuthOptions($samlAssertion, $authOptions);
        }

        return $samlAssertion;
    }

    /**
     * @return void
     */
    private function verifyAuthOptions(Assertion $samlAssertion, AuthOptions $authOptions)
    {
        // make sure we got the IdP we wanted
        if (null !== $idpEntityId = $authOptions->getIdp()) {
            if ($idpEntityId !== $samlAssertion->getIssuer()) {
                $this->terminateSession();

                throw new AuthException(\sprintf('IdP: expected "%s", got "%s"', $idpEntityId, $samlAssertion->getIssuer()));
            }
        }

        // make sure we got (any of) the AuthnContextClassRef we wanted
        if (0 !== \count($authOptions->getAuthnContextClassRef())) {
            if (!\in_array($samlAssertion->getAuthnContext(), $authOptions->getAuthnContextClassRef(), true)) {
                $this->terminateSession();

                throw new AuthException(\sprintf('AuthnContextClassRef: expected any of [%s], got "%s"', \implode(' ', $authOptions->getAuthnContextClassRef()), $samlAssertion->getAuthnContext()));
            }
        }
    }

    /**
     * @return string
     */
    private function prepareQueryParameters(AuthOptions $authOptions = null)
    {
        if (null === $authOptions) {
            $authOptions = AuthOptions::init()->withReturnTo($this->request->getUri());
        }
        $queryParameters = [
            'ReturnTo' => $authOptions->getReturnTo(),
        ];
        $authnContextClassRef = $authOptions->getAuthnContextClassRef();
        if (0 !== \count($authnContextClassRef)) {
            $queryParameters['AuthnContextClassRef'] = \implode(' ', $authnContextClassRef);
        }
        if (null !== $idpEntityId = $authOptions->getIdp()) {
            $queryParameters['IdP'] = $idpEntityId;
        }

        return \http_build_query($queryParameters);
    }

    /**
     * @return void
     */
    private function terminateSession()
    {
        $this->session->remove(SP::SESSION_KEY_PREFIX.'assertion');
    }
}
