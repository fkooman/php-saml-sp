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

namespace fkooman\SAML\SP\Api;

use fkooman\SAML\SP\Assertion;
use fkooman\SAML\SP\PhpSession;
use fkooman\SAML\SP\SessionInterface;
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

    public function __construct(SessionInterface $session = null)
    {
        $this->config = Config::fromFile(\dirname(\dirname(__DIR__)).'/config/config.php');
        $this->request = new Request($_SERVER, $_GET, $_POST);
        if (null === $session) {
            $session = new PhpSession();
            if (null === $secureCookie = $this->config->requireKey('secureCookie')) {
                $secureCookie = true;
            }
            $session->start($secureCookie);
        }
        $this->session = $session;
    }

    /**
     * @return \fkooman\SAML\SP\Assertion|string
     */
    public function requireAuth()
    {
        // do we have an active session?
        if (null !== $samlAssertion = $this->getAndVerifyAssertion()) {
            return $samlAssertion;
        }

        // return a redirect URI
        if (null === $spPath = $this->config->requireKey('spPath')) {
            $spPath = '/php-saml-sp';
        }

        $queryParameters = [
            'ReturnTo' => $this->request->getUri(),
        ];

        return $this->request->getOrigin().$spPath.'/login'.'?'.\http_build_query($queryParameters);
    }

    /**
     * @return \fkooman\SAML\SP\Assertion|null
     */
    private function getAndVerifyAssertion()
    {
        if (null === $assertionData = $this->session->get(SP::SESSION_KEY_PREFIX.'assertion')) {
            return null;
        }

        // XXX where do we check whether or not it expired?!
        $samlAssertion = \unserialize($assertionData);
        if (!($samlAssertion instanceof Assertion)) {
            // we are unable to unserialize the Assertion
            $this->session->delete(SP::SESSION_KEY_PREFIX.'assertion');

            return null;
        }

        return $samlAssertion;
    }
}
