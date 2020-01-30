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
        if (null === $secureCookie = $this->config->get('secureCookie')) {
            $secureCookie = true;
        }
        $this->session = new SeSession($secureCookie);
        $this->dateTime = new DateTime();
    }

    /**
     * @return string
     */
    public function getLoginURL(AuthOptions $authOptions = null)
    {
        if (null === $authOptions) {
            $authOptions = new AuthOptions($this->request->getUri());
        }

        if (null === $spPath = $this->config->get('spPath')) {
            $spPath = '/php-saml-sp';
        }

        $this->session->set(SP::SESSION_KEY_PREFIX.'auth_options', \serialize($authOptions));

        return $this->request->getOrigin().$spPath.'wayf';
    }

    /**
     * @return \fkooman\SAML\SP\Assertion
     */
    public function getAssertion()
    {
        if (null === $samlAssertion = $this->getAndVerifyAssertion()) {
            throw new AuthException('not authenticated');
        }

        return $samlAssertion;
    }

    /**
     * @return bool
     */
    public function isAuthenticated()
    {
        return null !== $this->getAndVerifyAssertion();
    }

    /**
     * @return \fkooman\SAML\SP\Assertion|null
     */
    public function getAndVerifyAssertion()
    {
        if (null === $sessionValue = $this->session->get(SP::SESSION_KEY_PREFIX.'assertion')) {
            return null;
        }
        $samlAssertion = \unserialize($sessionValue);
        if (!($samlAssertion instanceof Assertion)) {
            // we are unable to unserialize the Assertion
            $this->session->remove(SP::SESSION_KEY_PREFIX.'assertion');

            return null;
        }

        // make sure the SAML session is still valid
        $sessionNotOnOrAfter = $samlAssertion->getSessionNotOnOrAfter();
        if ($sessionNotOnOrAfter <= $this->dateTime) {
            $this->session->remove(SP::SESSION_KEY_PREFIX.'assertion');

            return null;
        }

        return $samlAssertion;
    }
}
