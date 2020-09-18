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

/**
 * Configure the SAML authentication.
 */
class AuthOptions
{
    /** @var string|null */
    private $returnTo = null;

    /** @var array<string> */
    private $authnContextClassRef = [];

    /** @var string|null */
    private $idpEntityId = null;

    /** @var array<string> */
    private $scopingIdpList = [];

    /**
     * @return self
     */
    public static function init()
    {
        return new self();
    }

    /**
     * Specify the URL the browser will return to after authentication is
     * complete. By default the browser will return to the URL the
     * authentication was started from.
     *
     * @param string $returnTo
     *
     * @return self
     */
    public function withReturnTo($returnTo)
    {
        $this->returnTo = $returnTo;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getReturnTo()
    {
        return $this->returnTo;
    }

    /**
     * Specify the "AuthnContext" for the authentication request. This can for
     * example be used to request two factor authentication.
     *
     * @see https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
     *
     * @param array<string> $authnContextClassRef
     *
     * @return self
     */
    public function withAuthnContextClassRef(array $authnContextClassRef)
    {
        $this->authnContextClassRef = $authnContextClassRef;

        return $this;
    }

    /**
     * @return array<string>
     */
    public function getAuthnContextClassRef()
    {
        return $this->authnContextClassRef;
    }

    /**
     * Specify the entityID of the IdP you want to use for authentication when
     * >= 1 IdP is configured in the metadata. This effectively skips the
     * IdP selector dialog, also know as "WAYF".
     *
     * @param string $idpEntityId
     *
     * @return self
     */
    public function withIdp($idpEntityId)
    {
        $this->idpEntityId = $idpEntityId;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getIdp()
    {
        return $this->idpEntityId;
    }

    /**
     * Restrict the list of IdP(s), by entityID, the user is allowed to choose
     * from when your IdP(s) are behind a proxy.
     *
     * @param array<string> $scopingIdpList
     *
     * @return self
     */
    public function withScopingIdpList(array $scopingIdpList)
    {
        $this->scopingIdpList = $scopingIdpList;

        return $this;
    }

    /**
     * @return array<string>
     */
    public function getScopingIdpList()
    {
        return $this->scopingIdpList;
    }
}
