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

/**
 * Holds the configuration information of an IdP.
 */
class IdpInfo
{
    /** @var string */
    private $entityId;

    /** @var string */
    private $displayName;

    /** @var string */
    private $ssoUrl;

    /** @var string|null */
    private $sloUrl;

    /** @var array<PublicKey> */
    private $publicKeys = [];

    /** @var array<string> */
    private $scopeList = [];

    /**
     * @param string           $entityId
     * @param string|null      $displayName
     * @param string           $ssoUrl
     * @param string|null      $sloUrl
     * @param array<PublicKey> $publicKeys
     * @param array<string>    $scopeList
     */
    public function __construct($entityId, $displayName, $ssoUrl, $sloUrl, array $publicKeys, array $scopeList)
    {
        $this->entityId = $entityId;
        $this->displayName = null !== $displayName ? $displayName : $entityId;
        $this->ssoUrl = $ssoUrl;
        $this->sloUrl = $sloUrl;
        $this->publicKeys = $publicKeys;
        $this->scopeList = $scopeList;
    }

    /**
     * @return string
     */
    public function getEntityId()
    {
        return $this->entityId;
    }

    /**
     * @return string
     */
    public function getDisplayName()
    {
        return $this->displayName;
    }

    /**
     * Get SingleSignOn URL.
     *
     * @return string
     */
    public function getSsoUrl()
    {
        return $this->ssoUrl;
    }

    /**
     * Get SingleLogout URL.
     *
     * @return string|null
     */
    public function getSloUrl()
    {
        return $this->sloUrl;
    }

    /**
     * @return array<PublicKey>
     */
    public function getPublicKeys()
    {
        return $this->publicKeys;
    }

    /**
     * @return array<string>
     */
    public function getScopeList()
    {
        return $this->scopeList;
    }
}
