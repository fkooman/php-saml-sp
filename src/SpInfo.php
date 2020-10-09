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
 * Holds the configuration information of this SP.
 */
class SpInfo
{
    /** @var string */
    private $entityId;

    /** @var CryptoKeys */
    private $cryptoKeys;

    /** @var string */
    private $acsUrl;

    /** @var string */
    private $sloUrl;

    /** @var bool */
    private $requireEncryption;

    /** @var array<string,string> */
    private $displayNameList;

    /**
     * @param string               $entityId          SP entityID
     * @param string               $acsUrl            AssertionConsumerService URL
     * @param string               $sloUrl            SingleLogoutService URL
     * @param bool                 $requireEncryption
     * @param array<string,string> $displayNameList
     */
    public function __construct($entityId, CryptoKeys $cryptoKeys, $acsUrl, $sloUrl, $requireEncryption, array $displayNameList)
    {
        $this->entityId = $entityId;
        $this->cryptoKeys = $cryptoKeys;
        $this->acsUrl = $acsUrl;
        $this->sloUrl = $sloUrl;
        $this->requireEncryption = $requireEncryption;
        $this->displayNameList = $displayNameList;
    }

    /**
     * @return string
     */
    public function getEntityId()
    {
        return $this->entityId;
    }

    /**
     * @return CryptoKeys
     */
    public function getCryptoKeys()
    {
        return $this->cryptoKeys;
    }

    /**
     * Get AssertionConsumerService URL.
     *
     * @return string
     */
    public function getAcsUrl()
    {
        return $this->acsUrl;
    }

    /**
     * Get SingleLogout URL.
     *
     * @return string
     */
    public function getSloUrl()
    {
        return $this->sloUrl;
    }

    /**
     * @return bool
     */
    public function getRequireEncryption()
    {
        return $this->requireEncryption;
    }

    /**
     * @return array<string,string>
     */
    public function getDisplayNameList()
    {
        return $this->displayNameList;
    }
}
