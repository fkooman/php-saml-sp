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

use fkooman\SAML\SP\Exception\IdpInfoException;
use fkooman\SAML\SP\Exception\KeyException;

/**
 * Holds the configuration information of an IdP.
 */
class IdpInfo
{
    /** @var string */
    private $entityId;

    /** @var string|null */
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
        $this->displayName = $displayName;
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
        if (null === $this->displayName) {
            return $this->entityId;
        }

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

    /**
     * @param string $xmlString
     *
     * @return self
     */
    public static function fromXml($xmlString)
    {
        // we do NOT (again) perform XML schema validation. Entities coming
        // coming from MetadataSource are verified there...
        $xmlDocument = XmlDocument::fromMetadata($xmlString, false);

        return new self(
            self::extractEntityId($xmlDocument),
            self::extractDisplayName($xmlDocument),
            self::extractSingleSignOnService($xmlDocument),
            self::extractSingleLogoutService($xmlDocument),
            self::extractPublicKeys($xmlDocument),
            self::extractScope($xmlDocument)
        );
    }

    /**
     * @return string
     */
    private static function extractEntityId(XmlDocument $xmlDocument)
    {
        return $xmlDocument->requireOneDomAttrValue('/md:EntityDescriptor/@entityID');
    }

    /**
     * @return string
     */
    private static function extractSingleSignOnService(XmlDocument $xmlDocument)
    {
        $ssoLocationList = $xmlDocument->allDomAttrValue('/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location');
        if (0 === \count($ssoLocationList)) {
            throw new IdpInfoException('unable to find SingleSignOnService with HTTP-Redirect binding');
        }

        // for now we only care about the first one...
        return $ssoLocationList[0];
    }

    /**
     * @return string|null
     */
    private static function extractSingleLogoutService(XmlDocument $xmlDocument)
    {
        $sloLocationList = $xmlDocument->allDomAttrValue('/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location');
        if (0 === \count($sloLocationList)) {
            // it is okay if SLO is not supported...
            return null;
        }

        // for now we only care about the first one...
        return $sloLocationList[0];
    }

    /**
     * @suppress PhanUnusedVariableCaughtException
     *
     * @return array<PublicKey>
     */
    private static function extractPublicKeys(XmlDocument $xmlDocument)
    {
        $publicKeyStringList = $xmlDocument->allDomElementTextContent(
            '/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'
        );

        $publicKeyList = [];
        foreach ($publicKeyStringList as $publicKeyString) {
            try {
                $publicKeyList[] = PublicKey::fromEncodedString($publicKeyString);
            } catch (KeyException $e) {
                // we do not (yet) support other keys than RSA at the moment,
                // trying to parse e.g. an EC cert will fail. We ignore those
                // entries..
            }
        }

        return $publicKeyList;
    }

    /**
     * @return array<string>
     */
    private static function extractScope(XmlDocument $xmlDocument)
    {
        return $xmlDocument->allDomElementTextContent(
            '/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/shibmd:Scope[not(@regexp) or @regexp="false" or @regexp="0"]'
        );
    }

    /**
     * @return string|null
     */
    private static function extractDisplayName(XmlDocument $xmlDocument)
    {
        $xPathQueryList = [
            '/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]',
            '/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName[@xml:lang="en"]',
            '/md:EntityDescriptor/md:Organization/md:OrganizationName[@xml:lang="en"]',
        ];

        foreach ($xPathQueryList as $xPathQuery) {
            if (null !== $textContent = $xmlDocument->optionalOneDomElementTextContent($xPathQuery)) {
                return $textContent;
            }
        }

        return null;
    }
}
