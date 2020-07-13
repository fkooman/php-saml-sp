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
        // from DbSource are considered "valid". Entities coming from
        // MetadataSource are verified there...
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
        $entityDescriptorDomNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('/md:EntityDescriptor'));
        $entityDescriptorDomElement = XmlDocument::requireDomElement($entityDescriptorDomNodeList->item(0));

        return $entityDescriptorDomElement->getAttribute('entityID');
    }

    /**
     * @return string
     */
    private static function extractSingleSignOnService(XmlDocument $xmlDocument)
    {
        $pathQuery = '/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location';
        $domNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query($pathQuery));
        if (null === $firstNode = $domNodeList->item(0)) {
            throw new IdpInfoException(\sprintf('path not found: "%s"', $pathQuery));
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @return string|null
     */
    private static function extractSingleLogoutService(XmlDocument $xmlDocument)
    {
        $pathQuery = '/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location';
        $domNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query($pathQuery));
        if (null === $firstNode = $domNodeList->item(0)) {
            return null;
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @throws Exception\IdpInfoException
     *
     * @return array<PublicKey>
     */
    private static function extractPublicKeys(XmlDocument $xmlDocument)
    {
        $pathQuery = '/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate';
        $domNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query($pathQuery));
        if (0 === $domNodeList->length) {
            throw new IdpInfoException(\sprintf('path not found: "%s"', $pathQuery));
        }
        $publicKeys = [];
        foreach ($domNodeList as $domNode) {
            $certificateElement = XmlDocument::requireDomElement($domNode);
            try {
                $publicKeys[] = PublicKey::fromEncodedString(\trim($certificateElement->textContent));
            } catch (KeyException $e) {
                // we do not (yet) support other keys than RSA at the moment,
                // trying to parse e.g. an EC cert will fail. We ignore those
                // entries..
            }
        }

        return $publicKeys;
    }

    /**
     * @return array<string>
     */
    private static function extractScope(XmlDocument $xmlDocument)
    {
        $pathQuery = '/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/shibmd:Scope[not(@regexp) or @regexp="false" or @regexp="0"]';
        $domNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query($pathQuery));
        $scopeList = [];
        foreach ($domNodeList as $domNode) {
            $scopeElement = XmlDocument::requireDomElement($domNode);
            $scopeList[] = \trim($scopeElement->textContent);
        }

        return $scopeList;
    }

    /**
     * @return string|null
     */
    private static function extractDisplayName(XmlDocument $xmlDocument)
    {
        $pathQueryList = [
            '/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]',
            '/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName[@xml:lang="en"]',
            '/md:EntityDescriptor/md:Organization/md:OrganizationName[@xml:lang="en"]',
        ];

        foreach ($pathQueryList as $pathQuery) {
            $domNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query($pathQuery));
            if (0 === $domNodeList->length) {
                continue;
            }
            $nameNode = XmlDocument::requireDomElement($domNodeList->item(0));

            return \trim($nameNode->textContent);
        }
    }
}
