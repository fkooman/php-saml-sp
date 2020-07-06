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

use DOMElement;
use fkooman\SAML\SP\Exception\XmlIdpInfoSourceException;
use RuntimeException;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var array<XmlDocument> */
    private $xmlDocumentList = [];

    /**
     * @param array<string> $metadataFileList
     * @param bool          $validateSchema
     *
     * @throws \RuntimeException
     */
    public function __construct(array $metadataFileList, $validateSchema = true)
    {
        foreach ($metadataFileList as $metadataFile) {
            if (false === $xmlData = \file_get_contents($metadataFile)) {
                throw new RuntimeException(\sprintf('unable to read file "%s"', $metadataFile));
            }

            $this->xmlDocumentList[] = XmlDocument::fromMetadata($xmlData, $validateSchema);
        }
    }

    /**
     * Make sure there is exactly 1 IdP with this entityID.
     *
     * @param string $entityId
     *
     * @return bool
     */
    public function has($entityId)
    {
        self::validateEntityId($entityId);
        $xPathQuery = \sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId);

        foreach ($this->xmlDocumentList as $xmlDocument) {
            if (1 === $xmlDocument->domXPath->query($xPathQuery)->length) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<IdpInfo>
     */
    public function getAll()
    {
        $xPathQuery = '//md:EntityDescriptor/md:IDPSSODescriptor';
        $idpList = [];
        foreach ($this->xmlDocumentList as $xmlDocument) {
            if (false === $domNodeList = $xmlDocument->domXPath->query($xPathQuery)) {
                continue;
            }
            if (1 !== $domNodeList->length) {
                continue;
            }
            $domElement = XmlDocument::requireDomElement($domNodeList->item(0));

            // determine entityID
            $entityId = $xmlDocument->domXPath->evaluate('string(parent::node()/@entityID)', $domElement);

            $idpList[] = new IdpInfo(
                $entityId,
                $this->getDisplayName($xmlDocument, $domElement),
                $this->getSingleSignOnService($xmlDocument, $domElement),
                $this->getSingleLogoutService($xmlDocument, $domElement),
                $this->getPublicKeys($xmlDocument, $domElement),
                $this->getScope($xmlDocument, $domElement)
            );
        }

        return $idpList;
    }

    /**
     * Get IdP information for an IdP.
     *
     * @param string $entityId
     *
     * @return IdpInfo
     */
    public function get($entityId)
    {
        self::validateEntityId($entityId);
        $xPathQuery = \sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId);

        foreach ($this->xmlDocumentList as $xmlDocument) {
            if (false === $domNodeList = $xmlDocument->domXPath->query($xPathQuery)) {
                continue;
            }
            if (1 !== $domNodeList->length) {
                continue;
            }

            $domElement = XmlDocument::requireDomElement($domNodeList->item(0));

            return new IdpInfo(
                $entityId,
                $this->getDisplayName($xmlDocument, $domElement),
                $this->getSingleSignOnService($xmlDocument, $domElement),
                $this->getSingleLogoutService($xmlDocument, $domElement),
                $this->getPublicKeys($xmlDocument, $domElement),
                $this->getScope($xmlDocument, $domElement)
            );
        }

        throw new XmlIdpInfoSourceException(\sprintf('IdP "%s" not available', $entityId));
    }

    /**
     * @throws \fkooman\SAML\SP\Exception\XmlIdpInfoSourceException
     *
     * @return string
     */
    private function getSingleSignOnService(XmlDocument $xmlDocument, DOMElement $domElement)
    {
        $domNodeList = $xmlDocument->domXPath->query('md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location', $domElement);
        // return the first one, also if multiple are available
        if (null === $firstNode = $domNodeList->item(0)) {
            throw new XmlIdpInfoSourceException('no "md:SingleSignOnService" available');
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @return string|null
     */
    private function getSingleLogoutService(XmlDocument $xmlDocument, DOMElement $domElement)
    {
        $domNodeList = $xmlDocument->domXPath->query('md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location', $domElement);
        // return the first one, also if multiple are available
        if (null === $firstNode = $domNodeList->item(0)) {
            return null;
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @throws \fkooman\SAML\SP\Exception\XmlIdpInfoSourceException
     *
     * @return array<PublicKey>
     */
    private function getPublicKeys(XmlDocument $xmlDocument, DOMElement $domElement)
    {
        $publicKeys = [];
        $domNodeList = $xmlDocument->domXPath->query('md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $domElement);
        if (0 === $domNodeList->length) {
            throw new XmlIdpInfoSourceException('entry MUST have at least one X509Certificate');
        }
        for ($i = 0; $i < $domNodeList->length; ++$i) {
            $certificateNode = $domNodeList->item($i);
            if (null !== $certificateNode) {
                $publicKeys[] = PublicKey::fromEncodedString($certificateNode->textContent);
            }
        }

        return $publicKeys;
    }

    /**
     * @return array<string>
     */
    private function getScope(XmlDocument $xmlDocument, DOMElement $domElement)
    {
        $scopeList = [];
        $domNodeList = $xmlDocument->domXPath->query('md:Extensions/shibmd:Scope[not(@regexp) or @regexp="false" or @regexp="0"]', $domElement);
        foreach ($domNodeList as $domNode) {
            $scopeElement = XmlDocument::requireDomElement($domNode);
            $scopeList[] = $scopeElement->textContent;
        }

        return $scopeList;
    }

    /**
     * @return string|null
     */
    private function getDisplayName(XmlDocument $xmlDocument, DOMElement $domElement)
    {
        $domNodeList = $xmlDocument->domXPath->query('md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]', $domElement);
        if (0 === $domNodeList->length) {
            return null;
        }
        if (null === $displayNameNode = $domNodeList->item(0)) {
            return null;
        }

        return \trim($displayNameNode->textContent);
    }

    /**
     * @param string $entityId
     *
     * @return void
     */
    private static function validateEntityId($entityId)
    {
        // we took all IdP entityID entries from eduGAIN metadata and made sure
        // the filter accepts all of those... anything outside this range is
        // probably not a valid xsd:anyURI anyway... this may need tweaking in
        // the future...
        //
        // Maybe it is enough to allow everything, except DQUOTE (")?
        if (1 !== \preg_match('|^[0-9a-zA-Z-./:=_?]+$|', $entityId)) {
            throw new XmlIdpInfoSourceException('invalid entityID');
        }
    }
}
