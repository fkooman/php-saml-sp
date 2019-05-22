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

use DOMElement;
use fkooman\SAML\SP\Exception\XmlIdpInfoSourceException;
use RuntimeException;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var XmlDocument */
    private $xmlDocument;

    /**
     * @param string $metadataFile
     * @param bool   $validateSchema
     *
     * @throws \RuntimeException
     */
    public function __construct($metadataFile, $validateSchema = true)
    {
        if (false === $xmlData = \file_get_contents($metadataFile)) {
            throw new RuntimeException(\sprintf('unable to read file "%s"', $metadataFile));
        }

        $this->xmlDocument = XmlDocument::fromMetadata($xmlData, $validateSchema);
    }

    /**
     * @param string $entityId
     *
     * @return false|IdpInfo
     */
    public function get($entityId)
    {
        // find the IdP with specified entityId, if there is more than one
        // we pick the first... Just don't have multiple entries for the same
        // entityId...
        // XXX if the IdP entityID does not exists, we have to give a better error!
        // "expected "DOMElement"" is not helpful!
        $xPathQuery = \sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId);
        $domElement = XmlDocument::requireDomElement($this->xmlDocument->domXPath->query($xPathQuery)->item(0));

        return new IdpInfo(
            $entityId,
            $this->getSingleSignOnService($domElement),
            $this->getSingleLogoutService($domElement),
            $this->getPublicKeys($domElement),
            $this->getScope($domElement)
        );
    }

    /**
     * @param \DOMElement $domElement
     *
     * @throws \fkooman\SAML\SP\Exception\XmlIdpInfoSourceException
     *
     * @return string
     */
    private function getSingleSignOnService(DOMElement $domElement)
    {
        $domNodeList = $this->xmlDocument->domXPath->query('md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location', $domElement);
        // return the first one, also if multiple are available
        if (null === $firstNode = $domNodeList->item(0)) {
            throw new XmlIdpInfoSourceException('no "md:SingleSignOnService" available');
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return string|null
     */
    private function getSingleLogoutService(DOMElement $domElement)
    {
        $domNodeList = $this->xmlDocument->domXPath->query('md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location', $domElement);
        // return the first one, also if multiple are available
        if (null === $firstNode = $domNodeList->item(0)) {
            return null;
        }

        return \trim($firstNode->textContent);
    }

    /**
     * @param \DOMElement $domElement
     *
     * @throws \fkooman\SAML\SP\Exception\XmlIdpInfoSourceException
     *
     * @return array<PublicKey>
     */
    private function getPublicKeys(DOMElement $domElement)
    {
        $publicKeys = [];
        $domNodeList = $this->xmlDocument->domXPath->query('md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $domElement);
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
     * @param \DOMElement $domElement
     *
     * @return array<string>
     */
    private function getScope(DOMElement $domElement)
    {
        $scopeList = [];
        $domNodeList = $this->xmlDocument->domXPath->query('md:Extensions/shibmd:Scope[not(@regexp) or @regexp="false" or @regexp="0"]', $domElement);
        foreach ($domNodeList as $domNode) {
            $scopeElement = XmlDocument::requireDomElement($domNode);
            $scopeList[] = $scopeElement->textContent;
        }

        return $scopeList;
    }
}
